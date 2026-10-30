"""The tick: route repositories whose inputs changed, then plan every asset that is due."""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Callable, Collection
from datetime import datetime
from typing import Generic, Protocol, TypeVar
from uuid import UUID

import pydantic
from traust_core.v1.context import Clock, FeedQuery, OpsService, Router
from traust_core.v1.errors import ConfigError, NotFoundError
from traust_core.v1.models.base import Model
from traust_core.v1.models.common import Cursor, PageRequest, encode_cursor
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.inventory import RecordedRelease
from traust_core.v1.models.operations import (
    OPEN_ORDER_STATES,
    AssetName,
    LaneName,
    OrderReason,
    OrderRequest,
    OrderState,
    Refusal,
)
from traust_core.v1.models.vocabulary import ActorKind

from traust_engine.ops.pack import Pack

log = logging.getLogger(__name__)

S = TypeVar("S")

ENGINE = Principal(identity="traust-engine", kind=ActorKind.MACHINE, display="traust-engine")
MATERIALIZED = (OrderState.SUCCEEDED, OrderState.DEGRADED)
# A refused or failed run waits out the cadence too, so a broken asset can't spin every tick.
ATTEMPTED = (*MATERIALIZED, OrderState.REFUSED, OrderState.FAILED)
FEED_PAGE = 1000


class TickReport(Model):
    planned: int = 0
    routed: int = 0
    unrouted: int = 0
    refused_again: int = 0
    stale: dict[AssetName, int] = pydantic.Field(default_factory=dict)
    overdue: dict[AssetName, int] = pydantic.Field(default_factory=dict)
    unrunnable: tuple[AssetName, ...] = ()


class Releases(Protocol):
    """The one portfolio read the router needs; `Context.services().portfolio` satisfies it."""

    def recorded_release(self, release_id: UUID) -> RecordedRelease: ...


class Controller(Generic[S]):
    def __init__(
        self,
        pack: Pack,
        ops: OpsService,
        clock: Clock,
        router: Router[S, RecordedRelease] | None = None,
        state_of: Callable[[UUID], S] | None = None,
        feed: FeedQuery | None = None,
        portfolio: Releases | None = None,
    ) -> None:
        if (router is None) != (state_of is None) or (
            router is not None and (feed is None or portfolio is None)
        ):
            raise ValueError(
                "a router needs state_of, the feed and the portfolio, and state_of needs a router"
            )
        self._pack = pack
        self._ops = ops
        self._clock = clock
        self._router = router
        self._state_of = state_of
        self._feed = feed
        self._portfolio = portfolio
        self._cursor: Cursor | None = None

    def tick(self, repositories: Collection[UUID]) -> TickReport:
        report, requests, stops = self.due(repositories)
        for request in requests:
            self._ops.plan(request, ENGINE, self._pack.config())
        for request in stops:
            order = self._ops.plan(request, ENGINE, self._pack.config())
            assert order.id is not None
            self._ops.withhold(order.id, OrderReason.UPSTREAM_STALE)
        return report

    def due(
        self, repositories: Collection[UUID]
    ) -> tuple[TickReport, list[OrderRequest], list[OrderRequest]]:
        """What a tick would plan (routed orders, then every due asset), and the stale-upstream
        stops it would record on the feed, writing nothing: the shadow run's view of the loop."""
        now = self._clock.now()
        unrunnable = self._pack.unrunnable()
        requests, routed, unrouted, refused_again = self._route(now, unrunnable)
        planned, stale, stops = 0, {}, []
        for name in self._pack.topo_order():
            spec = self._pack.assets[name]
            since = spec.trigger.since(now)
            if since is None or name in unrunnable:
                continue
            subjects: Collection[UUID | None] = repositories if spec.partitions else (None,)
            busy = self._ops.subjects(name, OPEN_ORDER_STATES) | self._ops.subjects(
                name, ATTEMPTED, since
            )
            fresh = {dep: self._fresh(dep, now) for dep in spec.deps}
            stopped: dict[AssetName, set[UUID | None]] = {}
            for subject in subjects:
                if subject in busy:
                    continue
                request = OrderRequest(asset=name, priority=spec.priority, repository_id=subject)
                behind = [d for d, ok in fresh.items() if self._dep_subject(d, subject) not in ok]
                if behind:
                    stale[name] = stale.get(name, 0) + 1
                    if not any(subject in self._stopped(name, d, now, stopped) for d in behind):
                        stops.append(request)
                    continue
                requests.append(request)
                planned += 1
        overdue = self._overdue(repositories, now, unrunnable)
        report = TickReport(
            planned=planned,
            routed=routed,
            unrouted=unrouted,
            refused_again=refused_again,
            stale=stale,
            overdue=overdue,
            unrunnable=unrunnable,
        )
        return report, requests, stops

    def _stopped(
        self,
        name: AssetName,
        dep: AssetName,
        now: datetime,
        cache: dict[AssetName, set[UUID | None]],
    ) -> set[UUID | None]:
        """Subjects of `name` already stopped on stale `dep` within `dep`'s cadence, so a stale
        upstream leaves one stop per window, not one per tick."""
        if dep not in cache:
            since = self._pack.assets[dep].trigger.since(now)
            cache[dep] = self._ops.subjects(
                name, (OrderState.WITHHELD,), since, OrderReason.UPSTREAM_STALE
            )
        return cache[dep]

    def _overdue(
        self, repositories: Collection[UUID], now: datetime, unrunnable: Collection[AssetName]
    ) -> dict[AssetName, int]:
        """Subjects past `freshness.fail` since their last materialization (or never made);
        unrunnable assets are reported as such instead."""
        overdue = {}
        for name, spec in self._pack.assets.items():
            if spec.freshness.fail is None or name in unrunnable:
                continue
            subjects = set(repositories) if spec.partitions else {None}
            fresh = self._ops.subjects(name, MATERIALIZED, now - spec.freshness.fail)
            if count := len(subjects - fresh):
                overdue[name] = count
        return overdue

    def _route(
        self, now: datetime, unrunnable: Collection[AssetName]
    ) -> tuple[list[OrderRequest], int, int, int]:
        """Re-route repositories whose `route_on` asset materialized, whose routed order was
        refused, or that a recorded release ships, since the last tick; each route with a lane the
        pack runs becomes an order for that lane's asset, except a route back into a lane that
        refused it."""
        source = self._pack.route_on
        if self._router is None or self._state_of is None or source is None:
            return [], 0, 0, 0
        changed, refusals, releases = self._changes(source, now)
        requests: list[OrderRequest] = []
        unknown: set[LaneName] = set()
        routed = unrouted = refused_again = 0
        for repository_id in changed | refusals.keys() | releases.keys():
            try:
                state = self._state_of(repository_id)
            except NotFoundError:
                unrouted += 1
                continue
            refused = refusals.get(repository_id, [])
            for route in self._router.route(state, releases.get(repository_id, []), refused):
                if route.lane is None:
                    continue
                if route.lane in {r.lane for r in refused}:
                    refused_again += 1
                    continue
                try:
                    asset = self._pack.asset_for_lane(route.lane)
                except ConfigError:
                    unknown.add(route.lane)
                    continue
                if asset not in unrunnable:
                    requests.append(
                        OrderRequest(
                            asset=asset,
                            priority=route.priority,
                            repository_id=repository_id,
                            lane=route.lane,
                            rule=route.reason,
                        )
                    )
            routed += 1
        if unknown:
            log.warning("routed lanes no pack asset runs: %s", ", ".join(sorted(unknown)))
        return requests, routed, unrouted, refused_again

    def _changes(
        self, source: AssetName, now: datetime
    ) -> tuple[set[UUID], dict[UUID, list[Refusal]], dict[UUID, list[RecordedRelease]]]:
        """Repositories whose `source` materialized, refusals of routed orders, and recorded
        releases by the repositories they ship, on the feed since the routing cursor, which moves
        past them. After a restart the cursor starts at the last routed order, looking back at
        most one `source` cadence."""
        assert self._feed is not None and self._portfolio is not None
        if self._cursor is None:
            since = self._pack.assets[source].trigger.since(now) or now
            last = self._ops.last_routed()
            self._cursor = encode_cursor(since if last is None else max(last, since), UUID(int=0))
        changed: set[UUID] = set()
        refusals: defaultdict[UUID, list[Refusal]] = defaultdict(list)
        releases: defaultdict[UUID, list[RecordedRelease]] = defaultdict(list)
        while True:
            page = self._feed.list(PageRequest(limit=FEED_PAGE, cursor=self._cursor))
            for event in page.items:
                if event.release is not None and event.release.id is not None:
                    recorded = self._portfolio.recorded_release(event.release.id)
                    for repository_id in recorded.repository_ids:
                        releases[repository_id].append(recorded)
                order = event.order
                if order is None or order.repository_id is None:
                    continue
                if order.asset == source and order.state in MATERIALIZED:
                    changed.add(order.repository_id)
                elif order.state == OrderState.REFUSED and order.lane is not None:
                    refusals[order.repository_id].append(
                        Refusal(
                            subject=str(order.repository_id),
                            lane=LaneName(order.lane),
                            reason=order.reason,
                        )
                    )
            if page.items:
                self._cursor = page.items[-1].cursor
            if page.next is None:
                return changed, refusals, releases

    def _fresh(self, dep: AssetName, now: datetime) -> set[UUID | None]:
        return self._ops.subjects(dep, MATERIALIZED, self._pack.assets[dep].trigger.since(now))

    def _dep_subject(self, dep: AssetName, subject: UUID | None) -> UUID | None:
        return subject if self._pack.assets[dep].partitions else None
