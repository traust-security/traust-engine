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
from traust_core.v1.models.assessment import Assessment
from traust_core.v1.models.base import Model
from traust_core.v1.models.common import Cursor, PageRequest, encode_cursor, every_item
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.inventory import (
    RecordedRelease,
    Repository,
    RepositoryFilter,
    RepositoryRef,
)
from traust_core.v1.models.operations import (
    OPEN_ORDER_STATES,
    AssetName,
    LaneName,
    OrderFilter,
    OrderReason,
    OrderRequest,
    OrderState,
    Refusal,
)
from traust_core.v1.models.vocabulary import ActorKind, AssessmentKind, RemediationStatus

from traust_engine.ops.pack import Pack
from traust_engine.ops.remediation import (
    REATTEMPT_LIMIT,
    REMEDIATE_ASSET,
    RETRY_AFTER,
    VERIFY_ASSET,
    Remediations,
    RemediationState,
)

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


class Refs(Protocol):
    """The commit reads the remediation trigger needs; `PortfolioService.inventory`
    satisfies it."""

    def resolve(self, repository_ref_id: UUID) -> tuple[RepositoryRef, Repository]: ...


class Releases(Protocol):
    """The portfolio reads the engine needs — recorded releases for the router, commit
    resolution for the remediation trigger; `Context.services().portfolio` satisfies it."""

    def recorded_release(self, release_id: UUID) -> RecordedRelease: ...

    inventory: Refs


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
        remediations: Remediations | None = None,
    ) -> None:
        if (router is None) != (state_of is None) or (
            router is not None and (feed is None or portfolio is None)
        ):
            raise ValueError(
                "a router needs state_of, the feed and the portfolio, and state_of needs a router"
            )
        if remediations is not None and (feed is None or portfolio is None):
            raise ValueError("the remediation trigger needs the feed and the portfolio")
        self._pack = pack
        self._ops = ops
        self._clock = clock
        self._router = router
        self._state_of = state_of
        self._feed = feed
        self._portfolio = portfolio
        self._remediations = remediations
        self._cursor: Cursor | None = None
        # Repositories whose remediation demand an attempt within the retry window
        # holds, with the earliest pass that may wake them — a wake is a recheck of
        # the repository's current states, never a stored order, so demand that has
        # moved on dispatches nothing. In memory only: a restart's full feed replay
        # re-derives it from the attempted orders it sees.
        self._deferred: dict[UUID, datetime] = {}

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
        unrunnable = tuple(
            name for name, spec in self._pack.assets.items() if not spec.run and spec.model is None
        )
        requests, routed, unrouted, refused_again = self._route(now)
        planned, stale, stops = 0, {}, []
        for name in self._pack.topo_order():
            spec = self._pack.assets[name]
            since = spec.trigger.since(now)
            if since is None or not spec.enabled:
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
        overdue = self._overdue(repositories, now)
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

    def _overdue(self, repositories: Collection[UUID], now: datetime) -> dict[AssetName, int]:
        """Subjects past `freshness.fail` since their last materialization (or never made);
        a disabled asset is not one the deployment is failing to keep fresh."""
        overdue = {}
        for name, spec in self._pack.assets.items():
            if spec.freshness.fail is None or not spec.enabled:
                continue
            subjects = set(repositories) if spec.partitions else {None}
            fresh = self._ops.subjects(name, MATERIALIZED, now - spec.freshness.fail)
            if count := len(subjects - fresh):
                overdue[name] = count
        return overdue

    def _route(self, now: datetime) -> tuple[list[OrderRequest], int, int, int]:
        """Re-route repositories whose `route_on` asset materialized, whose routed order was
        refused, or that a recorded release ships, since the last tick; each route with a lane
        the pack runs becomes an order for that lane's asset, except a route back into a lane
        that refused it. A lane the pack runs no asset for is a pack error: the pass fails
        before it plans anything."""
        source = self._pack.route_on
        if self._router is None or self._state_of is None or source is None:
            return [], 0, 0, 0
        if self._cursor is None:
            since = self._pack.assets[source].trigger.since(now) or now
            last = self._ops.last_routed()
            self._cursor = encode_cursor(since if last is None else max(last, since), UUID(int=0))
        before = self._cursor
        try:
            changed, refusals, releases = self._changes(source)
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
                    if self._pack.assets[asset].enabled:
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
                raise ConfigError(
                    f"pack {self._pack.pack} runs no asset for lane(s) "
                    f"{', '.join(sorted(unknown))}: "
                    "give each lane an asset (trigger.lanes), or fix the router"
                )
            return requests, routed, unrouted, refused_again
        except Exception:
            self._cursor = before
            raise

    def _changes(
        self, source: AssetName
    ) -> tuple[set[UUID], dict[UUID, list[Refusal]], dict[UUID, list[RecordedRelease]]]:
        """Repositories whose `source` materialized, refusals of routed orders, and recorded
        releases by the repositories they ship, on the feed since the routing cursor, which moves
        past them. After a restart the cursor starts at the last routed order, looking back at
        most one `source` cadence."""
        assert self._feed is not None and self._portfolio is not None
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

    def remediation_due(
        self, cursor: Cursor | None, *, wake: bool = True
    ) -> tuple[list[OrderRequest], Cursor | None]:
        """Remediation-driven work: verification orders for implemented remediations,
        reattempts for failed ones. Reads the feed for remediation assessments and finished
        remediation runs, and returns the orders to submit with the cursor to resume from —
        the same admission gate admits them as the tick's. A None cursor (a first pass, or
        one after a restart) reads from the feed's beginning, so remediations that reached
        a trigger state while the engine was down are still dispatched; the pass is
        idempotent, since an open order for a subject suppresses re-planning it.

        Demand an attempt within the retry window holds is deferred and woken by the first
        pass after the window (a restart loses the memory, but its full replay re-derives
        it); rechecks run once per pass, over the repositories the pass's events named,
        so a replayed history costs one state read per repository, not one per event."""
        if self._remediations is None:
            return [], cursor
        assert self._feed is not None and self._portfolio is not None
        requests: list[OrderRequest] = []
        planned: set[tuple[AssetName, UUID | None]] = set()
        busy: dict[AssetName, tuple[set[UUID | None], dict[str, datetime]]] = {}
        demanded: set[UUID] = set()  # repositories this pass dispatched or deferred for
        now = self._clock.now()
        recheck: dict[UUID, None] = {}  # insertion-ordered set
        woken: dict[UUID, datetime] = {}
        if wake:
            # A matured deferral wakes as a recheck of its repository's current
            # states: demand that moved on while it waited dispatches nothing.
            # A preview (the shadow) wakes nothing — consuming a deferral there
            # would leave the live pass, whose cursor has passed the creating
            # event, nothing to rediscover.
            for repository_id, ready_at in list(self._deferred.items()):
                if ready_at <= now:
                    woken[repository_id] = self._deferred.pop(repository_id)
                    recheck[repository_id] = None
        fleet_wide = False
        while True:
            page = self._feed.list(PageRequest(limit=FEED_PAGE, cursor=cursor))
            for event in page.items:
                if (assessment := event.assessment) is not None:
                    if assessment.kind == AssessmentKind.REMEDIATION:
                        state = self._assessment_request(
                            assessment, requests, planned, busy, demanded
                        )
                        if state is not None:
                            self._dispatch(state, requests, planned, busy, demanded)
                    elif assessment.kind == AssessmentKind.VERIFICATION:
                        # A recorded verification moved its remediations to revalidated_*;
                        # the verdicts are what name the repository to re-check.
                        if (repository_id := self._repository_of(assessment)) is not None:
                            recheck[repository_id] = None
                elif (
                    (order := event.order) is not None
                    and order.asset in (REMEDIATE_ASSET, VERIFY_ASSET)
                    and order.state in ATTEMPTED
                ):
                    # A finished attempt — materialized, refused or failed — re-reads what
                    # its subject's remediations now call for: a run that landed without a
                    # verdict leaves the work due. A remediation run names its repository;
                    # a verification sweep may have been fleet-wide, and the remediations
                    # that arrived while it was open were suppressed with their events
                    # already consumed — so its closing re-reads every repository. The
                    # rechecks run once per pass, not once per event.
                    if order.repository_id is not None:
                        recheck[order.repository_id] = None
                    else:
                        fleet_wide = True
            if page.items:
                cursor = page.items[-1].cursor
            if page.next is None:
                break
        for repository_id in recheck:
            self._recheck(repository_id, requests, planned, busy, demanded)
        if fleet_wide:
            for repository_id in self._repositories():
                self._recheck(repository_id, requests, planned, busy, demanded)
        # A woken deferral survives its pass unless the pass proves the demand
        # satisfied: a repository the pass dispatched for keeps its wake (a
        # planning failure after this return then finds it intact next pass —
        # its ready_at has passed, so the retry is immediate), a repository
        # re-deferred already carries a fresh one, and a repository nothing
        # was due for drops it. A wake whose dispatch planned cleanly fires
        # once more, meets the open order, and drops.
        for repository_id, ready_at in woken.items():
            if repository_id in demanded and repository_id not in self._deferred:
                self._deferred[repository_id] = ready_at
        return requests, cursor

    def _assessment_request(
        self,
        assessment: Assessment,
        requests: list[OrderRequest],
        planned: set[tuple[AssetName, UUID | None]],
        busy: dict[AssetName, tuple[set[UUID | None], dict[str, datetime]]],
        demanded: set[UUID],
    ) -> RemediationState | None:
        """One remediation assessment on the feed: the remediation order for a request the
        scheduling door left without one, and the assessment's current state."""
        assert assessment.id is not None and self._remediations is not None
        state = self._remediations.state_of(assessment.id)
        if (
            assessment.status == RemediationStatus.CANDIDATE
            and assessment.run_order_id is None
            and (state is None or state.status == RemediationStatus.CANDIDATE)
        ):
            # The door creates the assessment and its order atomically; one without an
            # order was opened beside it, so the engine submits the order itself — unless
            # the remediation has already moved on (a replayed event) or one is open.
            repository_id = (
                state.repository_id if state is not None else self._repository_of(assessment)
            )
            named = state.remediation_id if state is not None else assessment.id
            self._request(
                REMEDIATE_ASSET,
                repository_id,
                f"remediation:{named}",
                requests,
                planned,
                busy,
                demanded,
            )
        return state

    def _recheck(
        self,
        repository_id: UUID | None,
        requests: list[OrderRequest],
        planned: set[tuple[AssetName, UUID | None]],
        busy: dict[AssetName, tuple[set[UUID | None], dict[str, datetime]]],
        demanded: set[UUID],
    ) -> None:
        """Re-read the repository's remediations and dispatch whatever their current
        status calls for."""
        if repository_id is None or self._remediations is None:
            return
        for state in self._remediations.states_of(repository_id):
            self._dispatch(state, requests, planned, busy, demanded)

    def _dispatch(
        self,
        state: RemediationState,
        requests: list[OrderRequest],
        planned: set[tuple[AssetName, UUID | None]],
        busy: dict[AssetName, tuple[set[UUID | None], dict[str, datetime]]],
        demanded: set[UUID],
    ) -> None:
        """The order a remediation's current status calls for: verification once it is
        implemented, another attempt while verification still finds it vulnerable and the
        limit has not been reached, and the remediation order a candidate still waits on
        (one the door left unpaired, or whose earlier attempt is past its retry window).
        `revalidated_fixed` waits for SCI's filing loop; every other status waits on its
        own actor."""
        if state.status == RemediationStatus.CANDIDATE:
            self._request(
                REMEDIATE_ASSET,
                state.repository_id,
                f"remediation:{state.remediation_id}",
                requests,
                planned,
                busy,
                demanded,
            )
        elif state.status in (RemediationStatus.PATCHED, RemediationStatus.CHECKS_PASSED):
            self._request(
                VERIFY_ASSET,
                state.repository_id,
                f"verify-remediation:{state.remediation_id}",
                requests,
                planned,
                busy,
                demanded,
            )
        elif (
            state.status == RemediationStatus.REVALIDATED_STILL_VULNERABLE
            and state.reattempts < REATTEMPT_LIMIT
        ):
            self._request(
                REMEDIATE_ASSET,
                state.repository_id,
                f"remediation:{state.remediation_id}",
                requests,
                planned,
                busy,
                demanded,
            )

    def _request(
        self,
        asset: AssetName,
        repository_id: UUID | None,
        rule: str,
        requests: list[OrderRequest],
        planned: set[tuple[AssetName, UUID | None]],
        busy: dict[AssetName, tuple[set[UUID | None], dict[str, datetime]]],
        demanded: set[UUID],
    ) -> bool:
        """Plan one order of `asset` for the repository, unless the pack runs no such
        asset, one is already open for the subject, an attempt of this very remediation
        the retry window has not outlived holds it, or this pass already planned it.
        Demand an attempt holds is deferred with a wake-up, not dropped: the first pass
        after the window dispatches it (a restart loses the memory, but its full replay
        re-derives it). Returns whether the repository's demand was served — dispatched
        or deferred — so a woken deferral knows its pass owed it something."""
        spec = self._pack.assets.get(asset)
        if spec is None or not spec.enabled:
            log.warning(
                "pack %s runs no asset %s: remediation dispatch skipped",
                self._pack.pack,
                asset,
            )
            return False
        subject = repository_id if spec.partitions else None
        if spec.partitions and subject is None:
            log.warning("remediation dispatch of %s has no repository to work on", asset)
            return False
        if asset not in busy:
            # Open orders suppress re-planning; an attempt of this remediation
            # within the retry window defers its demand instead: a sweep or run
            # that landed without a verdict is retried at most once per window,
            # and woken when the window passes — not by every restart or recheck,
            # and never lost behind the cursor. The window is keyed by the rule —
            # the remediation — not the subject: an unrelated remediation of the
            # same repository waits only for the open order, never the hour. The
            # wake honors the attempt's own age (its finished_at), so an attempt
            # seen near the end of its window wakes the demand shortly after it
            # becomes eligible, not a full window after the pass that noticed it.
            window_start = self._clock.now() - RETRY_AFTER
            attempted: dict[str, datetime] = {}
            # The remediation assets are event-driven and low-volume, so paging
            # their attempted orders and keeping those inside the window is exact
            # where subjects() would say only that one exists. Orders without a
            # trigger rule are not this remediation's to wait for.
            for order in every_item(
                lambda page: self._ops.list(OrderFilter(states=ATTEMPTED, asset=asset), page)
            ):
                if (
                    order.rule is not None
                    and order.finished_at is not None
                    and order.finished_at > window_start
                    and (order.rule not in attempted or order.finished_at > attempted[order.rule])
                ):
                    attempted[order.rule] = order.finished_at
            busy[asset] = (self._ops.subjects(asset, OPEN_ORDER_STATES), attempted)
        open_, attempted = busy[asset]
        if subject in open_ or (asset, subject) in planned:
            return False
        if (attempted_at := attempted.get(rule)) is not None:
            # The repository the demand is about — the one whose states a wake
            # rechecks — keeps the earliest wake; a later demand for the same
            # repository never postpones it.
            ready = attempted_at + RETRY_AFTER
            if repository_id is not None:
                self._deferred[repository_id] = min(self._deferred.get(repository_id, ready), ready)
                demanded.add(repository_id)
            return True
        planned.add((asset, subject))
        requests.append(
            OrderRequest(asset=asset, priority=spec.priority, repository_id=subject, rule=rule)
        )
        if repository_id is not None:
            demanded.add(repository_id)
        return True

    def _repository_of(self, assessment: Assessment) -> UUID | None:
        """The repository an assessment examined; None when its commit is gone."""
        assert self._portfolio is not None
        try:
            _, repository = self._portfolio.inventory.resolve(assessment.repository_ref_id)
        except NotFoundError:
            log.warning("assessment %s: repository ref not found", assessment.id)
            return None
        assert repository.id is not None
        return repository.id

    def _repositories(self) -> list[UUID]:
        """Every registered repository: what a fleet-wide run's closing re-reads."""
        assert self._portfolio is not None
        return [
            repository.id
            for repository in every_item(
                lambda page: self._portfolio.list_repositories(RepositoryFilter(), page)
            )
            if repository.id is not None
        ]
