"""One pass of the continuous-ops loop: reap expired leases, tick, dispatch remediation
work, admit."""

from __future__ import annotations

from collections.abc import Callable, Collection, Sequence
from typing import Generic, TypeVar
from urllib.parse import urlsplit
from uuid import UUID

from traust_core.v1.context import Clock, Router, Services
from traust_core.v1.models.base import Model
from traust_core.v1.models.common import Cursor, every_item
from traust_core.v1.models.inventory import RecordedRelease, RepositoryFilter
from traust_core.v1.models.operations import (
    REMEDIATE_FINDING,
    AssetName,
    ConfigDigest,
    OrderRequest,
    RunOrder,
)

from traust_engine.ops.admission import Admission, AdmissionReport
from traust_engine.ops.controller import ENGINE, Controller, Scheduling, TickReport
from traust_engine.ops.pack import Pack

S = TypeVar("S")


class PassReport(Model):
    requeued: int
    tick: TickReport
    remediation: int = 0  # orders the remediation trigger planned
    admission: AdmissionReport


class ShadowReport(Model):
    tick: TickReport
    due: tuple[OrderRequest, ...]
    # The remediation trigger's would-be orders, kept out of `due`: the shadow
    # comparison measures cron's cadence work against recorded runs, and
    # remediation orders are event-driven work cron was never scheduled to run
    # — counting them as missed would misreport the cutover comparison.
    remediation: tuple[OrderRequest, ...] = ()


def plan_request(
    services: Services,
    request: OrderRequest,
    config: Sequence[ConfigDigest] = (),
    scheduling: Scheduling | None = None,
) -> RunOrder:
    """Plan one of the engine's own requests. remediate_finding is door-only (traust-core#541):
    another attempt of a scheduled effort goes through the scheduling door (the loop's own
    scheduling service, core's by default), which plans it with the effort's own fork facts;
    every other asset is planned directly."""
    if request.asset == REMEDIATE_FINDING:
        door = services.remediation_scheduling if scheduling is None else scheduling
        return door.reattempt(request, ENGINE, config)
    return services.ops.plan(request, ENGINE, config)


class EngineLoop(Generic[S]):
    def __init__(
        self,
        services: Services,
        clock: Clock,
        pack: Pack,
        router: Router[S, RecordedRelease] | None = None,
        state_of: Callable[[UUID], S] | None = None,
        remediations: Scheduling | None = None,
        assets: Collection[AssetName] | None = None,
    ) -> None:
        self._services = services
        self._pack = pack
        self._remediations = remediations
        # `run --asset`: the tick plans, and the pass admits, only the named assets —
        # the rest are left untouched for the engine that was given them.
        selected = None if assets is None else frozenset(assets)
        self._controller = Controller(
            pack,
            services.ops,
            clock,
            router,
            state_of,
            services.feed,
            services.portfolio,
            remediations,
            assets=selected,
        )
        self._admission = Admission(pack, services.ops, services.spend, clock, assets=selected)
        self._remediation_cursor: Cursor | None = None

    def run_once(self) -> PassReport:
        requeued = self._services.ops.requeue_expired()
        hosts = self._hosts()
        tick = self._controller.tick(hosts.keys())
        due, cursor = self._controller.remediation_due(
            self._remediation_cursor, active=hosts.keys()
        )
        for request in due:
            plan_request(self._services, request, self._pack.config(), self._remediations)
        # The cursor advances only once every request is planned: a planning failure
        # retries the unplanned remainder on the next pass, without duplicating the
        # requests that landed (an open or recently attempted order suppresses them).
        self._remediation_cursor = cursor
        return PassReport(
            requeued=requeued,
            tick=tick,
            remediation=len(due),
            admission=self._admission.admit(hosts),
        )

    def shadow_once(self) -> ShadowReport:
        """The orders a pass would plan, with nothing reaped, planned or admitted: run beside cron
        (whose runs are recorded orders) until the cutover."""
        tick, due, _ = self._controller.due(self._hosts().keys())
        # The remediation scan reads from the live cursor and discards its resume
        # point, and wakes no deferred demand: the shadow previews what the next
        # live pass would plan without consuming anything it alone could recover.
        remediation, _ = self._controller.remediation_due(
            self._remediation_cursor, wake=False, active=self._hosts().keys()
        )
        return ShadowReport(tick=tick, due=tuple(due), remediation=tuple(remediation))

    def _hosts(self) -> dict[UUID, str]:
        """The planner's universe: the active repositories only. A repository carrying
        the unreachable disposition (foundry plan repo-unreachable) left it — two
        consecutive gone-class observation failures flipped it, and only a person's
        verify returns it — so the tick neither routes nor plans any asset for it, and
        the dead registrations cost no roundtrip per walk."""
        portfolio = self._services.portfolio
        repositories = every_item(
            lambda p: portfolio.list_repositories(RepositoryFilter(dispositioned=False), p)
        )
        return {r.id: urlsplit(r.url).hostname or "" for r in repositories if r.id}
