"""One pass of the continuous-ops loop: reap expired leases, tick, dispatch remediation
work, admit."""

from __future__ import annotations

from collections.abc import Callable
from typing import Generic, TypeVar
from urllib.parse import urlsplit
from uuid import UUID

from traust_core.v1.context import Clock, Router, Services
from traust_core.v1.models.base import Model
from traust_core.v1.models.common import Cursor, every_item
from traust_core.v1.models.inventory import RecordedRelease, RepositoryFilter
from traust_core.v1.models.operations import OrderRequest

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


class EngineLoop(Generic[S]):
    def __init__(
        self,
        services: Services,
        clock: Clock,
        pack: Pack,
        router: Router[S, RecordedRelease] | None = None,
        state_of: Callable[[UUID], S] | None = None,
        remediations: Scheduling | None = None,
    ) -> None:
        self._services = services
        self._pack = pack
        self._controller = Controller(
            pack,
            services.ops,
            clock,
            router,
            state_of,
            services.feed,
            services.portfolio,
            remediations,
        )
        self._admission = Admission(pack, services.ops, services.spend, clock)
        self._remediation_cursor: Cursor | None = None

    def run_once(self) -> PassReport:
        requeued = self._services.ops.requeue_expired()
        hosts = self._hosts()
        tick = self._controller.tick(hosts.keys())
        due, cursor = self._controller.remediation_due(self._remediation_cursor)
        for request in due:
            self._services.ops.plan(request, ENGINE, self._pack.config())
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
        remediation, _ = self._controller.remediation_due(self._remediation_cursor, wake=False)
        return ShadowReport(tick=tick, due=tuple(due), remediation=tuple(remediation))

    def _hosts(self) -> dict[UUID, str]:
        portfolio = self._services.portfolio
        repositories = every_item(lambda p: portfolio.list_repositories(RepositoryFilter(), p))
        return {r.id: urlsplit(r.url).hostname or "" for r in repositories if r.id}
