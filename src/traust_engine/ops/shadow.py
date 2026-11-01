"""The shadow run (design step 7): runs made beside the engine recorded as orders, and the
daily comparison of the engine's shadow passes with them and with an expected routing."""

from __future__ import annotations

import logging
import subprocess
from collections import defaultdict
from collections.abc import Iterable, Iterator, Mapping, Sequence
from datetime import datetime, timedelta
from time import perf_counter
from uuid import UUID

from traust_core.v1.context.context import Services
from traust_core.v1.models.base import Model
from traust_core.v1.models.common import every_item
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.inventory import RepositoryFilter
from traust_core.v1.models.operations import (
    FINISHED_ORDER_STATES,
    JobResult,
    OrderFilter,
    OrderRequest,
    OrderState,
    RunOrder,
    WorkerId,
)

from traust_engine.ops.events import execution_scope, lifecycle
from traust_engine.ops.runner import CRASHED, outcome

log = logging.getLogger(__name__)

# A recorded run holds its lease for the whole command: nothing heartbeats it, and the shadow
# pass never reaps. A cron job still running after a day is broken anyway.
RECORD_LEASE = timedelta(hours=24)


Key = tuple[str, UUID | None]


class Tick(Model):
    """One shadow pass: when, and the orders it would have planned."""

    at: datetime
    due: tuple[OrderRequest, ...]


class Matched(Model):
    asset: str
    repository_id: UUID | None
    due_at: datetime | None
    ran_at: datetime
    late_by_hours: float | None


class Missed(Model):
    asset: str
    repository_id: UUID | None
    due_since: datetime


class Early(Model):
    asset: str
    repository_id: UUID | None
    ran_at: datetime
    due_in_hours: float | None


class RouteDifference(Model):
    repository_id: UUID
    url: str
    engine: str | None
    expected: str | None


class Diff(Model):
    since: datetime
    until: datetime
    matched: tuple[Matched, ...] = ()
    missed: tuple[Missed, ...] = ()
    early: tuple[Early, ...] = ()
    routes_same: int = 0
    routes_different: tuple[RouteDifference, ...] = ()

    @property
    def differences(self) -> int:
        return len(self.missed) + len(self.early) + len(self.routes_different)


def _complete(
    services: Services,
    order_id: UUID,
    worker: WorkerId,
    result: JobResult,
    started: float,
    *,
    returncode: int | None = None,
    error_type: str | None = None,
) -> RunOrder:
    try:
        completed = services.ops.complete(order_id, worker, result)
    except Exception as error:
        lifecycle(
            log,
            "execution",
            "failed",
            started=started,
            reason="completion_error",
            returncode=returncode,
            error_type=type(error).__name__,
        )
        raise
    lifecycle(
        log,
        "execution",
        str(completed.state),
        started=started,
        level=logging.INFO if completed.state is OrderState.SUCCEEDED else logging.WARNING,
        reason=str(result.reason) if result.reason is not None else None,
        status=str(completed.state),
        returncode=returncode,
        error_type=error_type,
    )
    return completed


def record(
    services: Services,
    request: OrderRequest,
    principal: Principal,
    worker: WorkerId,
    argv: Sequence[str],
) -> tuple[RunOrder, subprocess.CompletedProcess[str]]:
    """Run ``argv`` as an order of ``request``'s asset: started before, completed after."""
    started = perf_counter()
    order = services.ops.start(request, principal, worker, RECORD_LEASE)
    assert order.id is not None
    with execution_scope(order.id):
        try:
            done = subprocess.run(list(argv), capture_output=True, text=True, check=False)
        except OSError as error:
            _complete(
                services,
                order.id,
                worker,
                JobResult.failed(CRASHED),
                started,
                error_type=type(error).__name__,
            )
            raise
        except Exception as error:
            lifecycle(
                log,
                "execution",
                "failed",
                started=started,
                reason="command_error",
                error_type=type(error).__name__,
            )
            raise
        result = outcome(done)
        completed = _complete(
            services,
            order.id,
            worker,
            result,
            started,
            returncode=done.returncode,
        )
        return completed, done


def compare_runs(
    ticks: Sequence[Tick],
    runs: Iterable[RunOrder],
    cadence: Mapping[str, timedelta],
    tolerance: timedelta,
    since: datetime,
    until: datetime,
) -> tuple[list[Matched], list[Missed], list[Early]]:
    """Runs against the engine's due lists: a run while the engine listed its subject is
    matched; a run the engine wasn't asking for is early, unless its cadence fell due within
    ``tolerance``; a subject listed longer than ``tolerance`` with no run is missed. Runs before
    ``since`` only say when the next one falls due; routed orders are compared by route."""
    timelines: dict[Key, list[tuple[datetime, RunOrder | None]]] = defaultdict(list)
    for tick in ticks:
        for due in tick.due:
            if due.lane is None:
                timelines[(due.asset, due.repository_id)].append((tick.at, None))
    for run in runs:
        if run.started_at is not None:
            timelines[(run.asset, run.repository_id)].append((run.started_at, run))
    matched, missed, early = [], [], []
    for (asset, subject), timeline in timelines.items():
        listed: datetime | None = None
        finished: datetime | None = None
        every = cadence.get(asset)
        for at, run in sorted(timeline, key=lambda e: (e[0], e[1] is not None)):
            if run is None:
                listed = listed or at
                continue
            expected = listed or (finished + every if finished and every else None)
            if at < since:
                pass
            elif listed or (expected is not None and expected - at <= tolerance):
                late = None if expected is None else _hours(at - expected)
                matched.append(
                    Matched(
                        asset=asset,
                        repository_id=subject,
                        due_at=expected,
                        ran_at=at,
                        late_by_hours=late,
                    )
                )
            else:
                due_in = None if expected is None else _hours(expected - at)
                early.append(
                    Early(asset=asset, repository_id=subject, ran_at=at, due_in_hours=due_in)
                )
            listed, finished = None, run.finished_at or at
        if listed is not None and listed <= until - tolerance:
            missed.append(Missed(asset=asset, repository_id=subject, due_since=listed))
    return matched, missed, early


def _hours(delta: timedelta) -> float:
    return round(delta.total_seconds() / 3600, 2)


def compare_routes(
    ticks: Sequence[Tick],
    expected: Iterable[Mapping[str, object]],
    urls: Mapping[UUID, str],
    lanes: Iterable[str],
) -> tuple[int, list[RouteDifference]]:
    """The engine's latest routed lane per repository against an expected routing (rows of
    `repo_url` and `lane`); an expected lane no pack asset runs (`lanes`) counts as no lane."""
    queued = set(lanes)
    engine: dict[UUID, str] = {}
    for tick in sorted(ticks, key=lambda t: t.at):
        for due in tick.due:
            if due.lane is not None and due.repository_id is not None:
                engine[due.repository_id] = due.lane
    ids = {url: repository_id for repository_id, url in urls.items()}
    wanted: dict[UUID, str] = {}
    for row in expected:
        lane, repository_id = str(row.get("lane")), ids.get(str(row.get("repo_url")))
        if repository_id is not None and lane in queued:
            wanted[repository_id] = lane
    same, different = 0, []
    for repository_id in sorted(engine.keys() | wanted.keys(), key=str):
        mine, theirs = engine.get(repository_id), wanted.get(repository_id)
        if mine == theirs:
            same += 1
        else:
            url = urls.get(repository_id, "")
            different.append(
                RouteDifference(repository_id=repository_id, url=url, engine=mine, expected=theirs)
            )
    return same, different


def recorded_runs(services: Services, since: datetime) -> Iterator[RunOrder]:
    """Finished orders created since ``since``, newest first."""
    finished = OrderFilter(states=FINISHED_ORDER_STATES)
    for order in every_item(lambda p: services.ops.list(finished, p)):
        if order.created_at is not None and order.created_at < since:
            return
        yield order


def repository_urls(services: Services) -> dict[UUID, str]:
    portfolio = services.portfolio
    found = every_item(lambda p: portfolio.list_repositories(RepositoryFilter(), p))
    return {r.id: r.url for r in found if r.id is not None}
