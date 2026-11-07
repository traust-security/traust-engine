"""The fourth trigger: remediation assessments and finished remediation runs on the feed
become remediation and verification orders, read through the remediation service's door
(REMEDIATION-SCHEDULING-DESIGN.md, "Engine trigger" and "Verification trigger"). The
scheduling service lands in core beside this; the fakes below stand in for it."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
import yaml
from traust_core.v1.context import Config, Context
from traust_core.v1.context.context import Services
from traust_core.v1.models.assessment import Assessment
from traust_core.v1.models.common import Page, PageRequest, encode_cursor, every_item
from traust_core.v1.models.operations import (
    FeedEvent,
    JobResult,
    OrderFilter,
    OrderRequest,
    OrderState,
    RunOrder,
    WorkerId,
)
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.models.vocabulary import AssessmentKind, RemediationStatus

from traust_engine.ops.controller import ENGINE, Controller
from traust_engine.ops.loop import EngineLoop
from traust_engine.ops.pack import Pack
from traust_engine.ops.remediation import RETRY_AFTER, RemediationState

PACK = Path(__file__).parent / "fixtures" / "packs" / "security-source.yaml"
T0 = datetime(2026, 10, 1, 6, tzinfo=UTC)


class Clock:
    def __init__(self) -> None:
        self.at = T0

    def now(self) -> datetime:
        return self.at


class FakeFeed:
    """The ops feed in memory, oldest first, a page at a time however many were asked for."""

    def __init__(self, events: list[FeedEvent], page_size: int = 1000) -> None:
        self._events = sorted(events, key=lambda e: e.position)
        self._page_size = page_size
        self.reads = 0

    def list(self, page: PageRequest) -> Page[FeedEvent]:
        self.reads += 1
        after = page.position()
        remaining = [e for e in self._events if after is None or e.position > after]
        take = remaining[: self._page_size]
        return Page(
            items=tuple(take),
            next=encode_cursor(*remaining[self._page_size].position)
            if len(remaining) > self._page_size
            else None,
        )


class FakeRemediations:
    """Core's remediation scheduling service in memory: rows keyed by assessment and
    repository, exactly the reads the trigger asks for."""

    def __init__(self, *states: RemediationState) -> None:
        self.by_assessment = {s.assessment_id: s for s in states if s.assessment_id}
        self.by_repository: dict[UUID, list[RemediationState]] = {}
        for state in states:
            self.by_repository.setdefault(state.repository_id, []).append(state)

    def state_of(self, assessment_id: UUID) -> RemediationState | None:
        return self.by_assessment.get(assessment_id)

    def states_of(self, repository_id: UUID) -> list[RemediationState]:
        return list(self.by_repository.get(repository_id, ()))


def _context(tmp_path: Path, clock: Clock, **config: Any) -> Context:
    return Context(Config(home=tmp_path / "home", **config), clock=clock)


def _pack(tmp_path: Path) -> Pack:
    """The fixture pack plus the two remediation assets the trigger dispatches (the
    security pack runs `verify_remediation`; SCI's local pack adds `remediate_finding`)."""
    raw = yaml.safe_load(PACK.read_text())
    raw["assets"]["remediate_finding"] = {
        "model": {"role": "remediate-finding"},
        "partitions": "dynamic:repo",
    }
    raw["assets"]["verify_remediation"] = {"model": {"role": "verification-verdict"}}
    path = tmp_path / "assets.yaml"
    path.write_text(yaml.safe_dump(raw))
    return Pack.load(path)


def _repository(services: Services, *, nth: int = 0) -> tuple[UUID, UUID]:
    """A registered repository and one of its commits, for an assessment to name."""
    url = HttpsRepoUrl.parse(f"https://github.com/example/remediated-{nth}", ["github.com"])
    repository = services.portfolio.register_repository(url, public=True)
    ref = services.portfolio.register_ref(repository.id, GitSha("a" * 40), None, None)  # type: ignore[arg-type]
    assert repository.id is not None and ref.id is not None
    return repository.id, ref.id


def _assessment(
    at: datetime,
    *,
    kind: AssessmentKind = AssessmentKind.REMEDIATION,
    status: str = "candidate",
    repository_ref_id: UUID,
    run_order_id: UUID | None = None,
) -> Assessment:
    return Assessment(
        id=uuid4(),
        created_at=at,
        repository_ref_id=repository_ref_id,
        run_order_id=run_order_id,
        kind=kind,
        status=status,
        assessor="skill:remediate-finding",
        assessor_version="",
        occurred_at=at,
    )


def _order(
    at: datetime,
    *,
    asset: str = "remediate_finding",
    state: OrderState = OrderState.SUCCEEDED,
    repository_id: UUID | None = None,
) -> RunOrder:
    return RunOrder(
        id=uuid4(),
        created_at=at,
        updated_at=at,
        asset=asset,
        state=state,
        priority=10,
        requested_by="test",
        repository_id=repository_id,
    )


def _state(
    repository_id: UUID,
    status: RemediationStatus,
    *,
    reattempts: int = 0,
    remediation_id: UUID | None = None,
    assessment_id: UUID | None = None,
) -> RemediationState:
    return RemediationState(
        remediation_id=remediation_id or uuid4(),
        assessment_id=assessment_id,
        repository_id=repository_id,
        status=status,
        reattempts=reattempts,
    )


def _controller(
    services: Services,
    pack: Pack,
    feed: FakeFeed,
    remediations: FakeRemediations,
    clock: Clock | None = None,
) -> Controller[Any]:
    return Controller(
        pack,
        services.ops,
        clock or Clock(),
        feed=feed,
        portfolio=services.portfolio,
        remediations=remediations,
    )


def _dispatched(controller: Controller[Any]) -> list[tuple[str, UUID | None, str]]:
    requests, _ = controller.remediation_due(None)
    return [(r.asset, r.repository_id, r.rule or "") for r in requests]


def _orders(services: Services, *states: OrderState) -> list[RunOrder]:
    return list(every_item(lambda p: services.ops.list(OrderFilter(states=states), p)))


def test_a_remediation_request_without_its_order_plans_the_remediation_order(
    tmp_path: Path,
) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    repository, ref = _repository(services)
    assessment = _assessment(T0, repository_ref_id=ref)
    state = _state(repository, RemediationStatus.CANDIDATE, assessment_id=assessment.id)
    feed = FakeFeed([FeedEvent(assessment=assessment)])

    requests = _dispatched(_controller(services, _pack(tmp_path), feed, FakeRemediations(state)))

    # Keyed by the row's remediation_id — the same key a recheck's dispatch and
    # the retry window use, so a later failure of this order defers its re-run.
    assert requests == [("remediate_finding", repository, f"remediation:{state.remediation_id}")]


def test_an_assessment_without_a_remediation_row_plans_nothing(tmp_path: Path) -> None:
    """A candidate assessment the scheduling service holds no row for is not the
    engine's to plan: no state keys its retry window or reattempts, and the record
    door would have no row to move when the run lands."""
    clock = Clock()
    services = _context(tmp_path, clock).services()
    _, ref = _repository(services)
    assessment = _assessment(T0, repository_ref_id=ref)
    feed = FakeFeed([FeedEvent(assessment=assessment)])

    assert _dispatched(_controller(services, _pack(tmp_path), feed, FakeRemediations())) == []


def test_a_remediation_request_the_door_paired_with_an_order_plans_nothing(
    tmp_path: Path,
) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    _, ref = _repository(services)
    assessment = _assessment(T0, repository_ref_id=ref, run_order_id=uuid4())
    feed = FakeFeed([FeedEvent(assessment=assessment)])

    assert _dispatched(_controller(services, _pack(tmp_path), feed, FakeRemediations())) == []


def test_a_replayed_candidate_whose_remediation_moved_on_is_not_redispatched(
    tmp_path: Path,
) -> None:
    """A candidate assessment read again after its remediation patched: the remediation
    order is not re-planned; the verification order is."""
    clock = Clock()
    services = _context(tmp_path, clock).services()
    repository, ref = _repository(services)
    assessment = _assessment(T0, repository_ref_id=ref)
    state = _state(repository, RemediationStatus.PATCHED, assessment_id=assessment.id)
    feed = FakeFeed([FeedEvent(assessment=assessment)])

    requests = _dispatched(_controller(services, _pack(tmp_path), feed, FakeRemediations(state)))

    assert [r[0] for r in requests] == ["verify_remediation"]


@pytest.mark.parametrize("status", [RemediationStatus.PATCHED, RemediationStatus.CHECKS_PASSED])
def test_an_implemented_remediation_plans_a_verification_order(
    tmp_path: Path, status: RemediationStatus
) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    repository, ref = _repository(services)
    assessment = _assessment(T0, repository_ref_id=ref, run_order_id=uuid4())
    state = _state(repository, status, assessment_id=assessment.id)
    feed = FakeFeed([FeedEvent(assessment=assessment)])

    requests = _dispatched(_controller(services, _pack(tmp_path), feed, FakeRemediations(state)))

    # The verification sweep is fleet-wide in the pack: one order, whatever it verifies.
    assert requests == [("verify_remediation", None, f"verify-remediation:{state.remediation_id}")]


def test_a_still_vulnerable_remediation_below_the_limit_is_reattempted(
    tmp_path: Path,
) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    repository, ref = _repository(services)
    assessment = _assessment(T0, repository_ref_id=ref, run_order_id=uuid4())
    state = _state(
        repository,
        RemediationStatus.REVALIDATED_STILL_VULNERABLE,
        reattempts=0,
        assessment_id=assessment.id,
    )
    feed = FakeFeed([FeedEvent(assessment=assessment)])

    requests = _dispatched(_controller(services, _pack(tmp_path), feed, FakeRemediations(state)))

    assert requests == [("remediate_finding", repository, f"remediation:{state.remediation_id}")]


def test_a_still_vulnerable_remediation_at_the_limit_waits_for_a_person(
    tmp_path: Path,
) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    repository, ref = _repository(services)
    assessment = _assessment(T0, repository_ref_id=ref, run_order_id=uuid4())
    state = _state(
        repository,
        RemediationStatus.REVALIDATED_STILL_VULNERABLE,
        reattempts=2,
        assessment_id=assessment.id,
    )
    feed = FakeFeed([FeedEvent(assessment=assessment)])

    assert _dispatched(_controller(services, _pack(tmp_path), feed, FakeRemediations(state))) == []


def test_a_revalidated_fixed_remediation_is_left_to_the_filing_loop(
    tmp_path: Path,
) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    repository, ref = _repository(services)
    assessment = _assessment(T0, repository_ref_id=ref, run_order_id=uuid4())
    state = _state(repository, RemediationStatus.REVALIDATED_FIXED, assessment_id=assessment.id)
    feed = FakeFeed([FeedEvent(assessment=assessment)])

    assert _dispatched(_controller(services, _pack(tmp_path), feed, FakeRemediations(state))) == []


def test_a_feed_without_remediation_events_plans_nothing(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    repository, ref = _repository(services)
    events = [
        FeedEvent(order=_order(T0, asset="repo_state", repository_id=repository)),
        FeedEvent(
            assessment=_assessment(
                T0 + timedelta(minutes=1),
                kind=AssessmentKind.TRIAGE,
                status="completed",
                repository_ref_id=ref,
            )
        ),
    ]
    feed = FakeFeed(events)

    assert _dispatched(_controller(services, _pack(tmp_path), feed, FakeRemediations())) == []


def test_a_finished_remediation_run_rechecks_its_repository(tmp_path: Path) -> None:
    """The run that records patch progress finished: the repository's remediations are
    re-read, and one that reached patched gets its verification order."""
    clock = Clock()
    services = _context(tmp_path, clock).services()
    repository, _ = _repository(services)
    state = _state(repository, RemediationStatus.PATCHED)
    feed = FakeFeed([FeedEvent(order=_order(T0, repository_id=repository))])

    requests = _dispatched(_controller(services, _pack(tmp_path), feed, FakeRemediations(state)))

    assert requests == [("verify_remediation", None, f"verify-remediation:{state.remediation_id}")]


def test_a_recorded_verification_rechecks_its_repository(tmp_path: Path) -> None:
    """A verification assessment landed: the verdicts it recorded may have moved the
    repository's remediations to revalidated, and a still-vulnerable one is re-attempted."""
    clock = Clock()
    services = _context(tmp_path, clock).services()
    repository, ref = _repository(services)
    state = _state(repository, RemediationStatus.REVALIDATED_STILL_VULNERABLE, reattempts=1)
    verification = _assessment(
        T0, kind=AssessmentKind.VERIFICATION, status="completed", repository_ref_id=ref
    )
    feed = FakeFeed([FeedEvent(assessment=verification)])

    requests = _dispatched(_controller(services, _pack(tmp_path), feed, FakeRemediations(state)))

    assert requests == [("remediate_finding", repository, f"remediation:{state.remediation_id}")]


def test_an_open_order_suppresses_planning_another_for_the_subject(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    repository, ref = _repository(services)
    assessment = _assessment(T0, repository_ref_id=ref, run_order_id=uuid4())
    state = _state(repository, RemediationStatus.PATCHED, assessment_id=assessment.id)
    services.ops.submit(  # the weekly sweep is already queued
        OrderRequest(asset="verify_remediation", priority=50), ENGINE
    )
    feed = FakeFeed([FeedEvent(assessment=assessment)])

    assert _dispatched(_controller(services, _pack(tmp_path), feed, FakeRemediations(state))) == []


def test_one_request_per_subject_per_pass(tmp_path: Path) -> None:
    """Two remediations of one repository both patched in one pass: one verification
    order, not two."""
    clock = Clock()
    services = _context(tmp_path, clock).services()
    repository, _ = _repository(services)
    first = _state(repository, RemediationStatus.PATCHED)
    second = _state(repository, RemediationStatus.CHECKS_PASSED)
    orders = [
        FeedEvent(order=_order(T0, repository_id=repository)),
        FeedEvent(order=_order(T0 + timedelta(minutes=1), repository_id=repository)),
    ]
    feed = FakeFeed(orders)

    requests = _dispatched(
        _controller(services, _pack(tmp_path), feed, FakeRemediations(first, second))
    )

    assert requests == [("verify_remediation", None, f"verify-remediation:{first.remediation_id}")]


def test_the_cursor_resumes_after_the_events_a_pass_consumed(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    repository, _ = _repository(services)
    state = _state(repository, RemediationStatus.PATCHED)
    feed = FakeFeed([FeedEvent(order=_order(T0, repository_id=repository))], page_size=1)

    controller = _controller(services, _pack(tmp_path), feed, FakeRemediations(state))
    first, cursor = controller.remediation_due(None)
    assert [r.asset for r in first] == ["verify_remediation"] and feed.reads == 1

    # An event the next pass should read arrives after the cursor the pass returned.
    feed._events.append(
        FeedEvent(
            order=_order(T0 + timedelta(minutes=2), asset="repo_state", repository_id=repository)
        )
    )
    second, _ = controller.remediation_due(cursor)
    assert second == []  # the first event is consumed, not re-dispatched
    assert feed.reads == 2


def test_events_beyond_the_first_page_are_read(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    repository, _ = _repository(services)
    state = _state(repository, RemediationStatus.PATCHED)
    feed = FakeFeed(
        [
            FeedEvent(order=_order(T0 + timedelta(minutes=i), repository_id=repository))
            for i in range(3)
        ],
        page_size=2,
    )

    requests = _dispatched(_controller(services, _pack(tmp_path), feed, FakeRemediations(state)))

    assert [r[0] for r in requests] == ["verify_remediation"]
    assert feed.reads == 2


def test_a_pack_that_runs_no_remediation_asset_skips_the_dispatch(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    repository, ref = _repository(services)
    assessment = _assessment(T0, repository_ref_id=ref)
    state = _state(repository, RemediationStatus.PATCHED, assessment_id=assessment.id)
    feed = FakeFeed([FeedEvent(assessment=assessment)])

    assert _dispatched(_controller(services, Pack.load(PACK), feed, FakeRemediations(state))) == []


def test_the_trigger_needs_the_feed_and_the_portfolio(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    with pytest.raises(ValueError, match="remediation trigger"):
        Controller(Pack.load(PACK), services.ops, clock, remediations=FakeRemediations())


def test_the_loop_plans_and_admits_what_the_trigger_dispatches(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    repository, ref = _repository(services)
    assessment = _assessment(T0, repository_ref_id=ref)
    state = _state(repository, RemediationStatus.PATCHED, assessment_id=assessment.id)
    loop = EngineLoop(services, clock, _pack(tmp_path), remediations=FakeRemediations(state))
    loop._controller._feed = FakeFeed([FeedEvent(assessment=assessment)])  # type: ignore[assignment]

    report = loop.run_once()

    assert report.remediation == 1
    (order,) = [o for o in _orders(services, OrderState.QUEUED) if o.asset == "verify_remediation"]
    assert (order.repository_id, order.rule) == (None, f"verify-remediation:{state.remediation_id}")
    assert order.requested_by == ENGINE.ref


def _run(services: Services, order: RunOrder, result: JobResult) -> None:
    """Take an order through claim to completion, as the runner pool would."""
    worker = WorkerId("runner-1")
    claimed = services.ops.claim(worker, timedelta(minutes=5), (order.asset,))
    assert claimed is not None and claimed.id == order.id
    services.ops.complete(order.id, worker, result)


def _planned(
    controller: Controller[Any], services: Services, pack: Pack
) -> list[tuple[str, UUID | None, str]]:
    """The trigger's due requests, queued as the loop's plan-and-admit would: their
    (asset, subject, rule)."""
    requests, _ = controller.remediation_due(None)
    for request in requests:
        services.ops.submit(request, ENGINE)
    return [(r.asset, r.repository_id, r.rule or "") for r in requests]


def test_the_cursor_survives_a_planning_failure(tmp_path: Path) -> None:
    """Planning that fails partway through a batch must not consume the events behind it:
    the next pass retries the unplanned remainder without duplicating what landed."""
    clock = Clock()
    services = _context(tmp_path, clock).services()
    first, first_ref = _repository(services)
    second, second_ref = _repository(services, nth=1)
    first_assessment = _assessment(T0, repository_ref_id=first_ref)
    second_assessment = _assessment(T0 + timedelta(minutes=1), repository_ref_id=second_ref)
    states = FakeRemediations(
        _state(first, RemediationStatus.CANDIDATE, assessment_id=first_assessment.id),
        _state(second, RemediationStatus.CANDIDATE, assessment_id=second_assessment.id),
    )
    feed = FakeFeed(
        [FeedEvent(assessment=first_assessment), FeedEvent(assessment=second_assessment)],
        page_size=1,
    )
    pack = _pack(tmp_path)
    loop = EngineLoop(services, clock, pack, remediations=states)
    loop._controller._feed = feed  # type: ignore[assignment]
    planned: list[OrderRequest] = []
    original = services.ops.plan

    def failing(request: OrderRequest, *args: Any, **kwargs: Any) -> Any:
        if request.asset in ("remediate_finding", "verify_remediation"):
            if planned:
                raise RuntimeError("planning failed mid-batch")
            planned.append(request)
        return original(request, *args, **kwargs)

    services.ops.plan = failing  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="mid-batch"):
        loop.run_once()
    assert loop._remediation_cursor is None  # the cursor never advanced past the events

    services.ops.plan = original  # type: ignore[method-assign]
    report = loop.run_once()

    # The second request is retried; the first is not duplicated (its order is open).
    assert report.remediation == 1
    queued = [o for o in _orders(services, OrderState.QUEUED) if o.asset == "remediate_finding"]
    assert {o.repository_id for o in queued} == {first, second}


def test_the_shadow_reports_the_remediation_orders_a_pass_would_plan(tmp_path: Path) -> None:
    """Shadow parity: the would-be orders include the remediation trigger's, and reading
    them does not consume the live cursor."""
    clock = Clock()
    services = _context(tmp_path, clock).services()
    repository, ref = _repository(services)
    assessment = _assessment(T0, repository_ref_id=ref)
    state = _state(repository, RemediationStatus.PATCHED, assessment_id=assessment.id)
    loop = EngineLoop(services, clock, _pack(tmp_path), remediations=FakeRemediations(state))
    loop._controller._feed = FakeFeed([FeedEvent(assessment=assessment)])  # type: ignore[assignment]

    shadow = loop.shadow_once()

    # The remediation preview rides its own field: the cadence due list stays
    # what the shadow comparison measures.
    assert [(r.repository_id, r.rule) for r in shadow.remediation] == [
        (None, f"verify-remediation:{state.remediation_id}")
    ]
    assert not [r for r in shadow.due if r.asset == "verify_remediation"]
    assert loop._remediation_cursor is None  # the shadow consumed nothing

    report = loop.run_once()
    assert report.remediation == 1


def test_the_shadow_writes_no_deferral(tmp_path: Path) -> None:
    """A preview computes the same demand a live pass would, but a deferral is live
    state: a shadow that wrote one would wake a repository the live pass — whose
    cursor may have passed the creating event — never asked for."""
    clock = Clock()
    services = _context(tmp_path, clock).services()
    repository, ref = _repository(services)
    assessment = _assessment(T0, repository_ref_id=ref)
    state = _state(repository, RemediationStatus.CANDIDATE, assessment_id=assessment.id)
    pack = _pack(tmp_path)
    loop = EngineLoop(services, clock, pack, remediations=FakeRemediations(state))
    loop._controller._feed = FakeFeed([FeedEvent(assessment=assessment)])  # type: ignore[assignment]
    assert loop.run_once().remediation == 1
    (order,) = [o for o in _orders(services, OrderState.QUEUED) if o.asset == "remediate_finding"]
    _run(services, order, JobResult.succeeded())

    # The run landed without a record: a live pass over the finishing event would
    # defer the still-candidate demand — the preview must leave no deferral.
    loop._controller._feed = FakeFeed(  # type: ignore[assignment]
        [FeedEvent(order=_order(T0 + timedelta(minutes=1), repository_id=repository))]
    )
    shadow = loop.shadow_once()
    assert shadow.remediation == ()
    assert loop._controller._deferred == {}


def test_the_shadow_does_not_consume_deferred_demand(tmp_path: Path) -> None:
    """A preview must leave the deferred demand for the live pass: consuming it
    there would lose it — the live cursor has already passed the event that
    created it."""
    clock = Clock()
    services = _context(tmp_path, clock).services()
    repository, ref = _repository(services)
    assessment = _assessment(T0, repository_ref_id=ref)
    state = _state(repository, RemediationStatus.CANDIDATE, assessment_id=assessment.id)
    pack = _pack(tmp_path)
    loop = EngineLoop(services, clock, pack, remediations=FakeRemediations(state))
    loop._controller._feed = FakeFeed([FeedEvent(assessment=assessment)])  # type: ignore[assignment]
    assert loop.run_once().remediation == 1
    (order,) = [o for o in _orders(services, OrderState.QUEUED) if o.asset == "remediate_finding"]
    _run(services, order, JobResult.succeeded())
    loop._controller._feed = FakeFeed(  # type: ignore[assignment]
        [FeedEvent(order=_order(T0 + timedelta(minutes=1), repository_id=repository))]
    )
    loop.run_once()  # the failed-to-record attempt defers the still-candidate demand
    assert loop._controller._deferred == {repository: T0 + RETRY_AFTER}

    clock.at = T0 + timedelta(hours=2)
    shadow = loop.shadow_once()
    assert shadow.remediation == ()  # the preview wakes nothing
    assert loop._controller._deferred == {repository: T0 + RETRY_AFTER}  # and consumes nothing

    # The live pass still dispatches what the shadow previewed around.
    loop._controller._feed = FakeFeed([])  # type: ignore[assignment]
    assert loop.run_once().remediation == 1


def test_an_outdated_deferral_dispatches_nothing(tmp_path: Path) -> None:
    """A deferral wakes as a recheck of current state: demand that moved on
    while it waited plans no order."""
    clock = Clock()
    services = _context(tmp_path, clock).services()
    repository, ref = _repository(services)
    assessment = _assessment(T0, repository_ref_id=ref)
    state = _state(repository, RemediationStatus.CANDIDATE, assessment_id=assessment.id)
    states = FakeRemediations(state)
    pack = _pack(tmp_path)
    controller = _controller(
        services, pack, FakeFeed([FeedEvent(assessment=assessment)]), states, clock
    )
    assert _planned(controller, services, pack) == [
        ("remediate_finding", repository, f"remediation:{state.remediation_id}")
    ]
    (order,) = [o for o in _orders(services, OrderState.QUEUED) if o.asset == "remediate_finding"]
    _run(services, order, JobResult.succeeded())

    # The run landed without a record: the demand defers — then the remediation
    # is merged by another path before the wake.
    controller._feed = FakeFeed(  # type: ignore[assignment]
        [FeedEvent(order=_order(T0 + timedelta(minutes=1), repository_id=repository))]
    )
    assert _planned(controller, services, pack) == []
    assert controller._deferred == {repository: T0 + RETRY_AFTER}
    states.by_assessment[assessment.id] = state.model_copy(
        update={"status": RemediationStatus.MERGED}
    )
    states.by_repository[repository] = [states.by_assessment[assessment.id]]

    clock.at = T0 + timedelta(hours=2)
    controller._feed = FakeFeed([])  # type: ignore[assignment]
    assert _planned(controller, services, pack) == []  # nothing is still due


def test_a_candidate_suppressed_by_an_open_order_is_recovered_when_the_run_finishes(
    tmp_path: Path,
) -> None:
    """Two candidates of one repository: the second's order is suppressed while the first
    runs, and the first run's finishing recheck dispatches it — the assessment event
    behind the cursor cannot."""
    clock = Clock()
    services = _context(tmp_path, clock).services()
    repository, ref = _repository(services)
    first = _assessment(T0, repository_ref_id=ref)
    second = _assessment(T0 + timedelta(minutes=1), repository_ref_id=ref)
    first_state = _state(repository, RemediationStatus.CANDIDATE, assessment_id=first.id)
    second_state = _state(repository, RemediationStatus.CANDIDATE, assessment_id=second.id)
    states = FakeRemediations(first_state, second_state)
    pack = _pack(tmp_path)
    controller = _controller(services, pack, FakeFeed([FeedEvent(assessment=first)]), states, clock)

    # The first pass plans the first candidate's order.
    assert _planned(controller, services, pack) == [
        ("remediate_finding", repository, f"remediation:{first_state.remediation_id}")
    ]

    # The second candidate's event arrives while the first's order is open: suppressed.
    controller._feed = FakeFeed([FeedEvent(assessment=second)])  # type: ignore[assignment]
    assert _planned(controller, services, pack) == []

    # The first run finished and recorded: its remediation moved on, and the recheck
    # dispatches the verification it calls for and the second candidate's order —
    # immediately, because the retry window is the first remediation's, not the
    # repository's: an unrelated candidate never waits out another's attempt.
    (order,) = [o for o in _orders(services, OrderState.QUEUED) if o.asset == "remediate_finding"]
    _run(services, order, JobResult.succeeded())
    states.by_assessment[first.id] = first_state.model_copy(
        update={"status": RemediationStatus.PATCHED}
    )
    states.by_repository[repository] = [states.by_assessment[first.id], second_state]
    controller._feed = FakeFeed(  # type: ignore[assignment]
        [FeedEvent(order=_order(T0 + timedelta(minutes=2), repository_id=repository))]
    )
    assert _planned(controller, services, pack) == [
        ("verify_remediation", None, f"verify-remediation:{first_state.remediation_id}"),
        ("remediate_finding", repository, f"remediation:{second_state.remediation_id}"),
    ]


def test_a_candidate_whose_run_never_recorded_is_retried_after_the_window(
    tmp_path: Path,
) -> None:
    """A candidate whose remediation order finished without recording a report: the
    finishing recheck does not spin another run within the retry window, and does after."""
    clock = Clock()
    services = _context(tmp_path, clock).services()
    repository, ref = _repository(services)
    assessment = _assessment(T0, repository_ref_id=ref)
    state = _state(repository, RemediationStatus.CANDIDATE, assessment_id=assessment.id)
    pack = _pack(tmp_path)
    controller = _controller(
        services, pack, FakeFeed([FeedEvent(assessment=assessment)]), FakeRemediations(state), clock
    )
    assert _planned(controller, services, pack) == [
        ("remediate_finding", repository, f"remediation:{state.remediation_id}")
    ]

    # The run finished without recording: within the window, the recheck plans nothing.
    (order,) = [o for o in _orders(services, OrderState.QUEUED) if o.asset == "remediate_finding"]
    _run(services, order, JobResult.succeeded())
    controller._feed = FakeFeed(  # type: ignore[assignment]
        [FeedEvent(order=_order(T0 + timedelta(minutes=1), repository_id=repository))]
    )
    assert _planned(controller, services, pack) == []

    # Past the window, the still-candidate remediation is retried.
    clock.at = T0 + timedelta(hours=2)
    controller._feed = FakeFeed(  # type: ignore[assignment]
        [FeedEvent(order=_order(T0 + timedelta(minutes=2), repository_id=repository))]
    )
    assert _planned(controller, services, pack) == [
        ("remediate_finding", repository, f"remediation:{state.remediation_id}")
    ]


def test_a_failed_attempt_waits_out_the_retry_window(tmp_path: Path) -> None:
    """A patched remediation whose sweep failed without a verdict: a fresh scan (a None
    cursor, as after a restart) does not re-plan it within the window, and does after."""
    clock = Clock()
    services = _context(tmp_path, clock).services()
    repository, ref = _repository(services)
    assessment = _assessment(T0, repository_ref_id=ref)
    state = _state(repository, RemediationStatus.PATCHED, assessment_id=assessment.id)
    pack = _pack(tmp_path)
    sweep = services.ops.submit(
        OrderRequest(
            asset="verify_remediation",
            priority=10,
            rule=f"verify-remediation:{state.remediation_id}",
        ),
        ENGINE,
    )
    _run(services, sweep, JobResult.refused("source_unavailable"))

    controller = _controller(
        services, pack, FakeFeed([FeedEvent(assessment=assessment)]), FakeRemediations(state), clock
    )
    assert _planned(controller, services, pack) == []  # within the window: not re-planned

    clock.at = T0 + timedelta(hours=2)
    controller._feed = FakeFeed([FeedEvent(assessment=assessment)])  # type: ignore[assignment]
    assert _planned(controller, services, pack) == [
        ("verify_remediation", None, f"verify-remediation:{state.remediation_id}")
    ]


def test_a_fleet_wide_sweep_closing_rechecks_every_repository(tmp_path: Path) -> None:
    """A remediation that reached patched while a fleet-wide sweep was open: its request
    was suppressed and its event consumed; the sweep's closing re-dispatches it."""
    clock = Clock()
    services = _context(tmp_path, clock).services()
    repository, ref = _repository(services)
    assessment = _assessment(T0, repository_ref_id=ref)
    state = _state(repository, RemediationStatus.PATCHED, assessment_id=assessment.id)
    pack = _pack(tmp_path)
    sweep = services.ops.submit(  # the fleet-wide sweep is open
        OrderRequest(asset="verify_remediation", priority=50), ENGINE
    )
    feed = FakeFeed([FeedEvent(assessment=assessment)])

    controller = _controller(services, pack, feed, FakeRemediations(state), clock)
    assert _planned(controller, services, pack) == []  # suppressed while the sweep is open

    # The sweep closes (fleet-wide: no repository of its own): every repository is
    # re-read, and the still-patched remediation gets its verification order once the
    # closed sweep is past its retry window.
    _run(services, sweep, JobResult.succeeded())
    clock.at = T0 + timedelta(hours=2)
    controller._feed = FakeFeed(  # type: ignore[assignment]
        [FeedEvent(order=_order(T0 + timedelta(minutes=5), asset="verify_remediation"))]
    )
    assert _planned(controller, services, pack) == [
        ("verify_remediation", None, f"verify-remediation:{state.remediation_id}")
    ]


def test_a_failed_repair_is_retried_once_the_window_passes(tmp_path: Path) -> None:
    """A refused or failed run is a finished attempt too: its completion re-reads the
    repository, the still-candidate remediation waits out the retry window, and the
    next pass wakes it — no restart and no unrelated event needed."""
    clock = Clock()
    services = _context(tmp_path, clock).services()
    repository, ref = _repository(services)
    assessment = _assessment(T0, repository_ref_id=ref)
    state = _state(repository, RemediationStatus.CANDIDATE, assessment_id=assessment.id)
    pack = _pack(tmp_path)
    controller = _controller(
        services, pack, FakeFeed([FeedEvent(assessment=assessment)]), FakeRemediations(state), clock
    )
    assert _planned(controller, services, pack) == [
        ("remediate_finding", repository, f"remediation:{state.remediation_id}")
    ]
    (order,) = [o for o in _orders(services, OrderState.QUEUED) if o.asset == "remediate_finding"]
    _run(services, order, JobResult.refused("runner-crashed"))

    # The failed run's completion re-reads the repository; the attempt holds the
    # subject for the window, so the demand is deferred, not dropped or re-planned.
    controller._feed = FakeFeed(  # type: ignore[assignment]
        [FeedEvent(order=_order(T0 + timedelta(minutes=1), repository_id=repository))]
    )
    assert _planned(controller, services, pack) == []

    # The pass after the window wakes the deferred demand without a new event.
    clock.at = T0 + timedelta(hours=2)
    controller._feed = FakeFeed([])  # type: ignore[assignment]
    assert _planned(controller, services, pack) == [
        ("remediate_finding", repository, f"remediation:{state.remediation_id}")
    ]


def test_deferred_demand_wakes_without_a_new_event(tmp_path: Path) -> None:
    """Demand an attempt within the window suppressed — a patched remediation whose
    sweep just closed — is dispatched by the first pass after the window, with no new
    feed event to prompt it."""
    clock = Clock()
    services = _context(tmp_path, clock).services()
    repository, ref = _repository(services)
    assessment = _assessment(T0, repository_ref_id=ref)
    state = _state(repository, RemediationStatus.PATCHED, assessment_id=assessment.id)
    pack = _pack(tmp_path)
    sweep = services.ops.submit(
        OrderRequest(
            asset="verify_remediation",
            priority=10,
            rule=f"verify-remediation:{state.remediation_id}",
        ),
        ENGINE,
    )
    _run(services, sweep, JobResult.succeeded())
    controller = _controller(
        services, pack, FakeFeed([FeedEvent(assessment=assessment)]), FakeRemediations(state), clock
    )

    # The sweep that just closed holds the fleet-wide subject for the window: the
    # patched remediation's verification is deferred, not lost.
    controller._feed = FakeFeed(  # type: ignore[assignment]
        [FeedEvent(order=_order(T0 + timedelta(minutes=1), asset="verify_remediation"))]
    )
    assert _planned(controller, services, pack) == []

    # The next pass after the window wakes it — no event, no restart.
    clock.at = T0 + timedelta(hours=2)
    controller._feed = FakeFeed([])  # type: ignore[assignment]
    assert _planned(controller, services, pack) == [
        ("verify_remediation", None, f"verify-remediation:{state.remediation_id}")
    ]


def test_a_pass_rechecks_each_repository_once_whatever_its_history(tmp_path: Path) -> None:
    """A replayed history costs one remediation-state read per repository, not one per
    finished order: the rechecks a pass's events call for run once, at the end."""
    clock = Clock()
    services = _context(tmp_path, clock).services()
    repository, _ = _repository(services)
    state = _state(repository, RemediationStatus.PATCHED)
    reads = {"states_of": 0}

    class CountingRemediations(FakeRemediations):
        def states_of(self, repository_id: UUID) -> list[RemediationState]:
            reads["states_of"] += 1
            return super().states_of(repository_id)

    feed = FakeFeed(
        [
            FeedEvent(order=_order(T0 + timedelta(minutes=i), asset="verify_remediation"))
            for i in range(5)
        ]
    )
    controller = _controller(services, _pack(tmp_path), feed, CountingRemediations(state), clock)

    assert _dispatched(controller) == [
        ("verify_remediation", None, f"verify-remediation:{state.remediation_id}")
    ]
    # Five replayed fleet-wide completions, one repository: one state read.
    assert reads["states_of"] == 1


def test_a_deferred_retry_wakes_when_eligible_not_a_window_after_it_was_seen(
    tmp_path: Path,
) -> None:
    """The wake honors the attempt's own age: an attempt seen near the end of its
    window wakes the demand shortly after it becomes eligible, not a full window
    after the pass that noticed it."""
    clock = Clock()
    services = _context(tmp_path, clock).services()
    repository, ref = _repository(services)
    assessment = _assessment(T0, repository_ref_id=ref)
    state = _state(repository, RemediationStatus.CANDIDATE, assessment_id=assessment.id)
    pack = _pack(tmp_path)
    controller = _controller(
        services, pack, FakeFeed([FeedEvent(assessment=assessment)]), FakeRemediations(state), clock
    )
    assert _planned(controller, services, pack) == [
        ("remediate_finding", repository, f"remediation:{state.remediation_id}")
    ]
    (order,) = [o for o in _orders(services, OrderState.QUEUED) if o.asset == "remediate_finding"]
    clock.at = T0 + timedelta(minutes=50)  # the attempt fails late in its window
    _run(services, order, JobResult.refused("runner-crashed"))
    eligibility = T0 + timedelta(minutes=50) + RETRY_AFTER

    # A pass five minutes later sees the failure and defers the retry.
    clock.at = T0 + timedelta(minutes=55)
    controller._feed = FakeFeed(  # type: ignore[assignment]
        [FeedEvent(order=_order(T0 + timedelta(minutes=51), repository_id=repository))]
    )
    assert _planned(controller, services, pack) == []

    # One minute past eligibility the retry dispatches — not an hour after the
    # pass that deferred it.
    clock.at = eligibility + timedelta(minutes=1)
    controller._feed = FakeFeed([])  # type: ignore[assignment]
    assert _planned(controller, services, pack) == [
        ("remediate_finding", repository, f"remediation:{state.remediation_id}")
    ]


def test_an_unrelated_remediation_does_not_wait_out_another_attempt(
    tmp_path: Path,
) -> None:
    """The retry window is the remediation's own, not the repository's: a candidate
    whose remediation never ran dispatches right after an unrelated order of the
    same repository finishes — only the open-order serialization applies."""
    clock = Clock()
    services = _context(tmp_path, clock).services()
    repository, ref = _repository(services)
    first = _assessment(T0, repository_ref_id=ref)
    second = _assessment(T0 + timedelta(minutes=1), repository_ref_id=ref)
    first_state = _state(repository, RemediationStatus.CANDIDATE, assessment_id=first.id)
    second_state = _state(repository, RemediationStatus.CANDIDATE, assessment_id=second.id)
    pack = _pack(tmp_path)
    controller = _controller(
        services,
        pack,
        FakeFeed([FeedEvent(assessment=first)]),
        FakeRemediations(first_state, second_state),
        clock,
    )
    assert _planned(controller, services, pack) == [
        ("remediate_finding", repository, f"remediation:{first_state.remediation_id}")
    ]
    (order,) = [o for o in _orders(services, OrderState.QUEUED) if o.asset == "remediate_finding"]
    _run(services, order, JobResult.succeeded())

    # Minutes later — deep inside the first attempt's retry window — the second
    # candidate's event arrives: it dispatches now, not after the hour.
    clock.at = T0 + timedelta(minutes=5)
    controller._feed = FakeFeed([FeedEvent(assessment=second)])  # type: ignore[assignment]
    assert _planned(controller, services, pack) == [
        ("remediate_finding", repository, f"remediation:{second_state.remediation_id}")
    ]


def test_a_wake_survives_a_planning_failure(tmp_path: Path) -> None:
    """A matured wake whose pass fails to plan is not lost: the wake is kept until a
    pass proves the demand satisfied, so the next pass — whose cursor is past the
    creating event — still dispatches it, immediately (its ready_at has passed)."""
    clock = Clock()
    services = _context(tmp_path, clock).services()
    repository, ref = _repository(services)
    assessment = _assessment(T0, repository_ref_id=ref)
    state = _state(repository, RemediationStatus.CANDIDATE, assessment_id=assessment.id)
    pack = _pack(tmp_path)
    loop = EngineLoop(services, clock, pack, remediations=FakeRemediations(state))
    loop._controller._feed = FakeFeed([FeedEvent(assessment=assessment)])  # type: ignore[assignment]
    assert loop.run_once().remediation == 1
    (order,) = [o for o in _orders(services, OrderState.QUEUED) if o.asset == "remediate_finding"]
    _run(services, order, JobResult.succeeded())
    loop._controller._feed = FakeFeed(  # type: ignore[assignment]
        [FeedEvent(order=_order(T0 + timedelta(minutes=1), repository_id=repository))]
    )
    loop.run_once()  # the run landed without a record: the candidate demand defers
    clock.at = T0 + timedelta(hours=2)  # the wake matures

    # The wake's pass dispatches, and planning fails after it: the wake survives.
    loop._controller._feed = FakeFeed([])  # type: ignore[assignment]
    original = services.ops.plan

    def failing(request: OrderRequest, *args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("planning failed")

    services.ops.plan = failing  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="planning failed"):
        loop.run_once()
    assert loop._controller._deferred  # the wake is still there

    # The next pass dispatches it again — no event, no window: its time had come.
    services.ops.plan = original  # type: ignore[method-assign]
    assert loop.run_once().remediation == 1
