"""The loop over real core services on SQLite: a first tick from empty through routing,
cadence, budget, approval, pacing and the reaper."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
import yaml
from traust_core.v1.context import Config, Context
from traust_core.v1.context.context import Services
from traust_core.v1.errors import ConfigError, NotFoundError
from traust_core.v1.models.artifacts import RunManifestArtifact
from traust_core.v1.models.common import every_item
from traust_core.v1.models.inventory import (
    ProductSlug,
    RecordedRelease,
    ReleaseCommit,
    VersionLabel,
)
from traust_core.v1.models.operations import (
    OPEN_ORDER_STATES,
    JobResult,
    OrderFilter,
    OrderRequest,
    OrderState,
    Refusal,
    Route,
    RunOrder,
    WorkerId,
)
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.services.artifact_publishing import PublishSpec, PublishSpecs

from traust_engine.ops.controller import ENGINE, Controller
from traust_engine.ops.loop import EngineLoop
from traust_engine.ops.pack import Pack

PACK = Path(__file__).parent / "fixtures" / "packs" / "security-source.yaml"
T0 = datetime(2026, 10, 1, 6, tzinfo=UTC)
WORKER = WorkerId("runner-1")
LEASE = timedelta(minutes=5)
SUCCEEDED = JobResult.succeeded()


class Clock:
    def __init__(self) -> None:
        self.at = T0

    def now(self) -> datetime:
        return self.at


class LaneRouter:
    """Routes every repository to diff-scan except those in `skip`."""

    def __init__(self, skip: frozenset[UUID] = frozenset()) -> None:
        self.skip = skip
        self.seen: list[UUID] = []

    def route(self, state: UUID, events: object, refusals: object) -> tuple[Route, ...]:
        self.seen.append(state)
        lane = None if state in self.skip else "diff-scan"
        return (Route(lane=lane, priority=1, reason="rule-4"),)  # type: ignore[arg-type]


def _context(tmp_path: Path, clock: Clock, **config: Any) -> Context:
    return Context(Config(home=tmp_path / "home", **config), clock=clock)


def _repositories(services: Services, count: int, host: str = "github.com") -> list[UUID]:
    urls = [HttpsRepoUrl.parse(f"https://{host}/example/r{i}", [host]) for i in range(count)]
    return [services.portfolio.register_repository(u, public=True).id for u in urls]  # type: ignore[misc]


def _orders(services: Services, *states: OrderState) -> list[RunOrder]:
    return list(every_item(lambda p: services.ops.list(OrderFilter(states=states), p)))


def _by_asset(orders: list[RunOrder]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for o in orders:
        counts[o.asset] = counts.get(o.asset, 0) + 1
    return counts


def _drain(services: Services, result: JobResult = SUCCEEDED) -> list[RunOrder]:
    """A runner claims and completes every queued order."""
    done = []
    while (order := services.ops.claim(WORKER, LEASE)) is not None:
        done.append(services.ops.complete(order.id, WORKER, result))  # type: ignore[arg-type]
    return done


def _materialize(services: Services, asset: str, repository_id: UUID | None) -> None:
    order = services.ops.start(
        OrderRequest(asset=asset, priority=20, repository_id=repository_id), ENGINE, WORKER, LEASE
    )
    assert order.id is not None
    services.ops.complete(order.id, WORKER, SUCCEEDED)


def _pack(tmp_path: Path, **changes: dict[str, Any]) -> Pack:
    """The fixture pack with some assets' top-level keys replaced."""
    raw = yaml.safe_load(PACK.read_text())
    for asset, fields in changes.items():
        raw["assets"][asset] |= fields
    path = tmp_path / "assets.yaml"
    path.write_text(yaml.safe_dump(raw))
    return Pack.load(path)


def test_a_first_tick_from_empty_queues_the_source_assets(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    repos = _repositories(services, 3)
    report = EngineLoop(services, clock, Pack.load(PACK)).run_once()

    assert report.tick.planned == 4  # feeds_cache + repo_state x3
    assert report.tick.stale == {"dependency_graph": 3}
    assert (report.admission.admitted, report.admission.deferred) == (3, 1)  # quota 2/h
    queued = _orders(services, OrderState.QUEUED)
    assert _by_asset(queued) == {"feeds_cache": 1, "repo_state": 2}
    assert all(o.requested_by == ENGINE.ref and o.lane is None for o in queued)
    (waiting,) = _orders(services, OrderState.PLANNED)
    assert waiting.asset == "repo_state" and waiting.repository_id in repos


def test_a_second_tick_plans_nothing_already_open(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    _repositories(services, 3)
    loop = EngineLoop(services, clock, Pack.load(PACK))
    loop.run_once()
    again = loop.run_once()
    assert again.tick.planned == 0
    assert (again.admission.admitted, again.admission.deferred) == (0, 1)


def test_quota_refills_and_admits_the_deferred_order(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    _repositories(services, 3)
    loop = EngineLoop(services, clock, Pack.load(PACK))
    loop.run_once()
    clock.at += timedelta(minutes=30)
    assert loop.run_once().admission.admitted == 1
    assert _orders(services, OrderState.PLANNED) == []


def test_quota_is_per_forge_host(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    _repositories(services, 2, "github.com")
    _repositories(services, 2, "gitlab.com")
    report = EngineLoop(services, clock, Pack.load(PACK)).run_once()
    assert report.admission.deferred == 0


def test_a_materialized_source_unblocks_downstream_and_routes_once(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    repos = _repositories(services, 2)
    router = LaneRouter()
    loop = EngineLoop(services, clock, Pack.load(PACK), router, state_of=lambda r: r)
    loop.run_once()
    clock.at += timedelta(minutes=10)
    _drain(services)

    report = loop.run_once()
    assert report.tick.routed == 2 and sorted(router.seen) == sorted(repos)
    assert report.tick.stale == {}
    queued = _orders(services, OrderState.QUEUED)
    assert _by_asset(queued) == {"diff_scan": 2, "dependency_graph": 2}
    scans = [o for o in queued if o.asset == "diff_scan"]
    assert all((o.lane, o.rule, o.priority) == ("diff-scan", "rule-4", 1) for o in scans)

    router.seen.clear()
    assert loop.run_once().tick.routed == 0  # nothing new materialized since the last tick


class TableAndAdditiveRouter:
    """The decision table's route, then additive lanes (lever 6, the threat-model backstop)."""

    def route(self, state: UUID, events: object, refusals: object) -> tuple[Route, ...]:
        return (
            Route(lane="diff-scan", priority=1, reason="rule-5"),  # type: ignore[arg-type]
            Route(lane="iac-lane", priority=2, reason="lever-6"),  # type: ignore[arg-type]
            Route(lane=None, priority=3, reason="classified, not queued"),
        )


def _iac_pack(tmp_path: Path, **iac: Any) -> Pack:
    """The fixture pack plus an `iac_lane` asset running the iac-lane lane; a None field is
    dropped."""
    raw = yaml.safe_load(PACK.read_text())
    asset = raw["assets"]["diff_scan"] | {"trigger": {"lanes": ["iac-lane"]}} | iac
    raw["assets"]["iac_lane"] = {k: v for k, v in asset.items() if v is not None}
    path = tmp_path / "assets.yaml"
    path.write_text(yaml.safe_dump(raw))
    return Pack.load(path)


def _routed_once(tmp_path: Path, pack: Pack, router: Any) -> tuple[Services, Clock, UUID]:
    """One repository whose repo_state has materialized, routed by the second tick."""
    clock = Clock()
    services = _context(tmp_path, clock).services()
    (repo,) = _repositories(services, 1)
    loop = EngineLoop(services, clock, pack, router, state_of=lambda r: r)
    loop.run_once()
    clock.at += timedelta(minutes=10)
    _drain(services)
    loop.run_once()
    return services, clock, repo


def _routed_orders(services: Services) -> list[tuple[str, str | None, str | None, UUID | None]]:
    orders = _orders(services, OrderState.PLANNED, OrderState.QUEUED)
    return sorted((o.asset, o.lane, o.rule, o.repository_id) for o in orders if o.lane)


def test_every_route_with_a_lane_plans_its_lane_asset_once(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    (repo,) = _repositories(services, 1)
    router = TableAndAdditiveRouter()
    loop = EngineLoop(services, clock, _iac_pack(tmp_path), router, state_of=lambda r: r)
    loop.run_once()
    clock.at += timedelta(minutes=10)
    _drain(services)

    report = loop.run_once()
    routed = [o for o in _orders(services, OrderState.QUEUED) if o.lane]
    assert report.tick.routed == 1
    assert sorted((o.asset, o.lane, o.rule, o.repository_id) for o in routed) == [
        ("diff_scan", "diff-scan", "rule-5", repo),
        ("iac_lane", "iac-lane", "lever-6", repo),
    ]


def test_routing_the_same_repository_again_plans_no_second_order(tmp_path: Path) -> None:
    pack = _iac_pack(tmp_path)
    services, clock, repo = _routed_once(tmp_path, pack, TableAndAdditiveRouter())
    first = _routed_orders(services)
    # A restarted engine resumes after the last routed order; repo_state materializing again
    # routes the same repository again.
    clock.at += timedelta(minutes=1)
    _materialize(services, "repo_state", repo)
    report = EngineLoop(services, clock, pack, TableAndAdditiveRouter(), lambda r: r).run_once()
    assert report.tick.routed == 1
    assert _routed_orders(services) == first
    assert [o[0] for o in first] == ["diff_scan", "iac_lane"]


def test_a_route_to_a_disabled_assets_lane_plans_nothing_for_it(tmp_path: Path) -> None:
    pack = _iac_pack(tmp_path, enabled=False)
    services, _, repo = _routed_once(tmp_path, pack, TableAndAdditiveRouter())
    assert _routed_orders(services) == [("diff_scan", "diff-scan", "rule-5", repo)]


def test_a_route_to_a_lane_no_asset_runs_fails_the_pass(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="runs no asset for lane"):
        _routed_once(tmp_path, Pack.load(PACK), TableAndAdditiveRouter())


def test_a_repository_the_router_leaves_alone_gets_no_routed_order(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    quiet, busy = _repositories(services, 2)
    loop = EngineLoop(services, clock, Pack.load(PACK), LaneRouter(frozenset({quiet})), lambda r: r)
    loop.run_once()
    clock.at += timedelta(minutes=10)
    _drain(services)
    loop.run_once()
    scans = [o for o in _orders(services, OrderState.QUEUED) if o.asset == "diff_scan"]
    assert [o.repository_id for o in scans] == [busy]


def test_a_repository_without_routing_state_is_counted_not_routed(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    _repositories(services, 1)

    def missing(repository_id: UUID) -> UUID:
        raise NotFoundError(f"no forge observation for {repository_id}")

    loop = EngineLoop(services, clock, Pack.load(PACK), LaneRouter(), missing)
    loop.run_once()
    clock.at += timedelta(minutes=10)
    _drain(services)
    report = loop.run_once()
    assert (report.tick.routed, report.tick.unrouted) == (0, 1)


def test_cadence_makes_a_source_due_again(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    _repositories(services, 1)
    loop = EngineLoop(services, clock, Pack.load(PACK))
    loop.run_once()
    _drain(services)
    clock.at += timedelta(hours=23)
    assert _by_asset(_orders(services, OrderState.PLANNED)) == {}
    assert loop.run_once().tick.planned == 1  # dependency_graph, now that its deps are fresh
    clock.at += timedelta(hours=2)
    _drain(services)
    assert loop.run_once().tick.planned == 2  # feeds_cache and repo_state, a day on


def test_a_failed_run_waits_out_the_cadence(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    _repositories(services, 1)
    loop = EngineLoop(services, clock, Pack.load(PACK))
    loop.run_once()
    _drain(services, JobResult.failed("runner-crashed"))
    clock.at += timedelta(hours=1)
    report = loop.run_once()
    assert report.tick.planned == 0
    assert report.tick.stale == {"dependency_graph": 1}


def test_the_reaper_requeues_expired_leases(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    loop = EngineLoop(services, clock, Pack.load(PACK))
    loop.run_once()
    assert services.ops.claim(WORKER, LEASE) is not None
    clock.at += LEASE + timedelta(seconds=1)
    assert loop.run_once().requeued == 1


@pytest.mark.parametrize(
    ("enforcement", "withheld"), [("advisory", 1), ("observe", 0)], ids=["binding", "observe"]
)
def test_the_lane_budget_cuts_the_lowest_priority_routed_work(
    tmp_path: Path, enforcement: str, withheld: int
) -> None:
    clock = Clock()
    budget = {"lane": "diff-scan", "monthly_usd": "3", "enforcement": enforcement}
    services = _context(tmp_path, clock, budgets=[budget]).services()
    first, second = _repositories(services, 2)
    services.ops.plan(
        OrderRequest(asset="diff_scan", priority=1, repository_id=first, lane="diff-scan"), ENGINE
    )
    services.ops.plan(
        OrderRequest(asset="diff_scan", priority=9, repository_id=second, lane="diff-scan"), ENGINE
    )
    report = EngineLoop(services, clock, Pack.load(PACK)).run_once()
    assert report.admission.withheld == withheld
    if withheld:
        (cut,) = [o for o in _orders(services, OrderState.WITHHELD) if o.asset == "diff_scan"]
        assert (cut.repository_id, cut.reason) == (second, "budget-over")


def _stale_stops(services: Services) -> list[tuple[UUID | None, datetime | None]]:
    withheld = _orders(services, OrderState.WITHHELD)
    return sorted(
        ((o.repository_id, o.finished_at) for o in withheld if o.reason == "upstream-stale"),
        key=str,
    )


def test_a_stale_upstream_leaves_one_stop_per_subject_per_dependency_cadence(
    tmp_path: Path,
) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    repos = _repositories(services, 2)
    loop = EngineLoop(services, clock, Pack.load(PACK))
    for _ in range(3):
        assert loop.run_once().tick.stale == {"dependency_graph": 2}
        clock.at += timedelta(hours=1)
    first = _stale_stops(services)
    assert sorted(r for r, _ in first) == sorted(repos) and {at for _, at in first} == {T0}
    assert all(o.asset == "dependency_graph" for o in _orders(services, OrderState.WITHHELD))

    clock.at = T0 + timedelta(hours=24, minutes=1)
    assert loop.run_once().tick.stale == {"dependency_graph": 2}
    clock.at += timedelta(hours=1)
    loop.run_once()
    rolled = [s for s in _stale_stops(services) if s not in first]
    assert sorted(rolled, key=str) == sorted(
        ((r, T0 + timedelta(hours=24, minutes=1)) for r in repos), key=str
    )


def test_a_stale_stop_never_holds_back_the_order_once_upstreams_are_fresh(
    tmp_path: Path,
) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    repos = _repositories(services, 2)
    loop = EngineLoop(services, clock, Pack.load(PACK))
    loop.run_once()
    clock.at += timedelta(minutes=10)
    _drain(services)
    report = loop.run_once()
    assert report.tick.stale == {}
    graphs = [o for o in _orders(services, *OPEN_ORDER_STATES) if o.asset == "dependency_graph"]
    assert sorted(o.repository_id for o in graphs) == sorted(repos)
    assert len(_stale_stops(services)) == 2


def test_a_shadow_pass_records_no_stale_stop(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    _repositories(services, 2)
    shadow = EngineLoop(services, clock, Pack.load(PACK)).shadow_once()
    assert shadow.tick.stale == {"dependency_graph": 2}
    assert _orders(services, OrderState.WITHHELD) == []


def test_unknown_cost_is_never_withheld(tmp_path: Path) -> None:
    clock = Clock()
    budget = {"lane": "diff-scan", "monthly_usd": "0", "enforcement": "enforced"}
    services = _context(tmp_path, clock, budgets=[budget]).services()
    (repo,) = _repositories(services, 1)
    services.ops.plan(
        OrderRequest(asset="diff_scan", priority=1, repository_id=repo, lane="diff-scan"), ENGINE
    )
    pack = _pack(tmp_path, diff_scan={"admission": {}})
    assert EngineLoop(services, clock, pack).run_once().admission.withheld == 0


def test_a_human_gated_asset_waits_for_approval(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    pack = _pack(tmp_path, feeds_cache={"admission": {"approval": "security-operators"}})
    report = EngineLoop(services, clock, pack).run_once()
    assert report.admission.awaiting_approval == 1
    (held,) = _orders(services, OrderState.AWAITING_APPROVAL)
    assert held.asset == "feeds_cache"


def test_pacing_spreads_an_asset_across_ticks(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    _repositories(services, 3)
    pack = _pack(tmp_path, repo_state={"admission": {"pacing": {"per_tick": 1}}})
    loop = EngineLoop(services, clock, pack)
    assert loop.run_once().admission.deferred == 2
    assert loop.run_once().admission.deferred == 1


def test_a_planned_order_for_an_asset_the_pack_dropped_is_withheld(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    services.ops.plan(OrderRequest(asset="retired_asset", priority=1), ENGINE)
    report = EngineLoop(services, clock, Pack.load(PACK)).run_once()
    assert report.admission.withheld == 1
    (gone,) = _orders(services, OrderState.WITHHELD)
    assert gone.reason == "asset-not-in-pack"


def test_a_router_needs_its_state_reader(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    with pytest.raises(ValueError):
        Controller(Pack.load(PACK), services.ops, clock, router=LaneRouter())


def test_freshness_fail_reports_subjects_never_or_long_ago_materialized(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    _repositories(services, 2)
    pack = _pack(tmp_path, repo_state={"freshness": {"fail": "72h"}, "admission": {}})
    loop = EngineLoop(services, clock, pack)
    assert loop.run_once().tick.overdue == {"repo_state": 2}
    _drain(services)
    assert loop.run_once().tick.overdue == {}
    clock.at += timedelta(hours=73)
    assert loop.run_once().tick.overdue == {"repo_state": 2}


def test_assets_sharing_a_quota_key_share_one_bucket(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    _repositories(services, 2)
    forge = {"admission": {"quota": {"key": "forge:{host}", "per_hour": 2}}}
    pack = _pack(
        tmp_path,
        dependency_graph={"deps": [], "trigger": {"every": "24h"}, **forge},
    )
    report = EngineLoop(services, clock, pack).run_once()
    assert (report.admission.admitted, report.admission.deferred) == (3, 2)  # feeds + 2 forge calls


def _manifest(ctx: Context, order: RunOrder) -> dict[str, Any]:
    assert order.artifact_id is not None
    publisher = ctx.artifact_publisher(PublishSpecs(PublishSpec(RunManifestArtifact)))
    return json.loads(publisher.get(order.artifact_id).payload)


def test_every_planned_order_records_the_pack_version(tmp_path: Path) -> None:
    clock = Clock()
    ctx = _context(tmp_path, clock)
    services = ctx.services()
    _repositories(services, 2)
    pack = Pack.load(PACK)
    EngineLoop(services, clock, pack).run_once()
    orders = _orders(services, OrderState.QUEUED, OrderState.PLANNED)
    assert len({o.artifact_id for o in orders}) == 1  # one shared manifest for the tick
    digest = hashlib.sha256(PACK.read_bytes()).hexdigest()
    assert pack.digest == digest
    assert _manifest(ctx, orders[0])["config"] == [{"name": "pack:security", "digest": digest}]


def test_admission_records_the_lane_verdict_and_deferred_orders_spend_nothing(
    tmp_path: Path,
) -> None:
    clock = Clock()
    budget = {"lane": "diff-scan", "monthly_usd": "3", "enforcement": "advisory"}
    ctx = _context(tmp_path, clock, budgets=[budget])
    services = ctx.services()
    first, second, third = _repositories(services, 3)
    for priority, repo in ((1, first), (2, second), (3, third)):
        services.ops.plan(
            OrderRequest(
                asset="diff_scan", priority=priority, repository_id=repo, lane="diff-scan"
            ),
            ENGINE,
        )
    pack = _pack(
        tmp_path, diff_scan={"admission": {"estimate_usd": "1.50", "pacing": {"per_tick": 1}}}
    )
    report = EngineLoop(services, clock, pack).run_once()
    assert report.admission.withheld == 0  # deferred orders didn't spend the lane budget
    scans = [o for o in _orders(services, OrderState.QUEUED) if o.asset == "diff_scan"]
    assert [o.repository_id for o in scans] == [first]
    assert _manifest(ctx, scans[0])["budget"] == {
        "lane": "diff-scan",
        "status": "within",
        "enforcement": "advisory",
        "spent_usd": "0",
        "estimate_usd": "1.50",
        "budget_usd": "3",
    }


def test_a_disabled_asset_is_not_planned_or_reported(tmp_path: Path) -> None:
    raw = yaml.safe_load(PACK.read_text())
    raw["assets"]["repo_state"] |= {
        "enabled": False,
        "freshness": {"fail": "48h"},
        "requires": {"facts": ["sla-policy"]},
    }
    raw.pop("route_on")
    raw["assets"]["dependency_graph"]["enabled"] = False
    raw["assets"]["diff_scan"]["enabled"] = False
    path = tmp_path / "assets.yaml"
    path.write_text(yaml.safe_dump(raw))
    clock = Clock()
    services = _context(tmp_path, clock).services()
    repos = _repositories(services, 2)

    report = Controller(Pack.load(path), services.ops, clock).tick(repos)

    assert report.planned == 1  # feeds_cache only
    assert "repo_state" not in report.overdue
    assert _by_asset(_orders(services, OrderState.PLANNED)) == {"feeds_cache": 1}


def test_the_run_manifest_names_the_toolchain_pins_next_to_the_pack(tmp_path: Path) -> None:
    pins = tmp_path / "external-tools.yaml"
    pins.write_text("tools: {grype: {version: 0.104.0}}\n")
    clock = Clock()
    ctx = _context(tmp_path, clock)
    services = ctx.services()
    _repositories(services, 1)
    EngineLoop(services, clock, Pack.load(PACK, pins)).run_once()
    [order, *_] = _orders(services, OrderState.QUEUED, OrderState.PLANNED)
    assert _manifest(ctx, order)["config"] == [
        {"name": "pack:security", "digest": hashlib.sha256(PACK.read_bytes()).hexdigest()},
        {"name": "external-tools", "digest": hashlib.sha256(pins.read_bytes()).hexdigest()},
    ]


def _runs(services: Services, asset: str, repository_id: UUID | None = None) -> None:
    """A run beside the engine (cron, by hand): submitted, claimed and completed."""
    services.ops.submit(OrderRequest(asset=asset, priority=1, repository_id=repository_id), ENGINE)
    _drain(services)


def _requests(report: Any) -> list[tuple[str, UUID | None]]:
    return sorted(((r.asset, r.repository_id) for r in report.due), key=str)


def test_a_shadow_pass_lists_what_a_pass_would_plan_and_writes_nothing(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    repos = _repositories(services, 3)
    shadow = EngineLoop(services, clock, Pack.load(PACK)).shadow_once()

    assert _requests(shadow) == sorted(
        [("feeds_cache", None), *(("repo_state", r) for r in repos)], key=str
    )
    assert shadow.tick.planned == 4 and shadow.tick.stale == {"dependency_graph": 3}
    assert _orders(services, *OrderState) == []
    live = EngineLoop(services, clock, Pack.load(PACK)).run_once()
    assert live.tick == shadow.tick


def test_a_shadow_pass_counts_runs_made_beside_it(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    (repo,) = _repositories(services, 1)
    loop = EngineLoop(services, clock, Pack.load(PACK))
    _runs(services, "feeds_cache")
    _runs(services, "repo_state", repo)
    clock.at += timedelta(minutes=1)

    shadow = loop.shadow_once()
    assert _requests(shadow) == [("dependency_graph", repo)]
    clock.at += timedelta(hours=24)
    assert ("feeds_cache", None) in _requests(loop.shadow_once())  # due again after its cadence


def test_a_shadow_pass_lists_routed_orders_once_per_materialization(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    (repo,) = _repositories(services, 1)
    router = LaneRouter()
    loop = EngineLoop(services, clock, Pack.load(PACK), router, state_of=lambda r: r)
    _runs(services, "repo_state", repo)
    clock.at += timedelta(minutes=1)

    (routed,) = [r for r in loop.shadow_once().due if r.asset == "diff_scan"]
    assert (routed.repository_id, routed.lane, routed.rule) == (repo, "diff-scan", "rule-4")
    assert _orders(services, OrderState.PLANNED) == []
    clock.at += timedelta(minutes=1)
    assert all(r.asset != "diff_scan" for r in loop.shadow_once().due)


class RefusalRouter:
    """Routes every repository to `lane`, or to `instead` when it was refused; keeps the
    refusals it was given."""

    def __init__(self, lane: str = "diff-scan", instead: str | None = None) -> None:
        self.lane, self.instead = lane, instead
        self.refusals: list[Refusal] = []

    def route(self, state: UUID, events: object, refusals: Sequence[Refusal]) -> tuple[Route, ...]:
        self.refusals += refusals
        lane = self.instead if refusals and self.instead else self.lane
        return (Route(lane=lane, priority=1, reason="rule-4"),)  # type: ignore[arg-type]


def _scans(services: Services, *states: OrderState) -> list[RunOrder]:
    return [o for o in _orders(services, *states) if o.asset == "diff_scan"]


def _refuse_the_scan(services: Services) -> RunOrder:
    """Routed and admitted, the repository's scan is refused (everything else succeeds)."""
    (scan,) = _scans(services, OrderState.QUEUED)
    assert scan.id is not None
    services.ops.start(
        OrderRequest(asset="diff_scan", priority=1, repository_id=scan.repository_id),
        ENGINE,
        WORKER,
        LEASE,
    )
    services.ops.complete(scan.id, WORKER, JobResult.refused("diff-too-large"))
    _drain(services)
    return scan


def _routed_loop(tmp_path: Path, router: RefusalRouter) -> tuple[Services, Clock, EngineLoop]:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    _repositories(services, 1)
    loop = EngineLoop(services, clock, Pack.load(PACK), router, state_of=lambda r: r)
    loop.run_once()
    clock.at += timedelta(minutes=10)
    _drain(services)
    assert loop.run_once().tick.routed == 1
    return services, clock, loop


def test_a_refused_repository_is_re_routed_with_its_refusal_and_never_loops(
    tmp_path: Path,
) -> None:
    router = RefusalRouter()
    services, _, loop = _routed_loop(tmp_path, router)
    scan = _refuse_the_scan(services)

    again = loop.run_once().tick
    assert (again.routed, again.refused_again) == (1, 1)
    assert router.refusals == [
        Refusal(subject=str(scan.repository_id), lane="diff-scan", reason="diff-too-large")  # type: ignore[arg-type]
    ]
    assert _scans(services, *OPEN_ORDER_STATES) == []
    assert loop.run_once().tick.routed == 0  # no loop: nothing new since

    _materialize(services, "repo_state", scan.repository_id)
    assert loop.run_once().tick.routed == 1
    (planned,) = _scans(services, *OPEN_ORDER_STATES)
    assert planned.lane == "diff-scan"


def test_a_refusal_routed_into_another_lane_is_planned(tmp_path: Path) -> None:
    router = RefusalRouter(instead="diff-scan-quarterly")
    services, _, loop = _routed_loop(tmp_path, router)
    _refuse_the_scan(services)
    assert loop.run_once().tick.refused_again == 0
    (planned,) = _scans(services, *OPEN_ORDER_STATES)
    assert planned.lane == "diff-scan-quarterly"


def test_a_restart_resumes_routing_after_the_last_routed_order(tmp_path: Path) -> None:
    router = RefusalRouter()
    services, clock, _ = _routed_loop(tmp_path, router)
    restarted = EngineLoop(services, clock, Pack.load(PACK), router, state_of=lambda r: r)
    assert restarted.run_once().tick.routed == 0


def test_a_restart_with_nothing_routed_looks_back_one_cadence(tmp_path: Path) -> None:
    router = RefusalRouter()
    clock = Clock()
    services = _context(tmp_path, clock).services()
    _repositories(services, 2)
    EngineLoop(services, clock, Pack.load(PACK)).run_once()
    clock.at += timedelta(minutes=10)
    _drain(services)
    restarted = EngineLoop(services, clock, Pack.load(PACK), router, state_of=lambda r: r)
    assert restarted.run_once().tick.routed == 2


def test_a_router_needs_the_feed(tmp_path: Path) -> None:
    clock = Clock()
    services = _context(tmp_path, clock).services()
    with pytest.raises(ValueError):
        Controller(Pack.load(PACK), services.ops, clock, LaneRouter(), state_of=lambda r: r)


class ReleaseRouter:
    """Routes a repository to diff-scan-quarterly for each release it was given; keeps them."""

    def __init__(self) -> None:
        self.releases: dict[UUID, list[RecordedRelease]] = {}

    def route(
        self, state: UUID, events: Sequence[RecordedRelease], refusals: object
    ) -> tuple[Route, ...]:
        self.releases.setdefault(state, []).extend(events)
        lane = "diff-scan-quarterly" if events else None
        return (Route(lane=lane, priority=1, reason="release"),)  # type: ignore[arg-type]


def _release(services: Services, version: str, *repositories: UUID) -> RecordedRelease:
    product = services.portfolio.find_product(ProductSlug("ocp")) or (
        services.portfolio.register_product(ProductSlug("ocp"), "OCP")
    )
    commits = [
        ReleaseCommit(
            url=HttpsRepoUrl.parse(services.portfolio.get_repository(r).url, ["github.com"]),
            sha=GitSha("a" * 40),
        )
        for r in repositories
    ]
    release = services.portfolio.import_release(product.id, VersionLabel(version), commits)  # type: ignore[arg-type]
    return services.portfolio.recorded_release(release.id)  # type: ignore[arg-type]


def test_a_recorded_release_routes_each_repository_it_ships_once(tmp_path: Path) -> None:
    router = ReleaseRouter()
    clock = Clock()
    services = _context(tmp_path, clock).services()
    shipped, other, left_out = _repositories(services, 3)
    loop = EngineLoop(services, clock, Pack.load(PACK), router, state_of=lambda r: r)
    first = _release(services, "4.19", shipped, other)
    clock.at += timedelta(minutes=10)
    assert loop.run_once().tick.routed == 2
    assert router.releases == {shipped: [first], other: [first]}
    assert first.change is None
    planned = _scans(services, *OPEN_ORDER_STATES)
    assert sorted((o.repository_id, o.lane, o.rule) for o in planned) == sorted(
        (r, "diff-scan-quarterly", "release") for r in (shipped, other)
    )

    router.releases.clear()
    assert loop.run_once().tick.routed == 0
    second = _release(services, "4.20", shipped)
    assert loop.run_once().tick.routed == 1
    assert router.releases == {shipped: [second]}
    assert second.change is not None and second.change.remodels()
    assert left_out not in router.releases


def test_a_restart_does_not_replay_releases_routed_before_it(tmp_path: Path) -> None:
    router = ReleaseRouter()
    clock = Clock()
    services = _context(tmp_path, clock).services()
    (repo,) = _repositories(services, 1)
    _release(services, "4.19", repo)
    assert EngineLoop(services, clock, Pack.load(PACK), router, lambda r: r).run_once().tick.routed
    router.releases.clear()
    restarted = EngineLoop(services, clock, Pack.load(PACK), router, state_of=lambda r: r)
    assert restarted.run_once().tick.routed == 0 and router.releases == {}


def test_a_corrected_router_retry_reads_the_events_it_failed_on(tmp_path: Path) -> None:
    """The failed pass puts the feed cursor back, so a corrected router on the same loop
    routes the repositories the failed pass read (it does not skip past their events)."""
    clock = Clock()
    services = _context(tmp_path, clock).services()
    _repositories(services, 1)
    loop = EngineLoop(
        services, clock, Pack.load(PACK), TableAndAdditiveRouter(), state_of=lambda r: r
    )
    loop.run_once()
    clock.at += timedelta(minutes=10)
    _drain(services)
    with pytest.raises(ConfigError, match="runs no asset for lane"):
        loop.run_once()
    loop._controller._router = LaneRouter(frozenset())
    report = loop.run_once()
    assert report.tick.routed == 1
    assert _routed_orders(services)
