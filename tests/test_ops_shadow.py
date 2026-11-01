"""The shadow run: `traust-engine record` turns cron's jobs into orders, `traust-engine shadow`
prints what the engine would plan, and `traust-engine diff` compares the two (and an expected
routing). Comparisons are table tests; the commands run end to end on SQLite."""

from __future__ import annotations

import contextlib
import io
import json
import shutil
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
import yaml
from traust_core.v1.context import Context
from traust_core.v1.models.common import every_item
from traust_core.v1.models.operations import (
    JobResult,
    OrderFilter,
    OrderReason,
    OrderRequest,
    OrderState,
    Route,
    RunOrder,
)
from traust_core.v1.models.values import HttpsRepoUrl

from traust_engine.ops import cli
from traust_engine.ops.shadow import Tick, compare_routes, compare_runs, outcome

PACK = Path(__file__).parent / "fixtures" / "packs" / "security-source.yaml"
T0 = datetime(2026, 10, 1, 6, tzinfo=UTC)
DAY, HOUR = timedelta(days=1), timedelta(hours=1)
CADENCE = {"feeds_cache": DAY, "repo_state": DAY}
TOLERANCE = 2 * HOUR
REPO = uuid4()


def _tick(at: datetime, *due: tuple[str, UUID | None, str | None]) -> Tick:
    requests = (OrderRequest(asset=a, priority=1, repository_id=r, lane=lane) for a, r, lane in due)
    return Tick(at=at, due=tuple(requests))


def _run(asset: str, started: datetime, repository_id: UUID | None = None) -> RunOrder:
    return RunOrder(
        asset=asset,
        repository_id=repository_id,
        state=OrderState.SUCCEEDED,
        priority=1,
        requested_by="machine:record",
        started_at=started,
        finished_at=started + timedelta(minutes=5),
    )


@pytest.mark.parametrize(
    ("ticks", "runs", "want"),
    [
        pytest.param(
            [_tick(T0 + HOUR, ("feeds_cache", None, None))],
            [_run("feeds_cache", T0 + 3 * HOUR)],
            ([("feeds_cache", 2.0)], [], []),
            id="listed then run: matched, two hours late",
        ),
        pytest.param(
            [_tick(T0 + HOUR, ("feeds_cache", None, None))],
            [],
            ([], [("feeds_cache", T0 + HOUR)], []),
            id="listed and never run: missed",
        ),
        pytest.param(
            [_tick(T0 + DAY - HOUR, ("feeds_cache", None, None))],
            [],
            ([], [], []),
            id="listed within the tolerance of the window's end: not missed yet",
        ),
        pytest.param(
            [],
            [_run("feeds_cache", T0 - 2 * HOUR), _run("feeds_cache", T0 + HOUR)],
            ([], [], [("feeds_cache", 21.08)]),
            id="run long before its cadence fell due: early",
        ),
        pytest.param(
            [],
            [
                _run("feeds_cache", T0 - DAY + HOUR),
                _run("feeds_cache", T0 + HOUR - timedelta(minutes=30)),
            ],
            ([("feeds_cache", -0.58)], [], []),
            id="run just before its cadence fell due: matched",
        ),
        pytest.param(
            [],
            [_run("feeds_cache", T0 + HOUR)],
            ([], [], [("feeds_cache", None)]),
            id="run with no history and nothing listed: early, cadence unknown",
        ),
        pytest.param(
            [_tick(T0 + HOUR, ("diff_scan", REPO, "diff-scan"))],
            [],
            ([], [], []),
            id="routed orders are compared by route, not by run",
        ),
        pytest.param(
            [_tick(T0 + HOUR, ("repo_state", REPO, None))],
            [_run("repo_state", T0 + 3 * HOUR, REPO), _run("repo_state", T0 + 3 * HOUR)],
            ([("repo_state", 2.0)], [], [("repo_state", None)]),
            id="subjects are compared apart",
        ),
        pytest.param(
            [_tick(T0 - 2 * HOUR, ("feeds_cache", None, None))],
            [_run("feeds_cache", T0 - HOUR)],
            ([], [], []),
            id="a run before the window is never reported",
        ),
    ],
)
def test_compare_runs(ticks: list[Tick], runs: list[RunOrder], want: Any) -> None:
    matched, missed, early = compare_runs(ticks, runs, CADENCE, TOLERANCE, T0, T0 + DAY)
    got = (
        [(m.asset, m.late_by_hours) for m in matched],
        [(m.asset, m.due_since) for m in missed],
        [(e.asset, e.due_in_hours) for e in early],
    )
    assert got == want


URLS = {REPO: "https://github.com/org/app", uuid4(): "https://github.com/org/lib"}
LANES = ("diff-scan", "full-audit")


@pytest.mark.parametrize(
    ("engine", "expected", "same", "different"),
    [
        pytest.param("diff-scan", "diff-scan", 1, [], id="same lane"),
        pytest.param("full-audit", "diff-scan", 0, [("full-audit", "diff-scan")], id="other lane"),
        pytest.param(None, "full-audit", 0, [(None, "full-audit")], id="expected only"),
        pytest.param("full-audit", "none", 0, [("full-audit", None)], id="engine only"),
        pytest.param(None, "deps-lane", 0, [], id="a lane no asset runs is no lane"),
    ],
)
def test_compare_routes(
    engine: str | None, expected: str, same: int, different: list[tuple[str | None, ...]]
) -> None:
    ticks = [_tick(T0, ("x", REPO, engine))] if engine else []
    rows = [
        {"repo_url": URLS[REPO], "lane": expected},
        {"repo_url": "https://github.com/org/unknown", "lane": "full-audit"},
    ]
    got_same, got = compare_routes(ticks, rows, URLS, LANES)
    assert (got_same, [(d.engine, d.expected) for d in got]) == (same, different)


def test_the_latest_route_of_a_repository_counts() -> None:
    ticks = [_tick(T0 + HOUR, ("x", REPO, "diff-scan")), _tick(T0, ("x", REPO, "full-audit"))]
    rows = [{"repo_url": URLS[REPO], "lane": "diff-scan"}]
    assert compare_routes(ticks, rows, URLS, LANES) == (1, [])


def _done(code: int, stdout: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(["x"], code, stdout, "")


@pytest.mark.parametrize(
    ("done", "want"),
    [
        (_done(4, JobResult.partly({"kev": 1}).model_dump_json()), JobResult.partly({"kev": 1})),
        (
            _done(5, "log\n" + JobResult.refused(OrderReason.NOT_FOUND).model_dump_json()),
            JobResult.refused(OrderReason.NOT_FOUND),
        ),
        (_done(0, "done"), JobResult.succeeded()),
        (_done(0), JobResult.succeeded()),
        (_done(3, "{not json"), JobResult.failed(OrderReason.RUNNER_CRASHED)),
        (_done(1), JobResult.failed(OrderReason.RUNNER_CRASHED)),
    ],
    ids=["degraded answer", "refused answer", "plain output", "silent", "garbled", "plain failure"],
)
def test_outcome(done: subprocess.CompletedProcess[str], want: JobResult) -> None:
    assert outcome(done) == want


class EveryRepoToDiffScan:
    def route(self, state: object, events: object, refusals: object) -> tuple[Route, ...]:
        return (Route(lane="diff-scan", priority=1, reason="rule-5"),)  # type: ignore[arg-type]


@pytest.fixture
def core(tmp_path: Path) -> Path:
    path = tmp_path / "core.yaml"
    path.write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    shutil.copytree(Path(__file__).parent / "fixtures" / "config", tmp_path, dirs_exist_ok=True)
    return path


def _cli(core: Path, op: str, *argv: str, pack: Path = PACK) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = cli.main([op, "--core", str(core), "--pack", str(pack), *argv])
    return rc, out.getvalue()


def _unrouted_pack(tmp_path: Path) -> Path:
    """The fixture pack without route_on: a deployment that does not route starts with no
    --router."""
    raw = yaml.safe_load(PACK.read_text())
    del raw["route_on"]
    path = tmp_path / "assets.yaml"
    path.write_text(yaml.safe_dump(raw))
    return path


def _orders(core: Path) -> list[RunOrder]:
    ops = Context.from_file(core).services().ops
    return list(every_item(lambda p: ops.list(OrderFilter(states=tuple(OrderState)), p)))


def _repository(core: Path) -> tuple[UUID, str]:
    url = HttpsRepoUrl.parse("https://github.com/org/app", ["github.com"])
    repo = Context.from_file(core).services().portfolio.register_repository(url, False)
    assert repo.id is not None
    return repo.id, str(url)


def _python(code: str) -> list[str]:
    return ["--", sys.executable, "-c", code]


def test_record_runs_the_command_as_an_order_and_exits_with_it(core: Path) -> None:
    answer = JobResult.partly({"unreachable": 1}).model_dump_json()
    rc, out = _cli(core, "record", "feeds_cache", *_python(f"print({answer!r}); exit(4)"))
    (order,) = _orders(core)
    assert (rc, out.strip()) == (4, answer)
    assert (order.asset, order.state, order.repository_id) == ("feeds_cache", "degraded", None)
    assert order.requested_by.startswith("machine:record:")


def test_record_a_refused_answer_leaves_the_order_refused_with_its_reason(core: Path) -> None:
    answer = JobResult.refused(OrderReason.LEDGER_UNCONFIGURED).model_dump_json()
    rc, _ = _cli(core, "record", "feeds_cache", *_python(f"print({answer!r}); exit(5)"))
    (order,) = _orders(core)
    assert (rc, order.state, order.reason) == (5, "refused", OrderReason.LEDGER_UNCONFIGURED)


def test_record_a_repository_asset_by_its_url(core: Path) -> None:
    repository_id, url = _repository(core)
    rc, _ = _cli(core, "record", "repo_state", "--repo", url, *_python("pass"))
    (order,) = _orders(core)
    assert (rc, order.repository_id, order.state) == (0, repository_id, "succeeded")


@pytest.mark.parametrize(
    "argv",
    [
        ["no_such_asset", *_python("pass")],
        ["repo_state", *_python("pass")],
        ["feeds_cache", "--repo", "https://github.com/org/app", *_python("pass")],
        ["feeds_cache", "--"],
        ["repo_state", "--repo", "https://github.com/org/app", *_python("pass")],
    ],
    ids=[
        "unknown asset",
        "per-repository asset without --repo",
        "fleet asset with --repo",
        "no command",
        "repository outside the inventory",
    ],
)
def test_record_refuses_a_malformed_request(core: Path, argv: list[str]) -> None:
    assert _cli(core, "record", *argv)[0] == 2
    assert _orders(core) == []


def test_a_command_that_cannot_start_fails_its_order(core: Path) -> None:
    rc, _ = _cli(core, "record", "feeds_cache", "--", "/no/such/command")
    (order,) = _orders(core)
    assert (rc, order.state) == (2, "failed")


def test_shadow_prints_what_a_pass_would_plan_and_diff_compares_it(
    core: Path, tmp_path: Path
) -> None:
    rc, line = _cli(core, "shadow", "--once", pack=_unrouted_pack(tmp_path))
    tick = Tick.model_validate_json(line)
    assert rc == 0 and _orders(core) == []
    assert [d.asset for d in tick.due] == ["feeds_cache"]

    _cli(core, "record", "feeds_cache", *_python("pass"))
    shadow = tmp_path / "shadow.jsonl"
    shadow.write_text(line)
    rc, out = _cli(core, "diff", "--shadow", str(shadow))
    report = json.loads(out)
    assert [m["asset"] for m in report["matched"]] == ["feeds_cache"]
    assert (rc, report["missed"], report["early"]) == (0, [], [])


def test_shadow_routes_with_the_pack_router(core: Path) -> None:
    repository_id, url = _repository(core)
    _cli(core, "record", "repo_state", "--repo", url, *_python("pass"))
    rc, line = _cli(core, "shadow", "--once", "--router", f"{__name__}:EveryRepoToDiffScan")
    (routed,) = [d for d in Tick.model_validate_json(line).due if d.lane]
    assert (rc, routed.asset, routed.repository_id) == (0, "diff_scan", repository_id)


def test_diff_exits_1_on_a_difference_and_compares_the_routes(core: Path, tmp_path: Path) -> None:
    repository_id, url = _repository(core)
    at = datetime.now(UTC) - 3 * HOUR
    tick = _tick(at, ("feeds_cache", None, None), ("diff_scan", repository_id, "diff-scan"))
    shadow = tmp_path / "shadow.jsonl"
    shadow.write_text(tick.model_dump_json())
    routes = tmp_path / "worklist.json"
    routes.write_text(json.dumps({"decisions": [{"repo_url": url, "lane": "full-audit"}]}))
    rc, out = _cli(core, "diff", "--shadow", str(shadow), "--routes", str(routes))
    report = json.loads(out)
    assert rc == 1
    assert [m["asset"] for m in report["missed"]] == ["feeds_cache"]
    assert report["routes_different"] == [
        {"repository_id": str(repository_id), "url": url, "engine": "diff-scan", "expected": None}
    ]


def test_diff_ignores_expected_routes_to_a_disabled_assets_lane(core: Path, tmp_path: Path) -> None:
    _, url = _repository(core)
    raw = yaml.safe_load(PACK.read_text())
    raw["assets"]["diff_scan"]["enabled"] = False
    pack = tmp_path / "assets.yaml"
    pack.write_text(yaml.safe_dump(raw))
    shadow = tmp_path / "shadow.jsonl"
    shadow.write_text(_tick(datetime.now(UTC) - 3 * HOUR).model_dump_json())
    routes = tmp_path / "worklist.json"
    routes.write_text(json.dumps({"decisions": [{"repo_url": url, "lane": "diff-scan"}]}))

    rc, out = _cli(core, "diff", "--shadow", str(shadow), "--routes", str(routes), pack=pack)

    assert rc == 0 and json.loads(out)["routes_different"] == []


def test_a_router_that_cannot_be_imported_is_a_config_error(core: Path) -> None:
    assert _cli(core, "shadow", "--once", "--router", "no.such.module:Router")[0] == 2


def test_run_once_plans_and_admits(core: Path, tmp_path: Path) -> None:
    rc, out = _cli(core, "run", "--once", pack=_unrouted_pack(tmp_path))
    assert rc == 0 and json.loads(out)["tick"]["planned"] == 1
    assert [o.asset for o in _orders(core)] == ["feeds_cache"]
