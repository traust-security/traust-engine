"""The claim-once runner over real traust-core services on SQLite: it leases only the pack's
command assets, fills `{param}` tokens from the order, keeps the lease alive while the command
runs and completes the order as the command answered."""

from __future__ import annotations

import contextlib
import io
import json
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
import yaml
from traust_core.v1.context import Config, Context
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.operations import (
    JobResult,
    LaneName,
    ModelName,
    ModelUsage,
    OrderRequest,
    OrderState,
    ProviderName,
    RunOrder,
    SkillName,
    WorkerId,
)
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.models.vocabulary import ActorKind
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork

from traust_engine.ops import cli
from traust_engine.ops.pack import Pack
from traust_engine.ops.runner import Runner, UnresolvedParam, argv, runnable

PACK = Path(__file__).parent / "fixtures" / "packs" / "security-source.yaml"
WORKER = WorkerId("runner-1")
OPERATOR = Principal(identity="op@example.com", kind=ActorKind.HUMAN, display="op")
HOSTS = ("github.com",)


class Commands:
    """Stands in for subprocess: records each argv and answers as told."""

    def __init__(self, stdout: str = "", code: int = 0, delay: float = 0) -> None:
        self.stdout, self.code, self.delay = stdout, code, delay
        self.seen: list[list[str]] = []

    def __call__(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        self.seen.append(command)
        time.sleep(self.delay)
        return subprocess.CompletedProcess(command, self.code, self.stdout, "")


@pytest.fixture
def context(tmp_path: Path) -> Context:
    return Context(Config(home=tmp_path / "home"))


def _submit(
    context: Context, asset: str, priority: int = 1, repo: bool = False, rule: str | None = None
) -> RunOrder:
    services = context.services()
    repository_id = None
    if repo:
        url = HttpsRepoUrl.parse("https://github.com/example/app", HOSTS)
        repository_id = services.portfolio.register_repository(url, public=True).id
    request = OrderRequest(asset=asset, priority=priority, repository_id=repository_id, rule=rule)
    return services.ops.submit(request, OPERATOR)


def _runner(
    context: Context,
    commands: Commands,
    lease: timedelta = timedelta(minutes=5),
    worker: WorkerId = WORKER,
) -> Runner:
    return Runner(context.services(), Pack.load(PACK), worker, lease, HOSTS, run=commands)


def test_only_command_assets_are_runnable() -> None:
    pack = Pack.load(PACK)
    assert set(runnable(pack)) == {"feeds_cache", "repo_state", "diff_scan"}
    assert "dependency_graph" not in runnable(pack)  # a skill session: a launcher's job


@pytest.mark.parametrize(
    ("stdout", "code", "state", "reason"),
    [
        (JobResult.succeeded().model_dump_json(), 0, OrderState.SUCCEEDED, None),
        (JobResult.partly({"unreachable": 1}).model_dump_json(), 4, OrderState.DEGRADED, None),
        (
            "log line\n" + JobResult.refused("not_found").model_dump_json(),
            5,
            OrderState.REFUSED,
            "not_found",
        ),
        ("plain output", 0, OrderState.SUCCEEDED, None),
        ("", 3, OrderState.FAILED, "runner-crashed"),
    ],
    ids=["succeeded", "degraded", "refused", "plain", "plain failure"],
)
def test_a_claimed_order_is_completed_as_its_command_answered(
    context: Context, stdout: str, code: int, state: OrderState, reason: str | None
) -> None:
    queued = _submit(context, "feeds_cache")
    commands = Commands(stdout, code)
    done = _runner(context, commands).claim_once()
    assert done is not None and done.id == queued.id
    assert (done.state, done.reason, done.lease_holder) == (state, reason, None)
    assert commands.seen == [["python3", "-m", "traust.cli", "feeds", "fetch", "--feed", "all"]]


def test_a_repository_asset_gets_its_url(context: Context) -> None:
    _submit(context, "repo_state", repo=True)
    commands = Commands()
    _runner(context, commands).claim_once()
    assert commands.seen[0][-2:] == ["--repo", "https://github.com/example/app"]


def _with_rule_token(tmp_path: Path) -> Path:
    raw = yaml.safe_load(PACK.read_text())
    raw["assets"]["diff_scan"]["run"] = ["scan", "{repo_url}", "--rule", "{rule}"]
    path = tmp_path / "pack.yaml"
    path.write_text(yaml.safe_dump(raw))
    return path


def test_a_routed_order_gets_the_rule_that_routed_it(context: Context, tmp_path: Path) -> None:
    _submit(context, "diff_scan", repo=True, rule="rule-3+threat-model-pr")
    commands = Commands()
    runner = Runner(
        context.services(),
        Pack.load(_with_rule_token(tmp_path)),
        WORKER,
        timedelta(minutes=5),
        HOSTS,
        commands,
    )
    done = runner.claim_once()
    assert done is not None and done.state == OrderState.SUCCEEDED
    assert commands.seen == [
        ["scan", "https://github.com/example/app", "--rule", "rule-3+threat-model-pr"]
    ]


def test_an_order_with_no_rule_cannot_fill_a_rule_token(context: Context, tmp_path: Path) -> None:
    _submit(context, "diff_scan", repo=True)
    commands = Commands()
    runner = Runner(
        context.services(),
        Pack.load(_with_rule_token(tmp_path)),
        WORKER,
        timedelta(minutes=5),
        HOSTS,
        commands,
    )
    done = runner.claim_once()
    assert done is not None and done.state == OrderState.FAILED
    assert done.reason == "bad_request" and commands.seen == []


def test_a_skill_session_order_is_left_for_its_launcher(context: Context) -> None:
    session = _submit(context, "dependency_graph", priority=0)
    commands = Commands()
    assert _runner(context, commands).claim_once() is None
    assert commands.seen == []
    assert context.services().ops.get(session.id).state == OrderState.QUEUED  # type: ignore[arg-type]


def test_nothing_queued_claims_nothing(context: Context) -> None:
    assert _runner(context, Commands()).claim_once() is None


def test_a_param_the_order_cannot_supply_fails_without_running(context: Context) -> None:
    pack = yaml.safe_load(PACK.read_text())
    pack["assets"]["feeds_cache"]["run"] = ["fetch", "{sha}"]
    spec = Pack.model_validate(pack).assets["feeds_cache"]
    with pytest.raises(UnresolvedParam, match="sha"):
        argv(spec, {"run_id": "x"})


def test_a_token_is_replaced_whole_never_inside_text() -> None:
    raw = yaml.safe_load(PACK.read_text())
    raw["assets"]["feeds_cache"]["run"] = ["echo", "--repo={repo_url}", "{repo_url}", "{run_id}"]
    spec = Pack.model_validate(raw).assets["feeds_cache"]
    got = argv(spec, {"repo_url": "https://github.com/example/app", "run_id": "42"})
    assert got == ["echo", "--repo={repo_url}", "https://github.com/example/app", "42"]


def test_an_unresolved_param_fails_the_order(context: Context, tmp_path: Path) -> None:
    raw = yaml.safe_load(PACK.read_text())
    raw["assets"]["feeds_cache"]["run"] = ["fetch", "{sha}"]
    path = tmp_path / "pack.yaml"
    path.write_text(yaml.safe_dump(raw))
    _submit(context, "feeds_cache")
    commands = Commands()
    runner = Runner(
        context.services(), Pack.load(path), WORKER, timedelta(minutes=5), HOSTS, commands
    )
    done = runner.claim_once()
    assert done is not None and done.state == OrderState.FAILED
    assert done.reason == "bad_request" and commands.seen == []


def test_a_command_that_cannot_start_fails_the_order(context: Context) -> None:
    _submit(context, "feeds_cache")

    def missing(command: list[str]) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError(command[0])

    runner = Runner(
        context.services(), Pack.load(PACK), WORKER, timedelta(minutes=5), HOSTS, missing
    )
    done = runner.claim_once()
    assert done is not None and done.state == OrderState.FAILED
    assert done.reason == "runner-crashed"


def test_the_lease_is_renewed_while_the_command_runs(context: Context) -> None:
    queued = _submit(context, "feeds_cache")
    beats: list[Any] = []
    services = context.services()
    real = services.ops.heartbeat

    def heartbeat(*args: Any) -> RunOrder:
        beats.append(args)
        return real(*args)

    services.ops.heartbeat = heartbeat  # type: ignore[method-assign]
    runner = Runner(
        services, Pack.load(PACK), WORKER, timedelta(seconds=0.3), HOSTS, Commands(delay=0.5)
    )
    done = runner.claim_once()
    assert done is not None and done.state == OrderState.SUCCEEDED and done.id == queued.id
    assert beats and all(b[0] == queued.id and b[1] == WORKER for b in beats)


def test_claim_from_the_cli_runs_one_order_and_exits_with_its_outcome(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    core = tmp_path / "core.yaml"
    core.write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    _submit(Context.from_file(core), "feeds_cache")
    monkeypatch.setattr("traust_engine.ops.runner._run", Commands("", 1))

    def run(*extra: str) -> tuple[int, Any]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = cli.main(["claim", "--core", str(core), "--pack", str(PACK), *extra])
        return rc, json.loads(out.getvalue())

    rc, order = run("--worker", "w1")
    assert (rc, order["state"], order["reason"]) == (1, "failed", "runner-crashed")
    assert run() == (0, {"claimed": None})


def test_a_real_command_is_run_without_a_shell(context: Context) -> None:
    _submit(context, "feeds_cache")
    raw = yaml.safe_load(PACK.read_text())
    answer = JobResult.partly({"unreachable": 1}).model_dump_json()
    raw["assets"]["feeds_cache"]["run"] = [sys.executable, "-c", f"print({answer!r}); exit(4)"]
    runner = Runner(
        context.services(), Pack.model_validate(raw), WORKER, timedelta(minutes=5), HOSTS
    )
    done = runner.claim_once()
    assert done is not None and done.state == OrderState.DEGRADED


FEEDS = Path(__file__).parent / "fixtures" / "config" / "feeds.yaml"


def test_a_skill_session_with_a_command_runs_with_its_role(
    context: Context, tmp_path: Path
) -> None:
    raw = yaml.safe_load(PACK.read_text())
    raw["assets"]["dependency_graph"]["run"] = [
        "session",
        "--role",
        "{role}",
        "--repo",
        "{repo_url}",
    ]
    pack = Pack.model_validate(raw)
    assert "dependency_graph" in runnable(pack)
    _submit(context, "dependency_graph", priority=0, repo=True)
    commands = Commands()
    done = Runner(
        context.services(), pack, WORKER, timedelta(minutes=5), HOSTS, commands
    ).claim_once()
    assert done is not None and done.state == OrderState.SUCCEEDED
    assert commands.seen == [
        ["session", "--role", "dependency-graph", "--repo", "https://github.com/example/app"]
    ]


def test_a_feed_degraded_by_name_completes_once_the_pack_feeds_are_known(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    core = tmp_path / "core.yaml"
    core.write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    answer = JobResult.partly({"kev": 1}).model_dump_json()
    common = ["--core", str(core), "--pack", str(PACK)]

    def claim(*extra: str) -> tuple[int, Any]:
        _submit(Context.from_file(core), "feeds_cache")
        monkeypatch.setattr("traust_engine.ops.runner._run", Commands(answer, 4))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            return cli.main(["claim", *common, *extra]), out.getvalue()

    unknown, _ = claim()
    assert unknown == 2  # without the registry, core refuses the feed name as a degraded key
    rc, out = claim("--feeds", str(FEEDS))
    assert (rc, json.loads(out)["state"]) == (4, "degraded")


MODELS = Path(__file__).parent / "fixtures" / "config" / "model-registry.yaml"
SESSION = ModelUsage(
    provider=ProviderName("anthropic"),
    model=ModelName("claude-opus-5"),
    occurred_at=datetime(2026, 10, 27, tzinfo=UTC),
    tokens_in=10**6,
    tokens_out=0,
    skill=SkillName("vuln-scan"),
)


@pytest.mark.parametrize(
    ("models", "spend"),
    [(True, [("full-audit", "vuln-scan", Decimal(5))]), (False, [])],
    ids=["priced", "no registry: completed, the gap in its run manifest"],
)
def test_a_session_that_answers_its_usage_settles_it_as_the_orders_spend(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    models: bool,
    spend: list[tuple[str, str, Decimal]],
) -> None:
    core = tmp_path / "core.yaml"
    core.write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    request = OrderRequest(asset="feeds_cache", priority=1, lane=LaneName("full-audit"))
    queued = Context.from_file(core).services().ops.submit(request, OPERATOR)
    answer = JobResult.succeeded().model_copy(update={"usage": (SESSION,)}).model_dump_json()
    monkeypatch.setattr("traust_engine.ops.runner._run", Commands(f"session text\n{answer}"))
    argv = ["claim", "--core", str(core), "--pack", str(PACK)]
    with contextlib.redirect_stdout(io.StringIO()):
        assert cli.main([*argv, *(["--models", str(MODELS)] if models else [])]) == 0
    done = Context.from_file(core).services().ops.get(queued.id)
    assert done.state == OrderState.SUCCEEDED
    assert (done.artifact_id is None) is models  # `spend-unpriced` lands in the run manifest
    with Context.from_file(core).unit_of_work(SqlTraustUnitOfWork) as uow:
        events = uow.spend_events.list_for_order(queued.id)
    assert [(e.lane, e.skill, e.cost_usd) for e in events] == spend


def _repository(context: Context, path: str = "example/app") -> UUID:
    url = HttpsRepoUrl.parse(f"https://github.com/{path}", HOSTS)
    repository = context.services().portfolio.register_repository(url, public=True)
    assert repository.id is not None
    return repository.id


def _order(context: Context, asset: str, repository_id: UUID, priority: int) -> RunOrder:
    request = OrderRequest(asset=asset, priority=priority, repository_id=repository_id)
    return context.services().ops.submit(request, OPERATOR)


def _hold(
    context: Context, order: RunOrder, worker: str, lease_for: timedelta = timedelta(minutes=5)
) -> None:
    """Lease `order` to `worker` without running it, as a runner mid-command would have."""
    context.services().ops.start(
        OrderRequest(asset=order.asset, priority=order.priority, repository_id=order.repository_id),
        OPERATOR,
        WorkerId(worker),
        lease_for,
    )


@pytest.mark.parametrize(
    ("holder", "worker", "expected"),
    [
        (None, "b", ("repo_state", "app")),
        ("a", "a", ("diff_scan", "app")),
        ("a", "b", ("repo_state", "other")),
    ],
    ids=[
        "nobody holds it: the first claimer takes it",
        "the holder takes its repository's next order",
        "a runner without the mirror does not steal it",
    ],
)
def test_a_repositorys_orders_stick_to_the_runner_that_holds_it(
    context: Context, holder: str | None, worker: str, expected: tuple[str, str]
) -> None:
    app, other = _repository(context), _repository(context, "example/other")
    held = _order(context, "repo_state", app, priority=0)
    _order(context, "diff_scan", app, priority=1)
    _order(context, "repo_state", other, priority=2)
    if holder is not None:
        _hold(context, held, holder)
    done = _runner(context, Commands(), worker=WorkerId(worker)).claim_once()
    assert done is not None
    assert (done.asset, done.repository_id) == (
        expected[0],
        {"app": app, "other": other}[expected[1]],
    )


def test_every_order_of_a_held_repository_waits(context: Context) -> None:
    app = _repository(context)
    held = _order(context, "repo_state", app, priority=0)
    _order(context, "diff_scan", app, priority=1)
    _hold(context, held, "a")
    commands = Commands()
    assert _runner(context, commands, worker=WorkerId("b")).claim_once() is None
    assert commands.seen == []


def test_a_hold_from_an_asset_the_runner_does_not_make_still_waits(context: Context) -> None:
    """The hold is the repository's, not the asset's: another pack's leased order for it
    keeps this runner off its orders too (the mirror lives on the holder's node)."""
    app = _repository(context)
    held = _order(context, "dependency_graph", app, priority=0)  # not this runner's asset
    _order(context, "diff_scan", app, priority=1)
    _hold(context, held, "a")
    commands = Commands()
    assert _runner(context, commands, worker=WorkerId("b")).claim_once() is None
    assert commands.seen == []


@pytest.mark.parametrize(
    ("free", "expected"),
    [("complete", "diff_scan"), ("expire", "repo_state")],
    ids=["the holder's order completed", "the holder's lease expired"],
)
def test_freeing_the_hold_lets_other_runners_claim(
    context: Context, free: str, expected: str
) -> None:
    app = _repository(context)
    held = _order(context, "repo_state", app, priority=0)
    _order(context, "diff_scan", app, priority=1)
    _hold(
        context, held, "a", timedelta(minutes=5) if free == "complete" else timedelta(seconds=0.1)
    )
    if free == "complete":
        context.services().ops.complete(held.id, WorkerId("a"), JobResult.succeeded())
    else:
        time.sleep(0.3)  # the lease lapses; the claim sweep requeues it
    done = _runner(context, Commands(), worker=WorkerId("b")).claim_once()
    assert done is not None and done.asset == expected


def test_a_repositorys_orders_wait_while_their_holder_runs(context: Context) -> None:
    app = _repository(context)
    _order(context, "repo_state", app, priority=0)
    _order(context, "diff_scan", app, priority=1)
    running, gate = threading.Event(), threading.Event()

    def gated(command: list[str]) -> subprocess.CompletedProcess[str]:
        running.set()
        gate.wait()
        return subprocess.CompletedProcess(command, 0, JobResult.succeeded().model_dump_json(), "")

    holder = Runner(
        context.services(),
        Pack.load(PACK),
        WorkerId("a"),
        timedelta(minutes=5),
        HOSTS,
        gated,
    )
    thread = threading.Thread(target=holder.claim_once)
    thread.start()
    assert running.wait(5)  # the holder leased repo_state and started its command
    commands = Commands()
    assert _runner(context, commands, worker=WorkerId("b")).claim_once() is None
    assert commands.seen == []
    gate.set()
    thread.join(5)
    done = _runner(context, commands, worker=WorkerId("b")).claim_once()
    assert done is not None and done.asset == "diff_scan"


def test_a_pair_still_waiting_for_admission_is_not_taken_over(context: Context) -> None:
    """Reaching past a held repository must not lease a pair's planned order (its budget gate)
    when a later queued order shares the pair."""
    app, other = _repository(context), _repository(context, "example/other")
    held = _order(context, "repo_state", app, priority=0)
    _order(context, "diff_scan", app, priority=1)  # the top queued order: waits for the holder
    _hold(context, held, "a")
    planned = context.services().ops.plan(
        OrderRequest(asset="diff_scan", priority=1, repository_id=other), OPERATOR
    )
    _order(context, "diff_scan", other, priority=1)  # submit does not dedupe a planned pair
    commands = Commands()
    assert _runner(context, commands, worker=WorkerId("b")).claim_once() is None
    assert commands.seen == []
    assert context.services().ops.get(planned.id).state == OrderState.PLANNED
