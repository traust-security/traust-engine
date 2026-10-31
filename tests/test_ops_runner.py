"""The claim-once runner over real traust-core services on SQLite: it leases only the pack's
command assets, fills `{param}` tokens from the order, keeps the lease alive while the command
runs and completes the order as the command answered."""

from __future__ import annotations

import contextlib
import io
import json
import shutil
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

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
MODELS = Path(__file__).parent / "fixtures" / "config" / "model-registry.yaml"
WORKER = WorkerId("runner-1")
OPERATOR = Principal(identity="op@example.com", kind=ActorKind.HUMAN, display="op")
HOSTS = ("github.com",)


def _core(tmp_path: Path) -> Path:
    core = tmp_path / "core.yaml"
    core.write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    shutil.copytree(Path(__file__).parent / "fixtures" / "config", tmp_path, dirs_exist_ok=True)
    return core


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
    context: Context, commands: Commands, lease: timedelta = timedelta(minutes=5)
) -> Runner:
    return Runner(context.services(), Pack.load(PACK), WORKER, lease, HOSTS, run=commands)


def test_only_command_assets_are_runnable() -> None:
    pack = Pack.load(PACK)
    assert set(runnable(pack)) == {"feeds_cache", "repo_state", "diff_scan"}
    assert "dependency_graph" not in runnable(pack)  # a skill session: a launcher's job


def test_a_disabled_asset_is_not_claimable() -> None:
    raw = yaml.safe_load(PACK.read_text())
    raw["assets"]["diff_scan"]["enabled"] = False
    assert "diff_scan" not in runnable(Pack.model_validate(raw))


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
    core = _core(tmp_path)
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
    core = _core(tmp_path)
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
    core = _core(tmp_path)
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
