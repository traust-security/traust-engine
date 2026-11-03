"""Claimed and manually recorded runs share completion, not lease policy."""

from __future__ import annotations

import json
import subprocess
from datetime import timedelta
from pathlib import Path

import pytest
from traust_core.v1.context import Config, Context, LoggingConfig, Services, correlation_scope
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.operations import JobResult, OrderRequest, OrderState, RunOrder, WorkerId
from traust_core.v1.models.vocabulary import ActorKind

from traust_engine.ops.pack import Pack
from traust_engine.ops.runner import Runner
from traust_engine.ops.shadow import record

SECRET = "synthetic-secret-never-log"
WORKER = WorkerId("completion-test")
OPERATOR = Principal(identity="operator@example.test", kind=ActorKind.HUMAN, display="operator")
PACK = Pack.model_validate(
    {"pack": "completion-test", "assets": {"feeds_cache": {"run": ["fixture-command"]}}}
)


@pytest.fixture
def context(tmp_path: Path) -> Context:
    core = Context(
        Config(
            home=tmp_path / "store",
            logging=LoggingConfig(file=tmp_path / "execution.jsonl", outputs=("file",)),
        )
    )
    core.register_feeds(Path(__file__).parent / "fixtures" / "config" / "feeds.yaml")
    core.configure_logging("traust_engine")
    return core


def _execute(
    mode: str, services: Services, result: JobResult, code: int, monkeypatch: pytest.MonkeyPatch
) -> RunOrder:
    done = subprocess.CompletedProcess(
        ["fixture-command"], code, f"{SECRET}\n{result.model_dump_json()}", SECRET
    )
    request = OrderRequest(asset="feeds_cache", priority=1)
    if mode == "claim":
        services.ops.submit(request, OPERATOR)
        completed = Runner(
            services, PACK, WORKER, timedelta(minutes=5), (), run=lambda _: done
        ).claim_once()
        assert completed is not None
        return completed
    monkeypatch.setattr("traust_engine.ops.shadow.subprocess.run", lambda *a, **kw: done)
    return record(services, request, OPERATOR, WORKER, ["fixture-command"])[0]


def _executions(tmp_path: Path) -> list[dict]:
    rows = [json.loads(line) for line in (tmp_path / "execution.jsonl").read_text().splitlines()]
    return [row for row in rows if row.get("operation") == "engine.execution"]


@pytest.mark.parametrize("mode", ["claim", "record"])
@pytest.mark.parametrize(
    ("result", "code", "state", "reason"),
    [
        (JobResult.succeeded(), 0, OrderState.SUCCEEDED, None),
        (JobResult.partly({"epss": 1}), 4, OrderState.DEGRADED, None),
        (JobResult.refused("not_found"), 5, OrderState.REFUSED, "not_found"),
        (JobResult.failed("runner-crashed"), 9, OrderState.FAILED, "runner-crashed"),
    ],
    ids=["succeeded", "degraded", "refused", "failed"],
)
def test_completion_keeps_state_and_one_bounded_correlated_event(
    context: Context,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    result: JobResult,
    code: int,
    state: OrderState,
    reason: str | None,
) -> None:
    with correlation_scope("completion-request", actor_kind=ActorKind.MACHINE):
        completed = _execute(mode, context.services(), result, code, monkeypatch)
    assert (completed.state, completed.reason, completed.lease_holder) == (state, reason, None)
    [event] = _executions(tmp_path)
    assert (event["outcome"], event["status"], event["reason"], event["returncode"]) == (
        state,
        state,
        reason,
        code,
    )
    assert event["request_id"] == "completion-request"
    assert event["order_id"] == event["run_id"] == str(completed.id)
    assert event["level"] == ("INFO" if state == OrderState.SUCCEEDED else "WARNING")
    assert SECRET not in (tmp_path / "execution.jsonl").read_text()


@pytest.mark.parametrize("mode", ["claim", "record"])
def test_completion_rejection_propagates_without_a_success_event(
    context: Context, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    with (
        correlation_scope("rejected-completion", actor_kind=ActorKind.MACHINE),
        pytest.raises(ValidationError),
    ):
        _execute(mode, context.services(), JobResult.partly({SECRET: 1}), 4, monkeypatch)
    [event] = _executions(tmp_path)
    assert (event["outcome"], event["reason"], event["error_type"], event["returncode"]) == (
        "failed",
        "completion_error",
        "ValidationError",
        4,
    )
    assert event["request_id"] == "rejected-completion"
    assert event["order_id"] is not None and event["run_id"] == event["order_id"]
    assert SECRET not in (tmp_path / "execution.jsonl").read_text()
