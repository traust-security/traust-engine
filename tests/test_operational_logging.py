from __future__ import annotations

import json
import subprocess
import time
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml
from traust_core.v1.context import (
    Config,
    Context,
    LoggingConfig,
    correlation_scope,
    current_correlation,
)
from traust_core.v1.errors import ConflictError
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.operations import OrderRequest, WorkerId
from traust_core.v1.models.vocabulary import ActorKind

from traust_engine.ops import cli
from traust_engine.ops.pack import Pack
from traust_engine.ops.runner import Runner

PACK = Path(__file__).parent / "fixtures" / "packs" / "security-source.yaml"
SECRET = "synthetic-secret-never-log"
PRIVATE_URL = f"https://user:{SECRET}@private.example.test/repository"
WORKER = WorkerId("logging-runner")
OPERATOR = Principal(identity="operator@example.test", kind=ActorKind.HUMAN, display="operator")


def _core_file(tmp_path: Path, log_file: Path, outputs: tuple[str, ...] | None = ("file",)) -> Path:
    path = tmp_path / "core.yaml"
    logging_config: dict[str, object] = {
        "level": "INFO",
        "format": "json",
        "file": str(log_file),
    }
    if outputs is not None:
        logging_config["outputs"] = list(outputs)
    path.write_text(yaml.safe_dump({"home": str(tmp_path / "store"), "logging": logging_config}))
    return path


def _rows(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def _secret_pack(tmp_path: Path) -> Path:
    raw = yaml.safe_load(PACK.read_text())
    raw["assets"]["feeds_cache"]["run"] = ["scanner", f"--token={SECRET}", PRIVATE_URL]
    path = tmp_path / "pack.yaml"
    path.write_text(yaml.safe_dump(raw))
    return path


def test_cli_uses_core_outputs_and_scopes_claimed_execution_without_leaks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    log_file = tmp_path / "engine.log"
    core_file = _core_file(tmp_path, log_file)
    queued = (
        Context.from_file(core_file)
        .services()
        .ops.submit(OrderRequest(asset="feeds_cache", priority=1), OPERATOR)
    )
    assert queued.id is not None

    def run(command: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 9, SECRET, SECRET)

    monkeypatch.setattr("traust_engine.ops.runner._run", run)
    args = ["claim", "--core", str(core_file), "--pack", str(_secret_pack(tmp_path))]
    assert cli.main(args) == 1
    captured = capsys.readouterr()
    assert captured.err == "" and SECRET not in captured.out and PRIVATE_URL not in captured.out

    rows = _rows(log_file)
    engine = [row for row in rows if (row["operation"] or "").startswith("engine.")]
    assert [row["operation"] for row in engine] == [
        "engine.startup",
        "engine.lease",
        "engine.execution",
        "engine.claim",
    ]
    assert [row["outcome"] for row in engine] == ["ready", "claimed", "failed", "completed"]
    execution = engine[2]
    assert (execution["reason"], execution["returncode"], execution["status"]) == (
        "runner-crashed",
        9,
        "failed",
    )
    operation_rows = engine[1:]
    assert len({row["request_id"] for row in operation_rows}) == 1
    assert all(row["order_id"] == str(queued.id) for row in operation_rows)
    assert all(row["run_id"] == str(queued.id) for row in operation_rows)
    text = log_file.read_text()
    assert all(value not in text for value in (SECRET, PRIVATE_URL, "--token="))

    before = len(rows)
    assert cli.main(args) == 0
    capsys.readouterr()
    later = _rows(log_file)[before:]
    empty = [row for row in later if row["operation"] == "engine.lease"]
    assert len(empty) == 1 and empty[0]["outcome"] == "empty"
    assert empty[0]["order_id"] is None and empty[0]["run_id"] is None
    assert empty[0]["request_id"] != operation_rows[0]["request_id"]


def test_heartbeat_thread_inherits_order_correlation_without_exception_text(tmp_path: Path) -> None:
    log_file = tmp_path / "heartbeat.log"
    context = Context(
        Config(
            home=tmp_path / "home",
            logging=LoggingConfig(level="INFO", file=log_file, outputs=("file",)),
        )
    )
    context.configure_logging("traust_engine")
    services = context.services()
    queued = services.ops.submit(OrderRequest(asset="feeds_cache", priority=1), OPERATOR)
    assert queued.id is not None
    seen = []

    def heartbeat(*_: object) -> None:
        seen.append(current_correlation())
        raise ConflictError(SECRET)

    def slow(command: list[str]) -> subprocess.CompletedProcess[str]:
        time.sleep(0.08)
        return subprocess.CompletedProcess(command, 0, "", "")

    services.ops.heartbeat = heartbeat  # type: ignore[method-assign]
    runner = Runner(
        services,
        Pack.load(PACK),
        WORKER,
        lease_for=timedelta(seconds=0.03),
        hosts=("github.com",),
        run=slow,
    )
    with correlation_scope("heartbeat-request", actor_kind=ActorKind.MACHINE):
        completed = runner.claim_once()
    assert completed is not None
    assert seen and seen[0] is not None
    assert (seen[0].request_id, seen[0].order_id, seen[0].run_id) == (
        "heartbeat-request",
        queued.id,
        queued.id,
    )

    rows = _rows(log_file)
    heartbeats = [row for row in rows if row["operation"] == "engine.heartbeat"]
    assert len(heartbeats) == 1
    assert (heartbeats[0]["outcome"], heartbeats[0]["reason"]) == (
        "lease_lost",
        "lease_conflict",
    )
    assert heartbeats[0]["request_id"] == "heartbeat-request"
    assert heartbeats[0]["order_id"] == str(queued.id)
    assert SECRET not in log_file.read_text()


def test_recorded_execution_failure_has_no_false_success_or_raw_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    log_file = tmp_path / "record.log"
    core_file = _core_file(tmp_path, log_file)

    def missing(*_: object, **__: object) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError(f"/{SECRET}/missing")

    monkeypatch.setattr("traust_engine.ops.shadow.subprocess.run", missing)
    args = [
        "record",
        "--core",
        str(core_file),
        "--pack",
        str(PACK),
        "feeds_cache",
        "--",
        f"/{SECRET}/missing",
    ]
    assert cli.main(args) == 2
    captured = capsys.readouterr()
    assert "record failed (FileNotFoundError)" in captured.err
    assert SECRET not in captured.err
    rows = _rows(log_file)
    engine = [row for row in rows if (row["operation"] or "").startswith("engine.")]
    assert [(row["operation"], row["outcome"]) for row in engine] == [
        ("engine.startup", "ready"),
        ("engine.execution", "failed"),
        ("engine.record", "failed"),
    ]
    assert engine[1]["error_type"] == "FileNotFoundError"
    assert engine[1]["order_id"] == engine[2]["order_id"]
    assert SECRET not in log_file.read_text()


@pytest.mark.parametrize(
    "outputs",
    [("file",), ("stderr",), None],
    ids=["file-only", "stderr-only", "default"],
)
def test_run_once_emits_one_bounded_tick_summary_per_selected_output(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    outputs: tuple[str, ...] | None,
) -> None:
    log_file = tmp_path / "tick.log"
    core_file = _core_file(tmp_path, log_file, outputs)
    assert cli.main(["run", "--once", "--core", str(core_file), "--pack", str(PACK)]) == 0
    captured = capsys.readouterr()
    selected = outputs or ("stderr", "file")
    destinations = []
    if "stderr" in selected:
        destinations.append(captured.err)
    else:
        assert captured.err == ""
    if "file" in selected:
        destinations.append(log_file.read_text())
    else:
        assert not log_file.exists()
    for output in destinations:
        rows = [json.loads(line) for line in output.splitlines()]
        engine = [row for row in rows if (row["operation"] or "").startswith("engine.")]
        assert [row["operation"] for row in engine] == ["engine.startup", "engine.tick"]
        ticks = [row for row in engine if row["operation"] == "engine.tick"]
        assert len(ticks) == 1 and ticks[0]["outcome"] == "completed"
        assert "planned:" in ticks[0]["status"] and "withheld:" in ticks[0]["status"]


def test_preflight_failure_is_bounded_and_terminal(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    log_file = tmp_path / "preflight.log"
    core_file = _core_file(tmp_path, log_file)
    bad_pack = tmp_path / f"{SECRET}.yaml"
    bad_pack.write_text(f"assets: {SECRET}")
    assert cli.main(["run", "--once", "--core", str(core_file), "--pack", str(bad_pack)]) == 2
    captured = capsys.readouterr()
    assert "startup failed" in captured.err and SECRET not in captured.err
    rows = _rows(log_file)
    startup = [row for row in rows if row["operation"] == "engine.startup"]
    assert len(startup) == 1
    assert (startup[0]["outcome"], startup[0]["reason"]) == ("failed", "preflight_error")
    assert SECRET not in log_file.read_text()
