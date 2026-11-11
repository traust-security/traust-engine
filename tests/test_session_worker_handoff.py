from __future__ import annotations

from datetime import timedelta

import yaml
from test_ops_runner import HOSTS, PACK, WORKER, Commands, _submit
from test_ops_runner import context as context
from traust_core.v1.context import Context
from traust_core.v1.models.operations import OrderState

from traust_engine.ops.pack import Pack
from traust_engine.ops.runner import Runner


def test_a_session_receives_the_claiming_worker_and_order(context: Context) -> None:
    raw = yaml.safe_load(PACK.read_text())
    raw["assets"]["diff_scan"]["run"] = ["session", "--run-id", "{run_id}", "--worker", "{worker}"]
    order = _submit(context, "diff_scan", repo=True)
    commands = Commands()
    result = Runner(
        context.services(), Pack.model_validate(raw), WORKER, timedelta(minutes=5), HOSTS, commands
    ).claim_once()
    assert commands.seen == [["session", "--run-id", str(order.id), "--worker", str(WORKER)]]
    assert result.state == OrderState.SUCCEEDED and result.lease_holder is None
