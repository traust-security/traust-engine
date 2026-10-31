"""The start gate: `run`, `shadow` and `claim` preflight the enabled assets' requirements
(core's `Context.preflight`) and refuse before any work, naming every gap with its fix."""

from __future__ import annotations

import contextlib
import io
import json
import shutil
from pathlib import Path
from typing import Any

import pytest
import yaml
from traust_core.v1.context import Context
from traust_core.v1.models.common import every_item
from traust_core.v1.models.operations import OrderFilter, OrderState

from traust_engine.ops import cli

PACK = Path(__file__).parent / "fixtures" / "packs" / "security-source.yaml"
SCANNER = {"run": ["scan"], "trigger": {"every": "24h"}}
SESSION = {"model": {"role": "graph"}, "trigger": {"every": "24h"}}


def _core(tmp_path: Path) -> Path:
    path = tmp_path / "core.yaml"
    path.write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    shutil.copytree(Path(__file__).parent / "fixtures" / "config", tmp_path, dirs_exist_ok=True)
    return path


def _pack(tmp_path: Path, assets: dict[str, dict[str, Any]]) -> Path:
    path = tmp_path / "assets.yaml"
    path.write_text(yaml.safe_dump({"pack": "p", "assets": assets}))
    return path


def _start(core: Path, pack: Path, op: str, *argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = cli.main([op, "--core", str(core), "--pack", str(pack), *argv])
    return rc, out.getvalue(), err.getvalue()


def _orders(core: Path) -> list[str]:
    ops = Context.from_file(core).services().ops
    return sorted(
        o.asset for o in every_item(lambda p: ops.list(OrderFilter(states=tuple(OrderState)), p))
    )


def _uninstalled_tools(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("PATH", str(tmp_path / "nowhere"))


@pytest.mark.parametrize("op", ["run", "shadow"])
def test_run_and_shadow_refuse_before_planning_naming_every_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, op: str
) -> None:
    core = _core(tmp_path)
    pack = _pack(
        tmp_path,
        {"scanner": SCANNER | {"requires": {"tools": ["gitleaks"], "facts": ["sla-policy"]}}},
    )
    _uninstalled_tools(monkeypatch, tmp_path)

    rc, _, err = _start(core, pack, op, "--once")

    assert rc == 2
    assert "gitleaks: not found on PATH (install it at the external-tools.yaml pin" in err
    assert (
        "facts: sla-policy is not recorded -- record one (InsightService.record_sla_policy)" in err
    )
    assert _orders(core) == []


@pytest.mark.parametrize(
    ("requires", "gap"),
    [
        (
            {"tools": ["gitleaks"]},
            "gitleaks: not found on PATH (install it at the external-tools.yaml pin",
        ),
        ({"config": ["review"]}, "config: `review` is not set -- set it in traust.yaml"),
        (
            {"facts": ["sla-policy"]},
            "facts: sla-policy is not recorded -- record one (InsightService.record_sla_policy)",
        ),
        (
            {"feeds": ["deps_dev"]},
            "feeds: deps_dev is not an enabled source -- enable it in the feeds registry",
        ),
        ({"secrets": ["NVD_API_KEY"]}, "secrets: $NVD_API_KEY is not set"),
    ],
    ids=["tool", "config", "fact", "feed", "secret"],
)
def test_each_requirement_kind_refuses_the_engine_before_planning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, requires: dict[str, list[str]], gap: str
) -> None:
    core = _core(tmp_path)
    pack = _pack(tmp_path, {"scanner": SCANNER | {"requires": requires}})
    _uninstalled_tools(monkeypatch, tmp_path)
    monkeypatch.delenv("NVD_API_KEY", raising=False)

    rc, _, err = _start(core, pack, "run", "--once")

    assert rc == 2 and gap in err
    assert _orders(core) == []


def test_a_requirement_met_lets_the_engine_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    core = _core(tmp_path)
    pack = _pack(tmp_path, {"scanner": SCANNER | {"requires": {"secrets": ["NVD_API_KEY"]}}})
    monkeypatch.setenv("NVD_API_KEY", "synthetic-only")

    rc, _, _ = _start(core, pack, "run", "--once")

    assert rc == 0
    assert _orders(core) == ["scanner"]


def test_claim_checks_only_the_assets_it_can_claim(tmp_path: Path) -> None:
    core = _core(tmp_path)
    pack = _pack(
        tmp_path,
        {"scanner": SCANNER, "session": SESSION | {"requires": {"facts": ["sla-policy"]}}},
    )

    rc, _, err = _start(core, pack, "run", "--once")
    assert rc == 2 and "sla-policy is not recorded" in err  # a pass needs every enabled asset

    rc, out, _ = _start(core, pack, "claim")
    assert rc == 0 and json.loads(out) == {"claimed": None}  # a claim cannot run the session


def test_a_routing_pack_without_a_router_refuses_to_start(tmp_path: Path) -> None:
    core = _core(tmp_path)

    rc, _, err = _start(core, PACK, "run", "--once")

    assert rc == 2 and "no --router was given" in err
    assert _orders(core) == []
