from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pydantic
import pytest
import yaml
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.operations import LaneName, Requirement

from traust_engine.ops.admission import TokenBucket
from traust_engine.ops.pack import Pack

PACK = Path(__file__).parent / "fixtures" / "packs" / "security-source.yaml"
T0 = datetime(2026, 10, 1, tzinfo=UTC)


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "assets.yaml"
    path.write_text(text)
    return path


def test_load_reads_the_engine_fields_and_ignores_the_runners() -> None:
    pack = Pack.load(PACK)
    repo_state = pack.assets["repo_state"]
    assert (repo_state.partitions, repo_state.trigger.every) == (
        "dynamic:repo",
        timedelta(hours=24),
    )
    quota = repo_state.admission.quota
    assert (
        quota is not None
        and quota.per_hour == 2
        and quota.bucket("github.com") == "forge:github.com"
    )
    assert pack.assets["dependency_graph"].trigger.every == timedelta(days=7)
    assert pack.asset_for_lane(LaneName("diff-scan-quarterly")) == "diff_scan"


def test_topo_order_puts_upstreams_first() -> None:
    order = Pack.load(PACK).topo_order()
    assert order.index("repo_state") < order.index("dependency_graph")
    assert order.index("feeds_cache") < order.index("dependency_graph")
    assert order.index("repo_state") < order.index("diff_scan")


def test_a_lane_no_asset_runs_is_a_config_error() -> None:
    with pytest.raises(ConfigError):
        Pack.load(PACK).asset_for_lane(LaneName("full-audit"))


@pytest.mark.parametrize(
    "assets",
    [
        "a: {deps: [missing]}",
        "a: {deps: [b]}\n  b: {deps: [a]}",
        "a: {trigger: {lanes: [x]}}\n  b: {trigger: {lanes: [x]}}",
        "a: {trigger: {every: soon}}",
        "a: {admission: {quota: {key: k, per_hour: 0}}}",
        "a: {admission: {pacing: {per_tick: 0}}}",
        "a: {trigger: {evry: 24h}}",
        "a: {partitions: repository}",
    ],
    ids=[
        "unknown dep",
        "cycle",
        "shared lane",
        "bad duration",
        "zero quota",
        "zero pacing",
        "misspelt key (schema)",
        "unknown partitioning (schema)",
    ],
)
def test_an_inconsistent_pack_is_a_config_error(tmp_path: Path, assets: str) -> None:
    with pytest.raises(ConfigError):
        Pack.load(_write(tmp_path, f"pack: p\nassets:\n  {assets}\n"))


@pytest.mark.parametrize("route_on", ["missing", "a"], ids=["unknown", "no cadence"])
def test_route_on_must_be_an_asset_with_a_cadence(tmp_path: Path, route_on: str) -> None:
    with pytest.raises(ConfigError):
        Pack.load(_write(tmp_path, f"pack: p\nroute_on: {route_on}\nassets:\n  a: {{}}\n"))


@pytest.mark.parametrize("text", [None, "pack: [unclosed"], ids=["missing file", "bad yaml"])
def test_an_unreadable_pack_is_a_config_error(tmp_path: Path, text: str | None) -> None:
    path = tmp_path / "assets.yaml"
    if text is not None:
        path.write_text(text)
    with pytest.raises(ConfigError):
        Pack.load(path)


def test_a_token_bucket_spends_then_refills_up_to_an_hours_worth() -> None:
    bucket = TokenBucket(per_hour=2, tokens=2, at=T0)
    assert [bucket.take(T0) for _ in range(3)] == [True, True, False]
    assert bucket.take(T0 + timedelta(minutes=29)) is False
    assert bucket.take(T0 + timedelta(minutes=30)) is True
    assert bucket.take(T0 + timedelta(days=1)) is True
    assert bucket.tokens == 1


def test_a_missing_pin_file_is_a_config_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match=r"pinned config .*external-tools\.yaml"):
        Pack.load(PACK, tmp_path / "external-tools.yaml")


def test_an_enabled_asset_without_run_or_model_role_is_a_pack_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="enabled: false is the exemption"):
        Pack.load(_write(tmp_path, "pack: p\nassets:\n  a: {trigger: {every: 24h}}\n"))


def test_a_disabled_asset_is_exempt_from_its_requirements(tmp_path: Path) -> None:
    pack = Pack.load(
        _write(
            tmp_path,
            "pack: p\n"
            "assets:\n"
            "  a: {run: [x], trigger: {every: 24h}}\n"
            "  b: {enabled: false, requires: {facts: [sla-policy]}}\n",
        )
    )
    assert pack.requirements() == (Requirement(),)


def test_a_pack_built_in_code_records_no_config() -> None:
    assert Pack.model_validate({"pack": "p", "assets": {}}).config() == ()


def test_an_enabled_asset_depending_on_a_disabled_one_is_a_pack_error() -> None:
    raw = yaml.safe_load(PACK.read_text())
    raw["assets"]["feeds_cache"]["enabled"] = False  # repo_state deps on it
    with pytest.raises(pydantic.ValidationError, match="depend on disabled"):
        Pack.model_validate(raw)


def test_route_on_a_disabled_asset_is_a_pack_error() -> None:
    raw = yaml.safe_load(PACK.read_text())
    raw["assets"][raw["route_on"]]["enabled"] = False
    with pytest.raises(pydantic.ValidationError, match="route_on"):
        Pack.model_validate(raw)


def test_the_packs_lanes_are_the_enabled_assets_lanes() -> None:
    raw = yaml.safe_load(PACK.read_text())
    enabled = Pack.model_validate(raw).lanes
    disabled = [
        lane for a in raw["assets"].values() for lane in a.get("trigger", {}).get("lanes", [])
    ]
    raw["assets"]["diff_scan"]["enabled"] = False
    assert set(Pack.model_validate(raw).lanes) == set(enabled) - {
        lane for a in [raw["assets"]["diff_scan"]] for lane in a["trigger"]["lanes"]
    }
    assert set(disabled) >= set(Pack.model_validate(raw).lanes)
