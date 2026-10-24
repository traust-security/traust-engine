"""HarnessEngine client: built from a loaded context, injects locations into ops."""

from __future__ import annotations

import shutil
from pathlib import Path

import yaml

from traust_engine import HarnessEngine
from traust_engine.assets import compliance_data_dir

_FIXTURE = Path(__file__).parent / "fixtures" / "config"


def _home_with_progress_tracker(tmp_path: Path, pt: Path) -> Path:
    home = tmp_path / f"cfg-{pt.name}"
    shutil.copytree(_FIXTURE, home)
    (home / "locations.yaml").write_text(
        yaml.safe_dump({"progress_tracker": str(pt)}), encoding="utf-8"
    )
    return home


def test_metrics_journal_follows_configured_progress_tracker(tmp_path):
    pt = tmp_path / "estate-pt"
    h = HarnessEngine.load(config_home=_home_with_progress_tracker(tmp_path, pt))

    h.metrics.append("census", {"repos": 812})
    row = h.metrics.append("census", {"repos": 815})

    # the engine received its location from the context — the journal landed under
    # the operator-configured progress-tracker, not a workspace-relative guess.
    assert (pt / "metrics" / "metrics-history.jsonl").is_file()
    assert h.metrics.rows()[-1]["metrics"]["repos"] == 815
    assert h.metrics.previous("census")["row_sha"] == row["row_sha"]
    ok, issues = h.metrics.verify()
    assert ok, issues


def test_metrics_spend_build_uses_configured_paths(tmp_path):
    pt = tmp_path / "estate-pt"
    ws = tmp_path / "estate-ws"
    ws.mkdir()
    home = _home_with_progress_tracker(tmp_path, pt)
    (home / "locations.yaml").write_text(
        yaml.safe_dump({"progress_tracker": str(pt), "workspace": str(ws)}),
        encoding="utf-8",
    )
    h = HarnessEngine.load(config_home=home)
    out = h.metrics.build_spend_dashboard()
    assert out == pt / "metrics" / "dashboards" / "spend" / "spend-dashboard.md"
    assert out.is_file()


def test_compliance_reference_data_ships_with_the_engine():
    data = compliance_data_dir()
    for name in (
        "compliance-mapping.yaml",
        "spine-800-53-rev5.json",
        "profile-800-53b-high.json",
        "profile-800-53b-moderate.json",
        "provenance.json",
        "catalog-pci-dss-v4.yaml",
        "catalog-soc2-tsc.yaml",
        "catalog-gdpr-technical.yaml",
    ):
        assert (data / name).is_file(), name


def test_two_engines_are_isolated_by_their_context(tmp_path):
    h1 = HarnessEngine.load(config_home=_home_with_progress_tracker(tmp_path, tmp_path / "a"))
    h2 = HarnessEngine.load(config_home=_home_with_progress_tracker(tmp_path, tmp_path / "b"))
    h1.metrics.append("s", {"x": 1})
    assert h1.metrics.rows() and not h2.metrics.rows()


def test_namespace_ops_are_cached_per_engine(tmp_path):
    h = HarnessEngine.load(config_home=_home_with_progress_tracker(tmp_path, tmp_path / "pt"))
    assert h.metrics is h.metrics
    assert h.models is h.models
    assert h.compliance is h.compliance
    assert h.adapters is h.adapters
    assert h.sweep is h.sweep
    assert h.reporting is h.reporting
    assert h.portfolio is h.portfolio
    assert h.toolchain is h.toolchain


def test_models_registry_and_validate_from_context(tmp_path):
    h = HarnessEngine.load(config_home=_home_with_progress_tracker(tmp_path, tmp_path / "pt"))
    reg = h.models.registry()
    assert reg is h.ctx.model_registry
    assert h.models.validate() == []
    assert h.models.resolve("fact-judge") == "claude-sonnet-5"


def test_sweep_paths_follow_configured_locations(tmp_path):
    home = tmp_path / "cfg-sweep"
    shutil.copytree(_FIXTURE, home)
    ar = tmp_path / "analysis-results"
    ar.mkdir()
    pt = tmp_path / "progress-tracker"
    ws = tmp_path / "workspace"
    ws.mkdir()
    (home / "locations.yaml").write_text(
        yaml.safe_dump(
            {
                "analysis_results": str(ar),
                "progress_tracker": str(pt),
                "workspace": str(ws),
            }
        ),
        encoding="utf-8",
    )
    h = HarnessEngine.load(config_home=home)
    assert h.sweep._analysis_results() == ar
    assert h.sweep._scan_testing() == ar / "scan-testing"
    assert h.sweep._benchmark_dir() == ar / "scan-testing" / "validation-benchmark"
    assert h.sweep._progress_tracker() == pt
    assert h.sweep._workspace() == ws


def test_compliance_ops_use_configured_paths(tmp_path):
    pt = tmp_path / "pt"
    ar = tmp_path / "analysis-results"
    (ar / "compliance").mkdir(parents=True)
    (ar / "graph").mkdir(parents=True)
    pt.mkdir()
    home = _home_with_progress_tracker(tmp_path, pt)
    scope_path = home / "compliance-scope.yaml"
    scope_path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "updated": "2026-07-30",
                "boundaries": {
                    "b1": {
                        "frameworks": ["nist-800-53-rev5"],
                        "resolves_via": "explicit",
                        "include": [{"repo": "org/only", "reason": "fixture"}],
                        "declared_by": "test",
                        "declared_at": "2026-07-30",
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    graph_path = ar / "graph" / "repo-graph.json"
    graph_path.write_text('{"nodes":[],"edges":[]}', encoding="utf-8")

    (home / "locations.yaml").write_text(
        yaml.safe_dump({"progress_tracker": str(pt), "analysis_results": str(ar)}),
        encoding="utf-8",
    )
    h = HarnessEngine.load(config_home=home)

    assert h.compliance.scope_registry() == scope_path
    assert h.compliance.dashboard_out_dir() == pt / "metrics" / "dashboards" / "compliance"

    doc = h.compliance.build()
    assert doc["metadata"]["artifact"] == "compliance-dashboard"
    assert doc["metadata"]["assessments_found"] == 0


def test_adapters_ops_expose_context_config(tmp_path):
    home = _home_with_progress_tracker(tmp_path, tmp_path / "pt")
    h = HarnessEngine.load(config_home=home)
    allowlist = h.adapters.allowlist_for_opengrep()
    assert allowlist is not None
    assert "argus-observe-rules" in (allowlist.packs or {})
    assert h.adapters.rule_pack_allowlist_path() == home / "rule-pack-allowlist.yaml"
    assert h.adapters.rule_pack_dir().is_dir()

    from traust_engine.adapters.opengrep import load_supplemental_packs

    packs = load_supplemental_packs(allowlist=allowlist)
    assert any(p["name"] == "argus-observe-rules" for p in packs)


def test_portfolio_ops_use_configured_paths(tmp_path):
    ar = tmp_path / "analysis-results"
    (ar / "graph").mkdir(parents=True)
    spine_path = ar / "graph" / "repo-graph.json"
    spine_path.write_text('{"nodes":[],"edges":[]}', encoding="utf-8")
    explicit_db = tmp_path / "custom" / "portfolio.db"
    explicit_db.parent.mkdir()

    home = _home_with_progress_tracker(tmp_path, tmp_path / "pt")
    (home / "locations.yaml").write_text(
        yaml.safe_dump({"progress_tracker": str(tmp_path / "pt"), "analysis_results": str(ar)}),
        encoding="utf-8",
    )
    h = HarnessEngine.load(config_home=home)

    assert h.portfolio.repo_graph() == spine_path
    assert h.portfolio.portfolio_graph_db() == ar / "graph" / "portfolio-graph.db"
    assert h.portfolio.portfolio_graph_location() == str(ar / "graph" / "portfolio-graph.db")

    (home / "locations.yaml").write_text(
        yaml.safe_dump(
            {
                "progress_tracker": str(tmp_path / "pt"),
                "analysis_results": str(ar),
                "portfolio_graph": str(explicit_db),
            }
        ),
        encoding="utf-8",
    )
    h2 = HarnessEngine.load(config_home=home)
    assert h2.portfolio.portfolio_graph_db() == explicit_db
    assert h2.portfolio.portfolio_graph_location() == str(explicit_db)


def test_toolchain_ops_external_tools_from_context(tmp_path):
    home = _home_with_progress_tracker(tmp_path, tmp_path / "pt")
    h = HarnessEngine.load(config_home=home)
    assert h.toolchain.external_tools() is h.ctx.external_tools
    pins = h.toolchain.pins()
    assert pins["grype"]["expected"] == "0.115.0"
    assert pins["grype"]["version_cmd"] == ["grype", "--version"]


def test_safe_exec_profiles_from_engine_config_home_not_env(tmp_path, monkeypatch):
    """Profile map on *Ops is scoped to explicit config_home, not $TRAUST_CONFIG_HOME."""
    home_a = _home_with_progress_tracker(tmp_path, tmp_path / "pt-a")
    home_b = _home_with_progress_tracker(tmp_path, tmp_path / "pt-b")
    profiles_yaml = yaml.safe_load((home_b / "safe-exec-profiles.yaml").read_text())
    profiles_yaml["profiles"]["validation-step"]["allow"] = ["echo"]
    (home_b / "safe-exec-profiles.yaml").write_text(yaml.safe_dump(profiles_yaml), encoding="utf-8")

    monkeypatch.setenv("TRAUST_CONFIG_HOME", str(home_a))
    h_b = HarnessEngine.load(config_home=home_b)

    profile = h_b.adapters.safe_exec_profile_map()["validation-step"]
    assert profile.allow == frozenset({"echo"})
    assert "curl" not in profile.allow


def test_two_engines_keep_independent_safe_exec_profile_maps(tmp_path):
    """Two HarnessEngine instances in one process do not share a global allowlist."""
    home_a = _home_with_progress_tracker(tmp_path, tmp_path / "pt-a")
    home_b = _home_with_progress_tracker(tmp_path, tmp_path / "pt-b")
    profiles_yaml = yaml.safe_load((home_b / "safe-exec-profiles.yaml").read_text())
    profiles_yaml["profiles"]["validation-step"]["allow"] = ["echo"]
    (home_b / "safe-exec-profiles.yaml").write_text(yaml.safe_dump(profiles_yaml), encoding="utf-8")

    h_a = HarnessEngine.load(config_home=home_a)
    h_b = HarnessEngine.load(config_home=home_b)

    a_allow = h_a.adapters.safe_exec_profile_map()["validation-step"].allow
    b_allow = h_b.adapters.safe_exec_profile_map()["validation-step"].allow
    assert "curl" in a_allow
    assert b_allow == frozenset({"echo"})
    assert a_allow != b_allow


def test_safe_exec_bind_profiles_match_config_yaml_not_fallback(tmp_path):
    """profiles_from_section matches yaml; module bind is test/CLI legacy only."""
    from traust_contracts import load_context

    from traust_engine._util import safe_exec

    home = _home_with_progress_tracker(tmp_path, tmp_path / "pt")
    ctx = load_context(config_home=home)
    expected = safe_exec.profiles_from_section(ctx.safe_exec)

    safe_exec.reset_profiles()
    safe_exec.bind_profiles(ctx.safe_exec)

    bound = safe_exec.profiles()
    assert bound == expected
    assert "go-fuzz" in bound
    assert bound.keys() != safe_exec._FALLBACK_PROFILES.keys()
