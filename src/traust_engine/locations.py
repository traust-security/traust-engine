"""Runtime locations — where the harness reads and writes data.

Config-owned: every location comes from ``locations.yaml`` in the one config
home, never env, cwd, or a workspace-shaped heuristic. Config *resolution* lives
in ``traust_contracts``; this is the engine-side accessor layer.

Every accessor **requires** the ``Locations`` section from an already-loaded
context (``ctx.locations``, ``None`` when the estate has no ``locations.yaml``).
There is deliberately no environment self-fetch: a location can only come from a
context the caller resolved, so no consumer can silently read a second estate
below the ops layer. The resolution logic lives here, once; ops pass ``self._loc``
and never re-derive it.
"""

from __future__ import annotations

from pathlib import Path
from typing import TypeVar

from traust_contracts import DeploymentConfigMissing, Locations, load_section

_T = TypeVar("_T")


def configured_locations() -> Locations | None:
    """The ``Locations`` section resolved from the config home — the single,
    explicit **entry-point** read (``None`` when the estate has no
    ``locations.yaml``).

    Library code must NOT call this: it accepts an injected ``Locations``
    (``ctx.locations``, threaded by ``HarnessEngine`` ops) so config can only
    enter through a context the caller resolved. This function exists for CLI
    ``main``/default helpers that resolve their own context at the boundary.
    """
    return load_section("locations.yaml", required=False)


def local_path(value: str | None) -> Path | None:
    """The local Path form of a location value (a path or ``file://`` URI), or
    None when unset or a non-local URI (``s3://`` …) with no local form."""
    if not value:
        return None
    if value.startswith("file://"):
        return Path(value[len("file://") :])
    if "://" in value:
        return None
    return Path(value)


def require(value: _T | None, name: str) -> _T:
    """Return ``value``, or raise :class:`DeploymentConfigMissing` naming the
    unset location — the one place the fail-loud message is written. ``None`` also
    covers a remote URI with no local form when ``value`` came from
    :func:`local_path`."""
    if value is None:
        raise DeploymentConfigMissing(
            f"{name} not configured — set `{name}` in $TRAUST_CONFIG_HOME/locations.yaml "
            "(or it is a remote URI with no local form)."
        )
    return value


def analysis_results_location(loc: Locations | None) -> str | None:
    """Where findings-side artifacts live (local path or location URI). None when
    unconfigured."""
    return loc.analysis_results if loc and loc.analysis_results else None


def analysis_results_dir(loc: Locations | None) -> Path | None:
    """The LOCAL analysis-results path, or None when unset or a remote URI."""
    return local_path(analysis_results_location(loc))


def portfolio_graph_location(loc: Locations | None) -> str | None:
    """``locations.portfolio_graph`` when set, else
    ``<analysis-results>/graph/portfolio-graph.db``, else None."""
    if loc and loc.portfolio_graph:
        return loc.portfolio_graph
    base = analysis_results_location(loc)
    if not base:
        return None
    from traust_engine import storage

    return storage.join(base, "graph", "portfolio-graph.db")


def workspace_dir(loc: Locations | None) -> Path:
    """Workspace root, from ``locations.workspace``. FAILS LOUD when unconfigured
    — no cwd fallback that would write a stray tree wherever the process started."""
    return require(local_path(loc.workspace if loc else None), "workspace")


def progress_tracker_dir(loc: Locations | None) -> Path | None:
    """The metrics/progress output tree, from ``locations.progress_tracker``.
    None when unconfigured — no sibling-of-analysis-results heuristic."""
    return local_path(loc.progress_tracker if loc else None)


def feeds_cache_dir(loc: Locations | None) -> Path | None:
    """Feed cache directory, from ``locations.feeds_cache``. None when unset."""
    return local_path(loc.feeds_cache if loc else None)


def gitleaks_config_path(loc: Locations | None) -> Path | None:
    """Gitleaks rules TOML, from ``locations.gitleaks_config``. None when unset."""
    return local_path(loc.gitleaks_config if loc else None)


def opengrep_rules_dir(loc: Locations | None) -> Path | None:
    """Default opengrep rule pack directory, from ``locations.opengrep_rules``. None when unset."""
    return local_path(loc.opengrep_rules if loc else None)


def product_definitions_url(loc: Locations | None) -> str | None:
    """Product/ownership registry endpoint, from ``locations.product_definitions``.
    Returned raw (it is a URL, not a local path). None when unset."""
    return loc.product_definitions if loc else None


def sarif_tool_uri(loc: Locations | None) -> str | None:
    """SARIF driver ``informationUri``, from ``locations.sarif_tool_uri``.
    Returned raw (a URL). None when unset (the key is then omitted)."""
    return loc.sarif_tool_uri if loc else None


# --- known artifact layout ----------------------------------------------------
# The ONE place the fixed sub-layout under a root is defined. ``*_REL`` are
# relative paths for callers holding a root (``root / FINDINGS_DB_REL``); the
# accessors below join them under the config/injected root (None when unset).

FINDINGS_REL = Path("findings")
FINDINGS_DB_REL = Path("graph") / "findings.db"
REPO_GRAPH_REL = Path("graph") / "repo-graph.json"
PORTFOLIO_GRAPH_REL = Path("graph") / "portfolio-graph.db"
FP_PRECEDENT_CACHE_REL = Path("graph") / "fp-precedent-cache.json"
COMPLIANCE_REL = Path("compliance")
SCAN_TESTING_REL = Path("scan-testing")
PHASE0_REL = SCAN_TESTING_REL / "phase-0"
SWEEPS_REL = SCAN_TESTING_REL / "sweeps"
VALIDATION_BENCHMARK_REL = SCAN_TESTING_REL / "validation-benchmark"
#: The metrics-history journal lives under the configured metrics root, not results.
METRICS_HISTORY_REL = Path("metrics") / "metrics-history.jsonl"
#: Sweep-engine and regression-rule draft staging under the metrics root.
RULE_DRAFTS_REL = Path("metrics") / "rule-mining" / "rule-drafts"


def rule_drafts_dir(loc: Locations | None) -> Path | None:
    """Rule-draft staging tree, from ``locations.rule_drafts`` when set, else
    ``<progress_tracker>/metrics/rule-mining/rule-drafts``. None when neither
    can be resolved."""
    if loc and loc.rule_drafts:
        return local_path(loc.rule_drafts)
    pt = progress_tracker_dir(loc)
    return pt / RULE_DRAFTS_REL if pt else None


def _under_results(rel: Path, loc: Locations | None) -> Path | None:
    ar = analysis_results_dir(loc)
    return ar / rel if ar else None


def findings_db(loc: Locations | None) -> Path | None:
    """``<analysis-results>/graph/findings.db``, or None."""
    return _under_results(FINDINGS_DB_REL, loc)


def repo_graph(loc: Locations | None) -> Path | None:
    """``<analysis-results>/graph/repo-graph.json``, or None."""
    return _under_results(REPO_GRAPH_REL, loc)


def portfolio_graph_db(loc: Locations | None) -> Path | None:
    """``locations.portfolio_graph`` (local Path form) when set, else
    ``<analysis-results>/graph/portfolio-graph.db``, or None. Honors the explicit
    override, unlike a bare ``analysis_results`` join."""
    return local_path(portfolio_graph_location(loc))


def fp_precedent_cache(loc: Locations | None) -> Path | None:
    """``<analysis-results>/graph/fp-precedent-cache.json``, or None."""
    return _under_results(FP_PRECEDENT_CACHE_REL, loc)


def compliance_dir(loc: Locations | None) -> Path | None:
    """``<analysis-results>/compliance``, or None."""
    return _under_results(COMPLIANCE_REL, loc)


def scan_testing_dir(loc: Locations | None) -> Path | None:
    """``<analysis-results>/scan-testing``, or None."""
    return _under_results(SCAN_TESTING_REL, loc)


def benchmark_dir(loc: Locations | None) -> Path | None:
    """``<analysis-results>/scan-testing/validation-benchmark``, or None."""
    return _under_results(VALIDATION_BENCHMARK_REL, loc)


def metrics_history(loc: Locations | None) -> Path | None:
    """``<metrics-root>/metrics/metrics-history.jsonl``, or None."""
    pt = progress_tracker_dir(loc)
    return pt / METRICS_HISTORY_REL if pt else None
