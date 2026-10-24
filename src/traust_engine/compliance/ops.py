"""``HarnessEngine.compliance`` — posture dashboard, bound to context.

Paths come from the injected ``HarnessContext``; callers use ``h.compliance.build()``
where they used to pass ``compliance_dir()``, ``findings_db()``, etc.
"""

from __future__ import annotations

from pathlib import Path

from traust_contracts import DeploymentConfigMissing

from traust_engine._ops_base import ContextOps
from traust_engine.compliance import dashboard
from traust_engine.locations import COMPLIANCE_REL, FINDINGS_DB_REL, REPO_GRAPH_REL

SCOPE_REGISTRY = "compliance-scope.yaml"
DASHBOARD_OUT_REL = Path("metrics") / "dashboards" / "compliance"


class ComplianceOps(ContextOps):
    def _compliance_dir(self) -> Path:
        return self._analysis_results() / COMPLIANCE_REL

    def _findings_db(self) -> Path:
        return self._analysis_results() / FINDINGS_DB_REL

    def _repo_graph(self) -> Path | None:
        try:
            return self._analysis_results() / REPO_GRAPH_REL
        except DeploymentConfigMissing:
            return None

    def scope_registry(self) -> Path:
        """Where the scope registry lives: the config home.

        The file may not exist yet; the scope intake writes it there.
        """
        return self._ctx.config_home / SCOPE_REGISTRY

    def dashboard_out_dir(self) -> Path:
        return self._progress_tracker() / DASHBOARD_OUT_REL

    def build(
        self,
        *,
        assessments_dir: Path | None = None,
        findings_db: Path | None = None,
        results_root: Path | None = None,
        scope_path: Path | None = None,
        graph_path: Path | None = None,
    ) -> dict:
        resolved_scope = scope_path if scope_path is not None else self.scope_registry()
        return dashboard.build(
            assessments_dir or self._compliance_dir(),
            findings_db or self._findings_db(),
            results_root or self._analysis_results(),
            self._ctx.corpus,
            scope_path=resolved_scope,
            graph_path=graph_path if graph_path is not None else self._repo_graph(),
        )

    def render_md(self, doc: dict, history: list[dict]) -> str:
        return dashboard.render_md(doc, history)
