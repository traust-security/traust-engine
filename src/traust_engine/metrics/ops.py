"""``HarnessEngine.metrics`` — metrics journal and spend, bound to context."""

from __future__ import annotations

from pathlib import Path

from traust_engine._ops_base import ContextOps
from traust_engine.locations import METRICS_HISTORY_REL
from traust_engine.metrics import attribute_spend, collect_spend, history, spend


class MetricsOps(ContextOps):
    """Metrics operations bound to one loaded context.

    Paths come from ``ctx.locations``; stateless functions in sibling modules
    receive injected journal/registry/roots — the engine never self-fetches.
    """

    def _journal(self) -> Path:
        return self._progress_tracker() / METRICS_HISTORY_REL

    def _model_registry(self):
        return self._ctx.model_registry

    def workspace(self) -> Path:
        return self._workspace()

    # --- metrics history -----------------------------------------------------

    def append(self, source: str, metrics: dict, note: str = "", hv: str | None = None) -> dict:
        return history.append(source, metrics, note=note, hv=hv, journal=self._journal())

    def append_if_changed(
        self, source: str, metrics: dict, note: str = "", hv: str | None = None
    ) -> dict | None:
        return history.append_if_changed(source, metrics, note=note, hv=hv, journal=self._journal())

    def rows(self) -> list[dict]:
        return history.rows(self._journal())

    def previous(self, source: str, before: str | None = None) -> dict | None:
        return history.previous(source, before=before, journal=self._journal())

    def verify(self) -> tuple[bool, list[str]]:
        return history.verify(self._journal())

    def render(self) -> tuple[Path, Path]:
        return history.render_exec(self._journal())

    # --- spend dashboard -----------------------------------------------------

    def spend_dashboard_dir(self) -> Path:
        return self._progress_tracker() / "metrics" / "dashboards" / "spend"

    def build_spend_dashboard(
        self, out_dir: Path | None = None, budget_path: Path | None = None, budget_section=None
    ) -> Path:
        return spend.build(
            self._workspace(),
            out_dir or self.spend_dashboard_dir(),
            budget_path=budget_path,
            journal=self._journal(),
            reg=self._model_registry(),
            budget_section=(
                budget_section if budget_section is not None else self._ctx.budget_policy
            ),
        )

    # --- session / attribution spend -----------------------------------------

    def session_project_dirs(self, workspace: Path | None = None) -> list[Path]:
        return collect_spend.workspace_slugs(workspace or self._workspace())

    def _long_prompt_thresholds(self) -> dict[str, int]:
        from traust_engine.registry.models import long_prompt_thresholds

        return long_prompt_thresholds(self._model_registry())

    def collect_session_spend(self, dirs: list[Path], day: str | None = None) -> dict:
        return collect_spend.collect(dirs, day, self._long_prompt_thresholds())

    def append_session_spend(self, dirs: list[Path] | None = None) -> int:
        project_dirs = dirs if dirs is not None else self.session_project_dirs()
        return collect_spend.append_rows(
            self._workspace(),
            project_dirs,
            journal=self._journal(),
            thresholds=self._long_prompt_thresholds(),
        )

    def collect_attributed(
        self,
        dirs: list[Path],
        day: str | None = None,
        month: str | None = None,
        valid: set[str] | None = None,
    ) -> dict:
        return attribute_spend.collect_attributed(
            dirs, day, month, valid, self._long_prompt_thresholds()
        )

    def attribute_reconcile(
        self, dirs: list[Path], day: str | None = None, month: str | None = None
    ) -> dict:
        return attribute_spend.reconcile(dirs, day, month)

    def append_attribution_rows(self, agg: dict, reg=None) -> int:
        return attribute_spend.append_rows(
            self._workspace(),
            agg,
            reg=reg if reg is not None else self._model_registry(),
            journal=self._journal(),
        )

    def render_attribution(self, agg: dict, month_label: str, reg=None) -> list[str]:
        return attribute_spend.render(
            agg,
            month_label,
            reg=reg if reg is not None else self._model_registry(),
        )
