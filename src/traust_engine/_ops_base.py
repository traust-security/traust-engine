"""Shared base for ``HarnessEngine`` op namespaces.

Holds the injected context and the fail-loud location resolvers every namespace
needs. The resolution logic itself lives in :mod:`traust_engine.locations`; this
just binds it to ``self._ctx.locations`` so no namespace re-derives it.
"""

from __future__ import annotations

from pathlib import Path

from traust_contracts import HarnessContext, Locations

from traust_engine import locations


class ContextOps:
    def __init__(self, ctx: HarnessContext) -> None:
        self._ctx = ctx
        self._safe_exec_profile_map: dict | None = None

    def safe_exec_profile_map(self) -> dict:
        """Resolved safe_exec profiles for this context (one per cached *Ops instance)."""
        if self._safe_exec_profile_map is None:
            from traust_engine._util import safe_exec

            self._safe_exec_profile_map = safe_exec.profiles_from_section(self._ctx.safe_exec)
        return self._safe_exec_profile_map

    def _optional_config_path(self, filename: str, loaded: object | None) -> Path | None:
        """Path under config_home when an optional section was loaded at entry."""
        if loaded is None:
            return None
        return self._ctx.config_home / filename

    @property
    def _loc(self) -> Locations | None:
        return self._ctx.locations

    def _workspace(self) -> Path:
        return locations.workspace_dir(self._loc)

    def _analysis_results(self) -> Path:
        return locations.require(locations.analysis_results_dir(self._loc), "analysis_results")

    def _progress_tracker(self) -> Path:
        return locations.require(locations.progress_tracker_dir(self._loc), "progress_tracker")
