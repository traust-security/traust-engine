"""``HarnessEngine.toolchain`` — external scanner pins and readiness, bound to context."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from traust_contracts import ExternalTools

from traust_engine._ops_base import ContextOps
from traust_engine.toolchain import (
    POPULATABLE_TOOLS,
    populate,
    preflight_failures,
    stamp_string,
)
from traust_engine.toolchain import (
    check_tool as _check_tool,
)
from traust_engine.toolchain._types import ToolCheck

_PIN_KEYS = ("expected", "version_cmd", "version_regex")


def _tool_entry(tool: Any) -> dict[str, Any]:
    if isinstance(tool, dict):
        return tool
    return tool.model_dump()


class ToolchainOps(ContextOps):
    def external_tools(self) -> ExternalTools:
        return self._ctx.external_tools

    def pins(self) -> dict[str, dict]:
        """Pin specs from ``external-tools.yaml`` keyed by tool name."""
        out: dict[str, dict] = {}
        for tool in self.external_tools().tools:
            spec = _tool_entry(tool)
            name = spec.get("name")
            if not name:
                continue
            out[name] = {k: spec[k] for k in _PIN_KEYS if k in spec}
        return out

    def check_tool(self, name: str) -> ToolCheck:
        spec = self.pins().get(name, {})
        return _check_tool(
            name,
            expected=spec.get("expected"),
            version_cmd=spec.get("version_cmd"),
            version_regex=spec.get("version_regex"),
        )

    def populate(self, tool: str) -> tuple[bool, str]:
        return populate(tool)

    def preflight_failures(self, results: list[ToolCheck]) -> list[str]:
        return preflight_failures(results)

    def stamp_string(
        self,
        tool: str,
        version: str | None = None,
        *,
        db_built: str | None = None,
        db_schema: str | None = None,
    ) -> str:
        return stamp_string(tool, version, db_built=db_built, db_schema=db_schema)

    @property
    def populatable_tools(self) -> frozenset[str]:
        return POPULATABLE_TOOLS

    def db_cache_dirs(self) -> dict[str, Path]:
        """Native vuln-DB cache roots keyed by tool name (grype)."""
        from traust_engine.toolchain._parsers import _GRYPE_DB_DIR

        return {"grype": _GRYPE_DB_DIR}
