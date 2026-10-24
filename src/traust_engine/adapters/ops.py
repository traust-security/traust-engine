"""``HarnessEngine.adapters`` — scanner config injection, bound to context.

Adapters stay stateless; this namespace only surfaces typed config from the
injected context (rule-pack allowlist, safe_exec profiles, workspace root).
"""

from __future__ import annotations

from pathlib import Path

from traust_contracts import RulePackAllowlist

from traust_engine._ops_base import ContextOps
from traust_engine.adapters import opengrep


class AdaptersOps(ContextOps):
    def allowlist_for_opengrep(self) -> RulePackAllowlist | None:
        """Typed rule-pack allowlist for opengrep supplemental packs."""
        return self._ctx.rule_pack_allowlist

    def rule_pack_allowlist_path(self) -> Path | None:
        """Filesystem path for allowlist YAML when loaded from context."""
        return self._optional_config_path("rule-pack-allowlist.yaml", self._ctx.rule_pack_allowlist)

    def rule_pack_dir(self) -> Path:
        """Resolved opengrep rule pack: locations → env → bundled default."""
        return opengrep.resolve_rule_pack_dir(
            pack=None,
            loc=self._loc,
        )
