"""``HarnessEngine.portfolio`` — portfolio graph paths, bound to context.

Paths come from the injected ``HarnessContext``; callers use ``h.portfolio.repo_graph()``
and ``h.portfolio.portfolio_graph_db()`` where they used to pass ``--spine`` / ``--db``.
"""

from __future__ import annotations

from pathlib import Path

from traust_engine import locations
from traust_engine._ops_base import ContextOps
from traust_engine.locations import REPO_GRAPH_REL


class PortfolioOps(ContextOps):
    def _repo_graph(self) -> Path:
        return self._analysis_results() / REPO_GRAPH_REL

    def _portfolio_graph_db(self) -> Path:
        return locations.require(
            locations.local_path(self.portfolio_graph_location()), "portfolio_graph"
        )

    def repo_graph(self) -> Path:
        return self._repo_graph()

    def portfolio_graph_db(self) -> Path:
        return self._portfolio_graph_db()

    def portfolio_graph_location(self) -> str:
        return locations.require(locations.portfolio_graph_location(self._loc), "portfolio_graph")
