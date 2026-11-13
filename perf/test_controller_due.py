"""The planning pass at fleet volume: Controller.due() — the tick's read half, no dispatch —
over a settled cadence. K passes: per-pass wall time and statement count are bounded, the
routing cursor advances (routing is incremental, never a full re-scan), and the settled
pass's statement count does not grow with the repository count — the planning loop is
set-based over subjects() results, and a per-repository query sneaking in is the regression
this catches."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from time import perf_counter

import sqlalchemy as sa
from sqlalchemy.engine import Engine
from traust_core.v1.context import Config, Context
from traust_core.v1.context.config import DatabaseConfig
from traust_core.v1.models.common import every_item
from traust_core.v1.models.inventory import RepositoryFilter
from traust_core.v1.models.operations import LaneName, Route

from perf.seed import T0
from traust_engine.ops.controller import Controller
from traust_engine.ops.pack import Pack

PACK = Path(__file__).parents[1] / "tests" / "fixtures" / "packs" / "security-source.yaml"
PASSES = 5  # the first consumes the routing delta; the rest run the settled cadence
WALL_BUDGET_MS = 10_000
SETTLED_STATEMENT_BUDGET = 15  # set-based reads: a handful per asset, whatever the fleet


class Clock:
    def now(self) -> datetime:
        return T0


class FixedRouter:
    """Every state routes to the diff-scan lane; the pass proves the reads, not the lanes."""

    def route(self, state: object, releases: object, refused: object) -> list[Route]:
        return [Route(lane=LaneName("diff-scan"), priority=50, reason="perf")]


@dataclass
class Pass:
    page_statements: int
    due_statements: int
    wall_ms: float
    routed: int


@contextmanager
def issued(engine: Engine) -> Iterator[list[tuple[str, object]]]:
    statements: list[tuple[str, object]] = []

    def record(
        _conn: object, _cursor: object, sql: str, params: object, _ctx: object, _many: bool
    ) -> None:
        statements.append((sql, params))

    sa.event.listen(engine, "before_cursor_execute", record)
    try:
        yield statements
    finally:
        sa.event.remove(engine, "before_cursor_execute", record)


def _controller(engine: Engine) -> tuple[Controller[object], Context]:
    with TemporaryDirectory() as home:
        context = Context(
            Config(
                home=Path(home),
                database=DatabaseConfig(url=engine.url.render_as_string(hide_password=False)),
            ),
            clock=Clock(),
        )
    services = context.services()
    return (
        Controller(
            Pack.load(PACK),
            services.ops,  # type: ignore[arg-type]
            Clock(),
            router=FixedRouter(),  # type: ignore[arg-type]
            state_of=lambda repository_id: repository_id,
            feed=services.feed,  # type: ignore[arg-type]
            portfolio=services.portfolio,  # type: ignore[arg-type]
        ),
        context,
    )


def _passes(engine: Engine, count: int) -> list[Pass]:
    controller, context = _controller(engine)
    services = context.services()
    passed: list[Pass] = []
    for _ in range(count):
        start = perf_counter()
        # the fleet page a pass reads before planning (EngineLoop._hosts' read): bounded
        # pages, so its statement count grows with the fleet by page, not by repository
        with issued(context.database) as page_statements:
            repositories = [
                r.id
                for r in every_item(
                    lambda p: services.portfolio.list_repositories(RepositoryFilter(), p)
                )
                if r.id is not None
            ]
        # the planning pass itself: set-based reads, fleet-size independent
        with issued(context.database) as due_statements:
            report, _, _ = controller.due(repositories)
        wall_ms = (perf_counter() - start) * 1000
        passed.append(Pass(len(page_statements), len(due_statements), wall_ms, report.routed))
    return passed


def test_a_settled_tick_is_bounded_incremental_and_fleet_size_independent(
    fleet_engine: Engine, small_fleet_engine: Engine
) -> None:
    passed = _passes(fleet_engine, PASSES)
    # the routing cursor advances: the first pass consumes the delta, later passes re-scan
    # nothing (a cursor stuck at the start would route the whole fleet again)
    assert passed[0].routed > 0, passed
    assert all(p.routed == 0 for p in passed[1:]), passed
    # the settled cadence: the same bounded reads every pass
    assert all(p.wall_ms < WALL_BUDGET_MS for p in passed), passed
    settled = passed[1:]
    assert all(p.due_statements <= SETTLED_STATEMENT_BUDGET for p in settled), passed
    assert len({p.due_statements for p in settled}) == 1, passed
    # fleet-size independence: the settled planning pass reads the same statements at 1k and
    # 10k repositories — a per-repository query in the loop crosses this at once. The fleet
    # page above is paging by design and grows with the fleet by page, not by repository.
    small = _passes(small_fleet_engine, 2)
    assert small[1].due_statements == settled[0].due_statements, (small, settled[0])
    assert small[0].routed > 0 and small[1].routed == 0, small
