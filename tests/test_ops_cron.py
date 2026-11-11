"""Cron triggers: the expression's last fire time, and a clock-time asset in the loop over real
traust-core services on SQLite (due at each fire unless attempted since)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from traust_core.v1.context import Config, Context
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.operations import JobResult, WorkerId

from traust_engine.ops.cron import Cron
from traust_engine.ops.loop import EngineLoop
from traust_engine.ops.pack import Pack

PACK = Path(__file__).parent / "fixtures" / "packs" / "security-source.yaml"
MONDAY_0800 = datetime(2026, 10, 26, 8, 0, tzinfo=UTC)  # a Monday


@pytest.mark.parametrize(
    ("expression", "now", "last"),
    [
        ("0 7 * * 1", MONDAY_0800, datetime(2026, 10, 26, 7, 0, tzinfo=UTC)),
        ("0 7 * * 1", MONDAY_0800 - timedelta(hours=2), datetime(2026, 10, 19, 7, 0, tzinfo=UTC)),
        ("0 7 * * mon", MONDAY_0800, datetime(2026, 10, 26, 7, 0, tzinfo=UTC)),
        ("*/15 * * * *", MONDAY_0800 + timedelta(minutes=14), MONDAY_0800),
        ("0 5 * * *", MONDAY_0800, datetime(2026, 10, 26, 5, 0, tzinfo=UTC)),
        ("30 23 1 * *", MONDAY_0800, datetime(2026, 10, 1, 23, 30, tzinfo=UTC)),
        ("0 0 1,15 * *", MONDAY_0800, datetime(2026, 10, 15, 0, 0, tzinfo=UTC)),
        ("0 9-17 * * 1-5", MONDAY_0800, datetime(2026, 10, 23, 17, 0, tzinfo=UTC)),
        ("0 0 * * 0", MONDAY_0800, datetime(2026, 10, 25, 0, 0, tzinfo=UTC)),
        ("0 0 * * 7", MONDAY_0800, datetime(2026, 10, 25, 0, 0, tzinfo=UTC)),
        ("0 0 13 * 5", MONDAY_0800, datetime(2026, 10, 23, 0, 0, tzinfo=UTC)),  # 13th or Friday
        ("0 8 * * 1", MONDAY_0800, MONDAY_0800),  # a fire at now counts
    ],
)
def test_the_last_fire_at_or_before_now(expression: str, now: datetime, last: datetime) -> None:
    assert Cron.parse(expression).last(now) == last


@pytest.mark.parametrize(
    "expression",
    [
        "0 7 * *",
        "60 * * * *",
        "* 24 * * *",
        "* * 0 * *",
        "* * * 13 *",
        "* * * * 8",
        "*/0 * * * *",
        "5-1 * * * *",
        "x * * * *",
        "0 0 31 2 *",
    ],
)
def test_a_malformed_or_impossible_expression_is_refused(expression: str) -> None:
    with pytest.raises(ValueError):
        Cron.parse(expression).last(MONDAY_0800)


class Clock:
    def __init__(self, at: datetime) -> None:
        self.at = at

    def now(self) -> datetime:
        return self.at


def _pack(tmp_path: Path, trigger: dict[str, str]) -> Path:
    raw = yaml.safe_load(PACK.read_text())
    raw["assets"]["feeds_cache"]["trigger"] = trigger
    path = tmp_path / "assets.yaml"
    path.write_text(yaml.safe_dump(raw))
    return path


def test_a_cron_asset_is_due_at_each_fire_unless_attempted_since(tmp_path: Path) -> None:
    clock = Clock(MONDAY_0800)
    services = Context(Config(home=tmp_path / "home"), clock=clock).services()
    loop = EngineLoop(services, clock, Pack.load(_pack(tmp_path, {"on_cron": "0 7 * * 1"})))

    def feeds_planned() -> int:
        return sum(r.asset == "feeds_cache" for r in loop.shadow_once().due)

    assert feeds_planned() == 1  # never attempted: due since this morning's fire
    loop.run_once()
    order = services.ops.claim(WorkerId("w"), timedelta(minutes=5), ["feeds_cache"])
    assert order is not None and order.id is not None
    services.ops.complete(order.id, WorkerId("w"), JobResult.succeeded())
    clock.at += timedelta(days=6)
    assert feeds_planned() == 0  # attempted after Monday's fire, next is still to come
    clock.at += timedelta(days=1)
    assert feeds_planned() == 1  # next Monday 07:00 has passed


def test_a_bad_cron_in_the_pack_is_a_config_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cron"):
        Pack.load(_pack(tmp_path, {"on_cron": "61 7 * * 1"}))


def test_route_on_needs_an_interval_not_a_cron(tmp_path: Path) -> None:
    raw = yaml.safe_load(PACK.read_text())
    raw["assets"]["repo_state"]["trigger"] = {"on_cron": "0 5 * * *"}
    path = tmp_path / "assets.yaml"
    path.write_text(yaml.safe_dump(raw))
    with pytest.raises(ConfigError, match="route_on"):
        Pack.load(path)
