"""A Postgres contracts database seeded with the tick's own workload, built once and reused.

The database name carries a digest of the DDL and this seed, so a change to either rebuilds
it and an unchanged one is reused across runs. Unlike core's dashboard-volume seed, this is
the planning pass's read shape: repositories, a settled cadence of orders (nothing due), a
routing delta on the feed, and a refused-lane slice. `repositories` sets the fleet size —
each size gets its own database.
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime, timedelta

import sqlalchemy as sa
from traust_core.v1 import contracts
from traust_core.v1.repositories import apply_schema, create_database_engine
from traust_core.v1.repositories.sql import Dialect

# The tick reads a settled estate: every cadence's latest order materialized inside its
# window, so nothing is due and the planning pass proves its reads, not its plans.
T0 = datetime(2026, 10, 1, 6, tzinfo=UTC)
HOUR = timedelta(hours=1)
REFUSED_SLICE = 1_000  # repositories whose lane order was refused, so routing sees refusals

ANALYZED = ("traust.repository", "traust_ops.run_order")


def _at(delta: timedelta) -> str:
    return (T0 - delta).isoformat()


def _seed(repositories: int) -> tuple[str, ...]:
    hour, two_hours, two_days = _at(HOUR), _at(2 * HOUR), _at(2 * timedelta(days=2))
    return (
        f"""INSERT INTO traust.repository (url, public)
        SELECT 'https://perf.example/org/r' || g, true FROM generate_series(1, {repositories}) g""",
        """INSERT INTO traust_ops.run_batch (kind, period) VALUES ('drain_tranche', '2026-W40')""",
        # the routing delta: repo_state materialized within the route_on window, one per repo
        f"""INSERT INTO traust_ops.run_order (run_batch_id, repository_id, asset, lane, state,
            priority, requested_by, started_at, finished_at, created_at, updated_at)
        SELECT b.id, r.id, 'repo_state', NULL, 'succeeded', 20, 'machine:engine',
            '{hour}', '{hour}', '{hour}', '{hour}'
        FROM traust.repository r CROSS JOIN traust_ops.run_batch b""",
        # the fleet-wide cadence, settled inside its window
        f"""INSERT INTO traust_ops.run_order (run_batch_id, repository_id, asset, lane, state,
            priority, requested_by, started_at, finished_at, created_at, updated_at)
        SELECT b.id, NULL, 'feeds_cache', NULL, 'succeeded', 10, 'machine:engine',
            '{hour}', '{hour}', '{hour}', '{hour}'
        FROM traust_ops.run_batch b""",
        # a weekly cadence, settled inside its window
        f"""INSERT INTO traust_ops.run_order (run_batch_id, repository_id, asset, lane, state,
            priority, requested_by, started_at, finished_at, created_at, updated_at)
        SELECT b.id, r.id, 'dependency_graph', NULL, 'succeeded', 50, 'machine:engine',
            '{two_days}', '{two_days}', '{two_days}', '{two_days}'
        FROM traust.repository r CROSS JOIN traust_ops.run_batch b""",
        # the refused lane: routes back into it are counted, not re-planned
        f"""INSERT INTO traust_ops.run_order (run_batch_id, repository_id, asset, lane, state,
            priority, requested_by, started_at, finished_at, created_at, updated_at)
        SELECT b.id, r.id, 'diff_scan', 'diff-scan', 'refused', 50, 'machine:engine',
            '{two_hours}', '{two_hours}', '{two_hours}', '{two_hours}'
        FROM (SELECT * FROM traust.repository ORDER BY id LIMIT {REFUSED_SLICE}) r
        CROSS JOIN traust_ops.run_batch b""",
    )


def seeded_database(url: str, repositories: int) -> sa.Engine:
    """The tick-workload database for a fleet of `repositories`, built once and reused."""
    ddl = contracts.database_ddl(Dialect.POSTGRES)
    seed = _seed(repositories)
    digest = hashlib.sha256("\n".join((str(repositories), *ddl, *seed)).encode()).hexdigest()[:12]
    name = f"traust_engine_perf_{repositories}_{digest}"
    stale_prefix = f"traust_engine_perf_{repositories}_"
    admin = sa.create_engine(url, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        existing = set(
            conn.exec_driver_sql(
                "SELECT datname FROM pg_database WHERE starts_with(datname, 'traust_engine_perf_')"
            ).scalars()
        )
        for stale in existing - {name}:
            sized = re.fullmatch(r"traust_engine_perf_\d+_[0-9a-f]+", stale)
            if stale.startswith(stale_prefix) or sized is None:
                # another fleet size's current database stays; a same-size rebuild or an
                # older naming goes
                conn.exec_driver_sql(f"DROP DATABASE {stale} WITH (FORCE)")
        fresh = name not in existing
        if fresh:
            conn.exec_driver_sql(f"CREATE DATABASE {name}")
    admin.dispose()
    engine = create_database_engine(sa.make_url(url).set(database=name))
    if fresh:
        try:
            apply_schema(engine, ddl)
            apply_schema(engine, seed)
            with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
                for table in ANALYZED:
                    conn.exec_driver_sql(f"VACUUM (ANALYZE) {table}")
        except BaseException:
            engine.dispose()
            _drop(url, name)  # never leave a half-seeded database to be reused
            raise
    return engine


def _drop(url: str, name: str) -> None:
    admin = sa.create_engine(url, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.exec_driver_sql(f"DROP DATABASE {name} WITH (FORCE)")
    admin.dispose()
