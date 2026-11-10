"""The engine's perf gates: seeded Postgres workloads behind TRAUST_TEST_DATABASE_URL
(make db-up in traust-core — one container serves every repo)."""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest
from sqlalchemy.engine import Engine

from perf.seed import seeded_database


@pytest.fixture(scope="session")
def fleet_engine() -> Iterator[Engine]:
    url = os.environ.get("TRAUST_TEST_DATABASE_URL")
    if not url:
        pytest.skip("TRAUST_TEST_DATABASE_URL not set (make db-up)")
    eng = seeded_database(url, 10_000)
    yield eng
    eng.dispose()


@pytest.fixture(scope="session")
def small_fleet_engine() -> Iterator[Engine]:
    url = os.environ.get("TRAUST_TEST_DATABASE_URL")
    if not url:
        pytest.skip("TRAUST_TEST_DATABASE_URL not set (make db-up)")
    eng = seeded_database(url, 1_000)
    yield eng
    eng.dispose()
