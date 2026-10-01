"""End-to-end migration of fixtures through a real database backend.

The same ingest-and-verify flow runs across both supported backends:

  * SQLite  — always (part of `make test`).
  * Postgres — against the shared traust-postgres instance, only when
    TRAUST_MIGRATION_TEST_DATABASE_URL is reachable. The Postgres params are
    marked `postgres` and selected by `make db-test`; `make test` deselects
    them. Mirrors the traust-contracts / traust-ledger backend-parametrized
    storage e2e convention.
"""

from __future__ import annotations

import os
import sqlite3
import tempfile
import uuid
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import pytest
from test_migration_rehearsal import layer, put, setup

from traust_engine.corpus import migration_rehearsal as migration

BOOTSTRAP_DSN = os.environ.get("TRAUST_MIGRATION_TEST_DATABASE_URL")

RECONCILIATION_CHECKS = [
    "evidence_pointer",
    "binding_context",
    "projection_values_and_multiplicity",
    "row_counts",
]

BACKENDS = [
    pytest.param("sqlite", id="sqlite"),
    pytest.param("postgres", marks=pytest.mark.postgres, id="postgres"),
]


def _require_postgres():
    if not BOOTSTRAP_DSN:
        pytest.skip("TRAUST_MIGRATION_TEST_DATABASE_URL is not configured (run `make db-up`)")
    psycopg = pytest.importorskip("psycopg")
    try:
        with psycopg.connect(BOOTSTRAP_DSN, connect_timeout=2):
            pass
    except psycopg.OperationalError as exc:
        pytest.skip(f"postgres not reachable at TRAUST_MIGRATION_TEST_DATABASE_URL: {exc}")
    return psycopg


@pytest.fixture
def target(request) -> Iterator[tuple[str, str]]:
    """A fresh, empty store target for the parametrized backend.

    SQLite gets a nonexistent temp path; Postgres gets a freshly created
    empty database on the shared instance (dropped afterwards) — the importer
    refuses a target that already holds tables.
    """
    backend = request.param
    if backend == "sqlite":
        with tempfile.TemporaryDirectory() as tmp:
            yield backend, str(Path(tmp) / "artifact-store.sqlite")
        return

    psycopg = _require_postgres()
    from psycopg import sql

    name = f"traust_migration_e2e_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(BOOTSTRAP_DSN, autocommit=True) as conn:
        conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    try:
        yield backend, urlunsplit(urlsplit(BOOTSTRAP_DSN)._replace(path=f"/{name}"))
    finally:
        with psycopg.connect(BOOTSTRAP_DSN, autocommit=True) as conn:
            conn.execute(
                sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(name))
            )


def _evidence_byte_size(backend: str, dest: str) -> int:
    if backend == "sqlite":
        with sqlite3.connect(dest) as conn:
            return conn.execute("SELECT byte_size FROM artifact_evidence").fetchone()[0]
    import psycopg

    with psycopg.connect(dest) as conn:
        row = conn.execute("SELECT byte_size FROM traust_storage.artifact_evidence").fetchone()
        return row[0]


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_ingests_fixture_through_the_database(tmp_path, target) -> None:
    backend, dest = target
    root, config, output = setup(tmp_path)
    source = put(root, "team/good-findings-layer.json", layer())

    result = migration.rehearse(root, config, dest, output, database_type=backend)

    assert result["status"] == "passed", (output / "issues.jsonl").read_text()
    assert result["migration_ready"]
    assert result["reconciliation"]["passed"]
    assert result["reconciliation"]["checks"] == RECONCILIATION_CHECKS
    assert _evidence_byte_size(backend, dest) == len(source.read_bytes())


@pytest.mark.parametrize("target", BACKENDS, indirect=True)
def test_refuses_a_non_empty_target(tmp_path, target) -> None:
    backend, dest = target
    root, config, output = setup(tmp_path)
    put(root, "team/good-findings-layer.json", layer())

    first = migration.rehearse(root, config, dest, output, database_type=backend)
    assert first["status"] == "passed", (output / "issues.jsonl").read_text()

    retry = migration.rehearse(root, config, dest, tmp_path / "retry", database_type=backend)
    assert retry["status"] == "blocked"
    assert retry["issue_counts"] == {"systemic_failure": 1}
