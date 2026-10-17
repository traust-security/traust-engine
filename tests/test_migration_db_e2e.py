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

import importlib.util
import json
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


def _migrate_script():
    """scripts/migrate.py, the engine-local entry point (outside the package)."""
    path = Path(__file__).resolve().parents[1] / "scripts" / "migrate.py"
    spec = importlib.util.spec_from_file_location("migrate_script", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


def test_registers_filesystem_repository_before_artifacts_and_exports_ledger(
    tmp_path: Path,
) -> None:
    pytest.importorskip("sqlalchemy")
    from traust_ledger._internal.historical_migration import iter_manifest_layers

    root, config, output = setup(tmp_path)
    document = layer()
    put(root, "findings/acm/cli__release-2.0/cli-findings-layer.json", document)
    dest = str(tmp_path / "storage.sqlite")
    result = migration.rehearse(
        root, config, dest, output, database_type="sqlite", route_layers_to_ledger=True
    )

    assert result["status"] == "passed", (output / "issues.jsonl").read_text()
    assert not result["migration_ready"]  # Ledger still needs an explicit target.
    with sqlite3.connect(dest) as conn:
        product_repo_id, slug, url, ref = conn.execute(
            "SELECT pr.product_repo_id, p.slug, r.repo_url, pr.ref "
            "FROM product_repo pr JOIN product p USING (product_id) "
            "JOIN repo r USING (repo_id)"
        ).fetchone()
    assert (slug, url, ref) == ("acm", "https://example.test/r", "release-2.0")
    decision = next(
        json.loads(line)
        for line in (output / "decisions.jsonl").read_text().splitlines()
        if '"namespace": "traust_ledger"' in line
    )
    assert decision["product_repo_id"] == product_repo_id
    assert (
        next(iter_manifest_layers(root, output / "decisions.jsonl")).product_repo_id
        == product_repo_id
    )


def test_registry_strategy_reuses_product_and_repo_keys(tmp_path: Path) -> None:
    from traust_engine.corpus.migration_database import MigrationTarget

    target = MigrationTarget.sqlite(tmp_path / "registry.sqlite")
    try:
        target.initialize()
        first = target.register_repository("acm", "https://example.test/cli", "")
        branch = target.register_repository("acm", "https://example.test/cli", "release-2")
        target.register_repository("other", "https://example.test/cli", "")
        assert first != branch
        assert len(target.products) == 2
        assert len(target.repos) == 1
    finally:
        target.close()


def test_reuses_registered_repository_within_one_import(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from traust_engine.corpus.migration_database import MigrationTarget

    root, config, output = setup(tmp_path)
    put(root, "team/a-findings-layer.json", layer())
    put(root, "team/b-findings-layer.json", layer())
    original = MigrationTarget.register_repository
    calls = 0

    def register(database: MigrationTarget, slug: str, url: str, ref: str) -> str:
        nonlocal calls
        calls += 1
        return original(database, slug, url, ref)

    monkeypatch.setattr(MigrationTarget, "register_repository", register)
    result = migration.rehearse(
        root, config, str(tmp_path / "storage.sqlite"), output, database_type="sqlite"
    )
    assert result["status"] == "passed", (output / "issues.jsonl").read_text()
    assert calls == 1


def test_audit_binding_uses_registered_repo_and_commit(tmp_path: Path) -> None:
    from test_migration_validation import report

    root, config, output = setup(tmp_path)
    document = report()
    document["findings"][0]["fingerprint"] = "a" * 64
    document["metadata"]["repository"] = "https://example.test/r"
    document["metadata"]["commit"] = "b" * 40
    put(root, "findings/acm/cli/cli-security-audit.json", document)
    dest = tmp_path / "storage.sqlite"
    result = migration.rehearse(root, config, str(dest), output, database_type="sqlite")
    assert result["status"] == "passed", (output / "issues.jsonl").read_text()
    with sqlite3.connect(dest) as conn:
        assert conn.execute(
            "SELECT product_repo_id, commit_sha FROM artifact_binding"
        ).fetchone() == (
            conn.execute("SELECT product_repo_id FROM product_repo").fetchone()[0],
            "b" * 40,
        )


def test_optional_ledger_import_uses_the_same_product_repo(tmp_path: Path) -> None:
    pytest.importorskip("sqlalchemy")
    root, config, output = setup(tmp_path)
    put(root, "findings/acm/cli/cli-findings-layer.json", layer())
    dest = tmp_path / "storage.sqlite"
    result = migration.rehearse(
        root,
        config,
        str(dest),
        output,
        database_type="sqlite",
        route_layers_to_ledger=True,
        ledger_target_url=f"sqlite:///{dest}",
    )
    assert result["status"] == "passed", (output / "issues.jsonl").read_text()
    assert result["migration_ready"]
    assert result["ledger"]["counts"] == {"inserted": 1}
    with sqlite3.connect(dest) as conn:
        assert (
            conn.execute("SELECT product_repo_id FROM layers").fetchone()[0]
            == conn.execute("SELECT product_repo_id FROM product_repo").fetchone()[0]
        )


def test_cli_imports_layers_into_the_same_database_without_routing_options(
    tmp_path: Path,
) -> None:
    root, config, _ = setup(tmp_path)
    put(root, "findings/acm/cli/cli-findings-layer.json", layer())
    target = tmp_path / "target.sqlite"
    output = tmp_path / "cli-output"
    profile = tmp_path / "migration.yaml"
    profile.write_text(
        f"results-root: {root}\nconfig: {config}\noutput: {output}\n"
        f"database:\n  type: sqlite\n  path: {target}\n"
    )

    assert _migrate_script().main(["run", "--profile", str(profile)]) == 0
    with sqlite3.connect(target) as conn:
        assert conn.execute("SELECT count(*) FROM layers").fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM artifact_binding").fetchone()[0] == 0
    result = json.loads((output / "run" / "migration-result.json").read_text())
    assert result["ledger"]["status"] == "passed"
    assert result["migration_ready"]


def test_rejects_findings_without_repository(tmp_path: Path) -> None:
    root, config, output = setup(tmp_path)
    from test_migration_validation import report

    document = report()
    document["findings"][0]["fingerprint"] = "a" * 64
    put(root, "findings/acm/cli/cli-security-audit.json", document)
    result = migration.rehearse(
        root, config, str(tmp_path / "storage.sqlite"), output, database_type="sqlite"
    )
    assert result["issue_counts"] == {"unresolved_repository": 1}
    assert not result["migration_ready"]


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
