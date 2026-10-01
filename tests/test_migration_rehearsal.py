"""Artifact-first selection, continuation, conservation, and a retained database."""

from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from traust_contracts.v1.storage import Binding, Store
from traust_contracts.v1.storage.sql import bootstrap_files, bootstrap_statements

from traust_engine.corpus import migration_rehearsal as migration
from traust_engine.corpus.migration_database import (
    BUNDLE,
    RehearsalDatabase,
    acquire_run_lock,
    save_result,
)


class MemoryDatabase(RehearsalDatabase):
    def __init__(self, _dsn: str) -> None:
        self.name = "memory"
        self.conn = sqlite3.connect(":memory:")
        self.store = Store(self.conn)
        self.last_binding = ""

    def initialize(self) -> None:
        for path in bootstrap_files("sqlite"):
            if path.parent.name != "views":
                for statement in bootstrap_statements("sqlite", path):
                    self.conn.execute(statement)
        self.conn.commit()

    def ingest(self, artifact: str, payload: bytes, binding: Binding) -> Any:
        import hashlib

        saved = self.store.ingest(artifact, payload, binding)
        assert saved.digest == hashlib.sha256(payload).hexdigest()
        assert self.conn.execute(
            "SELECT byte_size FROM artifact_evidence WHERE digest=?", (saved.digest,)
        ).fetchone()[0] == len(payload)
        assert self.store.get_binding(saved.binding_id).binding == binding
        self.last_binding = saved.binding_id
        return saved

    def counts(self) -> dict[str, int]:
        tables = [
            row[0] for row in self.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        ]
        return {
            table: self.conn.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0]
            for table in tables
            if table == "artifact_evidence"
            or any(
                row[1] == "binding_id" for row in self.conn.execute(f'PRAGMA table_info("{table}")')
            )
        }

    @property
    def projection_counts(self) -> dict[str, int]:
        return {
            table: self.conn.execute(
                f'SELECT count(*) FROM "{table}" WHERE binding_id=?', (self.last_binding,)
            ).fetchone()[0]
            for table in self.counts()
            if table not in {"artifact_evidence", "artifact_binding"}
        }


def layer() -> dict[str, Any]:
    return {
        "metadata": {
            "audit_report": "report.json",
            "repository": "https://example.test/r",
            "created": "2026-01-01T00:00:00Z",
            "harness_version": "0.1.0",
        },
        "events": [],
        "needs_review": [],
    }


def setup(tmp_path: Path, extra: str = "") -> tuple[Path, Path, Path]:
    root = tmp_path / "sources"
    root.mkdir()
    config = tmp_path / "config.yaml"
    config.write_text("version: 1\ntrees: {}\n" + extra)
    return root, config, tmp_path / "run"


def put(root: Path, relative: str, value: Any) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")
    return path


def test_continues_invalid_and_unknown_inputs_without_census_filter(tmp_path: Path) -> None:
    root, config, output = setup(tmp_path)
    paths = [
        put(root, "new-team/bad-findings-layer.json", {}),
        put(root, "unknown.json", {}),
        put(root, "benchmarks/_manifest/good-findings-layer.json", layer()),
    ]
    before = {path: path.read_bytes() for path in paths}
    result = migration.rehearse(root, config, "", output, database_factory=MemoryDatabase)
    assert result["status"] == "failed"
    assert result["diagnostics_complete"]
    assert result["outcomes"] == {"rejected": 1, "unselected": 1, "ingested": 1}
    assert result["issue_counts"] == {"contract_validation": 3}
    assert result["reconciliation"]["loaded_artifacts_verified"]
    assert not result["reconciliation"]["passed"]
    assert result["database_retained"]
    assert {p.name for p in output.iterdir()} == set(BUNDLE)
    assert before == {p: p.read_bytes() for p in paths}


def test_refuted_register_preserves_evidence_digest_binding_and_projection(tmp_path: Path) -> None:
    root, config, output = setup(tmp_path)
    document = {
        "source": "repo-triage.json",
        "generated_at": "2026-01-01T00:00:00Z",
        "entries": [
            {
                "finding_ref": "FIND-001",
                "title": "Refuted claim",
                "refute_reasons": ["misread_code"],
                "tier": "countersign",
                "evidence_refs": ["main.go:10"],
                "asserted_at": "2026-01-01T00:00:00Z",
                "asserted_by": "triage/1.0.0",
                "note": "Execution evidence overrides.",
            }
        ],
    }
    source = put(root, "org/repo/repo-refuted-register.json", document)

    class InspectingMemoryDatabase(MemoryDatabase):
        evidence: int
        row: tuple[str, str, str]

        def close(self) -> None:
            digest = migration.digest(source)
            self.evidence = self.conn.execute(
                "SELECT byte_size FROM artifact_evidence WHERE digest=?", (digest,)
            ).fetchone()[0]
            self.row = self.conn.execute(
                "SELECT artifact_digest, source, entries FROM refuted_register"
            ).fetchone()
            super().close()

    database = InspectingMemoryDatabase("")
    result = migration.rehearse(root, config, "", output, database_factory=lambda _dsn: database)
    assert result["status"] == "passed"
    assert result["migration_ready"]
    digest = migration.digest(source)
    assert database.evidence == len(source.read_bytes())
    assert database.row[:2] == (digest, "repo-triage.json")
    assert json.loads(database.row[2]) == document["entries"]
    assert result["reconciliation"]["expected_rows"]["refuted_register"] == 1


def test_operator_excludes_scratch_by_config_before_routing(tmp_path: Path) -> None:
    root, config, output = setup(
        tmp_path,
        'migration:\n  exclude: ["_manifest/**", "**/candidate.json", "bundle/aggregate-findings-layer.json"]\n',
    )
    put(root, "_manifest/scratch-triage.json", {})
    put(root, "team-a/service/artifacts/candidate.json", {})
    put(root, "bundle/aggregate-findings-layer.json", {})
    alias_target = root / "elsewhere"
    alias_target.mkdir()
    (root / "_orgs").mkdir()
    (root / "_orgs/org").symlink_to(alias_target)
    result = migration.rehearse(root, config, "", output, database_factory=MemoryDatabase)
    assert result["status"] == "failed"  # no selected inputs is intentionally blocking
    assert result["outcomes"] == {"excluded": 4}
    assert result["excluded_by_rule"] == {
        "_manifest/**": 1,
        "**/candidate.json": 1,
        "bundle/aggregate-findings-layer.json": 1,
        "navigation_alias": 1,
    }
    decisions = [json.loads(line) for line in (output / "decisions.jsonl").read_text().splitlines()]
    assert all(item["reason"] for item in decisions)
    assert all(
        "source_digest" in item for item in decisions if item["reason"] != "navigation_alias"
    )
    assert result["issue_counts"] == {"no_selected_inputs": 1}


def test_explicit_exclusions_and_no_sqlite_or_view_gate(tmp_path: Path) -> None:
    root, config, output = setup(tmp_path, 'migration:\n  exclude: ["ecoengg-findings/**"]\n')
    put(root, "ecoengg-findings/bad.json", {})
    put(root, "somebody-else/good-findings-layer.json", layer())
    result = migration.rehearse(root, config, "", output, database_factory=MemoryDatabase)
    assert result["status"] == "passed"
    assert result["migration_ready"]
    assert result["outcomes"] == {"excluded": 1, "ingested": 1}
    assert result["excluded_by_rule"] == {"ecoengg-findings/**": 1}
    assert result["reconciliation"]["passed"]
    assert result["views"] == "deferred"
    assert result["comparison"] == {"status": "not_requested"}
    assert result["issue_count"] == 0
    assert "database_handle" not in result
    assert "cleanup" not in result


def test_preview_selects_hidden_repository_without_guessing_scratch(tmp_path: Path) -> None:
    root, config, output = setup(tmp_path)
    put(root, ".hidden/repo/repo-findings-layer.json", layer())
    (root / ".hidden/repo/scratch.json").write_text("not JSON")
    result = migration.preview(root, config, output, route_layers_to_ledger=True)
    assert result["outcomes"] == {"selected": 1, "unselected": 1}
    assert result["issue_count"] == 0
    decisions = [json.loads(row) for row in (output / "decisions.jsonl").read_text().splitlines()]
    selected = next(item for item in decisions if item["decision"] == "selected")
    assert selected["layer_id"] == "corpus:layer:.hidden/repo/repo"
    assert selected["namespace"] == "traust_ledger"


def test_preview_rejects_duplicate_ledger_identity(tmp_path: Path) -> None:
    root, config, output = setup(tmp_path)
    put(root, "org/repo-findings-layer.json", layer())
    put(root, "org/repo-layer.json", layer())
    result = migration.preview(root, config, output, route_layers_to_ledger=True)
    assert result["issue_counts"] == {"ambiguous_binding": 1}
    assert result["outcomes"] == {"selected": 1, "blocked": 1}
    decisions = [json.loads(row) for row in (output / "decisions.jsonl").read_text().splitlines()]
    assert all(row["format_version"] == 1 for row in decisions)


def test_layer_route_is_not_a_storage_binding_when_delegated(tmp_path: Path) -> None:
    root, config, output = setup(tmp_path)
    put(root, "org/a/repo-findings-layer.json", layer())
    put(root, "org/b/repo-findings-layer.json", layer())
    put(root, "scratch.json", {"artifact": "layer", "events": []})
    target = tmp_path / "target.sqlite"
    result = migration.rehearse(
        root, config, str(target), output, database_type="sqlite", route_layers_to_ledger=True
    )
    assert result["status"] == "passed"
    assert not result["migration_ready"]
    assert result["ledger"] == {"status": "not_run", "selected": 2}
    assert result["outcomes"] == {"delegated": 2, "unselected": 1}
    with sqlite3.connect(target) as conn:
        assert conn.execute("SELECT count(*) FROM artifact_binding").fetchone()[0] == 0
    decisions = [json.loads(row) for row in (output / "decisions.jsonl").read_text().splitlines()]
    assert {row["layer_id"] for row in decisions if row["decision"] == "delegated"} == {
        "corpus:layer:org/a/repo",
        "corpus:layer:org/b/repo",
    }
    assert all(row["namespace"] == "traust_ledger" for row in decisions if "layer_id" in row)


def test_sqlite_ingests_evidence_pointer_without_reusing_target(tmp_path: Path) -> None:
    root, config, output = setup(tmp_path)
    source = put(root, "team/good-findings-layer.json", layer())
    target = tmp_path / "artifact-store.sqlite"
    result = migration.rehearse(root, config, str(target), output, database_type="sqlite")
    assert result["status"] == "passed"
    assert result["reconciliation"]["checks"] == [
        "evidence_pointer",
        "binding_context",
        "projection_values_and_multiplicity",
        "row_counts",
    ]
    with sqlite3.connect(target) as conn:
        assert conn.execute("SELECT byte_size FROM artifact_evidence").fetchone()[0] == len(
            source.read_bytes()
        )
    retry = migration.rehearse(
        root, config, str(target), tmp_path / "retry", database_type="sqlite"
    )
    assert retry["status"] == "blocked"
    assert retry["issue_counts"] == {"systemic_failure": 1}


def test_sqlite_report_projection_preserves_json_fields(tmp_path: Path) -> None:
    from test_migration_validation import report

    root, config, output = setup(tmp_path)
    document = report()
    document["findings"][0]["fingerprint"] = "a" * 64
    source = put(root, "org/repo/repo-security-audit.json", document)
    target = tmp_path / "target.sqlite"
    result = migration.rehearse(root, config, str(target), output, database_type="sqlite")
    assert result["status"] == "passed", (output / "issues.jsonl").read_text()
    with sqlite3.connect(target) as conn:
        assert conn.execute("SELECT count(*) FROM report_finding").fetchone()[0] == 1
        assert conn.execute("SELECT byte_size FROM artifact_evidence").fetchone()[0] == len(
            source.read_bytes()
        )


def test_sqlite_duplicate_projection_rolls_back_and_continues(tmp_path: Path) -> None:
    root, config, output = setup(tmp_path)
    event = {
        "event_id": "a" * 64,
        "finding_ref": "F-1",
        "recorded_at": "2026-01-01T00:00:00Z",
        "source": {
            "type": "interactive",
            "ref": "https://example.test/e",
            "actor": {"kind": "human"},
        },
        "disposition": {"validity": "confirmed"},
        "rationale": "Confirmed by independent review.",
    }
    bad = layer()
    bad["events"] = [event, event]
    put(root, "a-findings-layer.json", bad)
    put(root, "b-findings-layer.json", layer())
    target = tmp_path / "target.sqlite"
    result = migration.rehearse(root, config, str(target), output, database_type="sqlite")
    assert result["outcomes"] == {"rejected": 1, "ingested": 1}
    assert result["issue_counts"] == {"ingest_rejected": 1}
    with sqlite3.connect(target) as conn:
        assert conn.execute("SELECT count(*) FROM artifact_evidence").fetchone()[0] == 1


def test_preview_validates_without_database_and_emits_receipts(tmp_path: Path) -> None:
    root, config, output = setup(tmp_path)
    source = put(root, "team/good-findings-layer.json", layer())
    put(root, "team/bad-findings-layer.json", {})
    before = source.read_bytes()
    result = migration.preview(root, config, output)
    assert result["status"] == "planned"
    assert not result["migration_ready"]
    assert result["outcomes"] == {"selected": 1, "rejected": 1}
    assert result["database_retained"] is False
    assert source.read_bytes() == before
    assert {p.name for p in output.iterdir()} == set(BUNDLE)


def test_decisions_record_each_path_and_explicit_filter_policy(tmp_path: Path) -> None:
    root, config, output = setup(tmp_path)
    put(root, "_manifest/state.json", {})
    put(root, "team/good-findings-layer.json", layer())
    result = migration.rehearse(root, config, "", output, database_factory=MemoryDatabase)
    decisions = [json.loads(line) for line in (output / "decisions.jsonl").read_text().splitlines()]
    assert len(decisions) == result["inventory"]["candidate_paths"] == 2
    by_path = {entry["source_file"]: entry for entry in decisions}
    assert by_path["_manifest/state.json"]["decision"] == "unselected"
    assert by_path["_manifest/state.json"]["reason"] == "no_filename_route"
    assert by_path["team/good-findings-layer.json"]["decision"] == "ingested"
    assert len(by_path["team/good-findings-layer.json"]["source_digest"]) == 64
    assert result["excluded_by_rule"] == {}


def test_scope_configuration_does_not_silently_filter_a_tree(tmp_path: Path) -> None:
    root, config, output = setup(tmp_path, "scope: {mode: explicit, id: local}\n")
    put(root, "unregistered/a-findings-layer.json", layer())
    result = migration.rehearse(root, config, "", output, database_factory=MemoryDatabase)
    assert result["issue_counts"] == {"unresolved_binding": 1}
    assert result["outcomes"] == {"blocked": 1}


def test_source_drift_stops_the_run(tmp_path: Path) -> None:
    root, config, output = setup(tmp_path)
    source = put(root, "a-findings-layer.json", layer())
    put(root, "b-findings-layer.json", layer())

    class DriftingDatabase(MemoryDatabase):
        def ingest(self, artifact: str, payload: bytes, binding: Binding) -> Any:
            saved = super().ingest(artifact, payload, binding)
            source.write_text("{}")
            return saved

    result = migration.rehearse(root, config, "", output, database_factory=DriftingDatabase)
    assert result["status"] == "blocked"
    assert not result["diagnostics_complete"]
    assert not result["migration_ready"]
    assert result["issue_counts"] == {"systemic_failure": 1}


def test_budget_exhaustion_saves_two_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root, config, output = setup(tmp_path)
    put(root, "a-findings-layer.json", layer())
    clock = iter((0, 2))
    monkeypatch.setattr(migration.time, "monotonic", lambda: next(clock))
    result = migration.rehearse(
        root, config, "", output, max_seconds=1, database_factory=MemoryDatabase
    )
    assert result["status"] == "blocked"
    assert {p.name for p in output.iterdir()} == set(BUNDLE)


def test_refuses_output_inside_sources(tmp_path: Path) -> None:
    root, config, _ = setup(tmp_path)
    with pytest.raises(ValueError, match="outside"):
        migration.rehearse(root, config, "", root / "run")


def test_active_output_lock_survives_atomic_replacement(tmp_path: Path) -> None:
    with acquire_run_lock(tmp_path):
        save_result(tmp_path, {"run_state": "running"})
        save_result(tmp_path, {"run_state": "running", "issue_count": 100})
        with pytest.raises(ValueError, match="in use"), acquire_run_lock(tmp_path):
            pass
    assert {p.name for p in tmp_path.iterdir()} == {"migration-result.json"}


def test_optional_sqlite_is_readonly_and_not_required_for_success(tmp_path: Path) -> None:
    root, config, output = setup(tmp_path)
    put(root, "a-findings-layer.json", layer())
    db = tmp_path / "findings.db"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE findings (id TEXT)")
        conn.execute("INSERT INTO findings VALUES ('one')")
    before = db.read_bytes()
    result = migration.rehearse(
        root, config, "", output, findings_db=db, database_factory=MemoryDatabase
    )
    assert result["status"] == "passed"
    assert result["comparison"]["table_counts"] == {"findings": 1}
    assert not result["comparison"]["parity_checked"]
    assert db.read_bytes() == before


def test_unavailable_optional_comparison_does_not_fail_artifact_migration(tmp_path: Path) -> None:
    root, config, output = setup(tmp_path)
    put(root, "a-findings-layer.json", layer())
    result = migration.rehearse(
        root,
        config,
        "",
        output,
        findings_db=tmp_path / "missing.db",
        database_factory=MemoryDatabase,
    )
    assert result["status"] == "passed"
    assert result["blocking_issue_count"] == 0
    assert result["issue_counts"] == {"comparison_unavailable": 1}


@pytest.fixture
def postgres_target() -> Iterator[tuple[str, str]]:
    psycopg = pytest.importorskip("psycopg")
    from psycopg import sql
    from psycopg.conninfo import make_conninfo

    admin_dsn = os.environ.get("TRAUST_TEST_ADMIN_DSN")
    if not admin_dsn:
        pytest.skip("TRAUST_TEST_ADMIN_DSN is required")
    name = "traust_test_" + uuid4().hex
    with psycopg.connect(admin_dsn, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
        try:
            yield make_conninfo(admin_dsn, dbname=name), name
        finally:
            admin.execute(sql.SQL("DROP DATABASE {}").format(sql.Identifier(name)))


@pytest.mark.integration
def test_postgres_retention_projection_verification_and_nonempty_guard(
    tmp_path: Path, postgres_target: tuple[str, str]
) -> None:
    import psycopg

    root, config, output = setup(tmp_path)
    put(root, "a-findings-layer.json", {})
    source = put(root, "b-findings-layer.json", layer())
    dsn, name = postgres_target
    result = migration.rehearse(root, config, dsn, output)
    assert result["diagnostics_complete"], (output / "issues.jsonl").read_text()
    assert result["outcomes"] == {"rejected": 1, "ingested": 1}
    assert result["reconciliation"]["loaded_artifacts_verified"]
    assert result["database"] == name
    assert {p.name for p in output.iterdir()} == set(BUNDLE)
    with psycopg.connect(dsn) as conn:
        assert conn.execute("SELECT byte_size FROM traust_storage.artifact_evidence").fetchone()[
            0
        ] == len(source.read_bytes())
        assert (
            conn.execute(
                "SELECT shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()"
            ).fetchone()[0]
            is None
        )
        assert (
            conn.execute(
                "SELECT count(*) FROM pg_views WHERE schemaname='traust_storage'"
            ).fetchone()[0]
            == 0
        )
    retry = migration.rehearse(root, config, dsn, tmp_path / "retry")
    assert retry["status"] == "blocked"
    with psycopg.connect(dsn) as conn:
        assert (
            conn.execute("SELECT count(*) FROM traust_storage.artifact_evidence").fetchone()[0] == 1
        )


@pytest.mark.integration
def test_postgres_projection_loss_rolls_back_and_later_record_continues(
    tmp_path: Path, postgres_target: tuple[str, str]
) -> None:
    root, config, output = setup(tmp_path)
    bad = layer()
    event = {
        "event_id": "a" * 64,
        "finding_ref": "F-1",
        "recorded_at": "2026-01-01T00:00:00Z",
        "source": {
            "type": "interactive",
            "ref": "https://example.test/e",
            "actor": {"kind": "human"},
        },
        "disposition": {"validity": "confirmed"},
        "rationale": "Confirmed by independent review.",
    }
    bad["events"] = [event, event]
    put(root, "a-findings-layer.json", bad)
    put(root, "b-findings-layer.json", layer())
    result = migration.rehearse(root, config, postgres_target[0], output)
    assert result["diagnostics_complete"], (output / "issues.jsonl").read_text()
    assert result["outcomes"] == {"rejected": 1, "ingested": 1}
    assert result["issue_counts"] == {"ingest_rejected": 1}
    assert result["reconciliation"]["actual_rows"]["artifact_evidence"] == 1


@pytest.mark.integration
def test_postgres_layer_event_nul_is_escaped_only_in_projection(
    tmp_path: Path, postgres_target: tuple[str, str]
) -> None:
    import psycopg

    root, config, output = setup(tmp_path)
    document = layer()
    document["events"] = [
        {
            "event_id": "a" * 64,
            "finding_ref": "F-1",
            "recorded_at": "2026-01-01T00:00:00Z",
            "source": {
                "type": "interactive",
                "ref": "https://example.test/e",
                "actor": {"kind": "human"},
            },
            "disposition": {"validity": "confirmed"},
            "rationale": "argv\x00--flag=value",
        }
    ]
    source = put(root, "a-findings-layer.json", document)

    result = migration.rehearse(root, config, postgres_target[0], output)

    assert result["status"] == "passed"
    assert result["migration_ready"]
    with psycopg.connect(postgres_target[0]) as conn:
        rationale = conn.execute("SELECT rationale FROM traust_storage.layer_event").fetchone()[0]
        byte_size = conn.execute(
            "SELECT byte_size FROM traust_storage.artifact_evidence"
        ).fetchone()[0]
    assert rationale == r"argv\u0000--flag=value"
    assert byte_size == len(source.read_bytes())


@pytest.mark.integration
def test_postgres_jsonb_nul_rolls_back_without_stripping_and_continues(
    tmp_path: Path, postgres_target: tuple[str, str]
) -> None:
    from test_migration_validation import report

    root, config, output = setup(tmp_path)
    bad = report()
    bad["findings"][0]["fingerprint"] = "a" * 64
    bad["metadata"]["additional"]["probe"] = "before\x00after"
    source = put(root, "a-security-audit.json", bad)
    original = source.read_bytes()
    put(root, "b-findings-layer.json", layer())
    result = migration.rehearse(root, config, postgres_target[0], output)
    assert result["diagnostics_complete"], (output / "issues.jsonl").read_text()
    assert result["outcomes"] == {"rejected": 1, "ingested": 1}
    assert result["issue_counts"] == {"ingest_rejected": 1}
    rows = result["reconciliation"]["actual_rows"]
    assert rows["artifact_evidence"] == rows["artifact_binding"] == 1
    assert rows["report"] == rows["report_finding"] == 0
    assert source.read_bytes() == original
