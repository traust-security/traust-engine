"""Load an operator-selected empty database; never create, stamp, reset, or drop it."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from traust_contracts.v1.storage import Binding
from traust_contracts.v1.storage.sql import bootstrap_files

from traust_engine.corpus.migration_projection import VerifiedSQLiteStore, VerifiedStore

BUNDLE = ("migration-result.json", "issues.jsonl", "decisions.jsonl")


class TargetNotEmpty(ValueError):
    pass


class TargetInUse(ValueError):
    pass


def save_result(output: Path, result: dict[str, Any]) -> None:
    temporary = output / "migration-result.json.tmp"
    temporary.write_text(json.dumps(result, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    temporary.replace(output / "migration-result.json")


def save_decisions(output: Path, decisions: list[dict[str, Any]]) -> None:
    temporary = output / "decisions.jsonl.tmp"
    with temporary.open("w", encoding="utf-8") as stream:
        for decision in decisions:
            stream.write(json.dumps({"format_version": 1, **decision}, ensure_ascii=True) + "\n")
    temporary.replace(output / "decisions.jsonl")


@contextmanager
def acquire_run_lock(output: Path) -> Generator[None, None, None]:
    import fcntl

    descriptor = os.open(output, os.O_RDONLY)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise ValueError("Output directory is in use") from None
        yield
    finally:
        os.close(descriptor)


class SQLiteRehearsalDatabase:
    """Create a fresh SQLite artifact target without modifying an existing database."""

    checks = (
        "evidence_pointer",
        "binding_context",
        "projection_values_and_multiplicity",
        "row_counts",
    )

    def __init__(self, path: Path) -> None:
        self.path = path.resolve()
        with self.path.open("xb"):
            pass
        self.conn = sqlite3.connect(self.path, isolation_level=None)
        self.name = str(self.path)
        self.store = VerifiedSQLiteStore(self.conn)
        self.last_binding = ""

    def initialize(self) -> None:
        self.store.init()

    def ingest(self, artifact: str, payload: bytes, binding: Binding) -> Any:
        saved = self.store.ingest(artifact, payload, binding)
        if saved.digest != hashlib.sha256(payload).hexdigest():
            raise RuntimeError("Stored evidence digest differs from original bytes")
        pointer = self.conn.execute(
            "SELECT byte_size FROM artifact_evidence WHERE digest=?", (saved.digest,)
        ).fetchone()
        if pointer is None or pointer[0] != len(payload):
            raise RuntimeError("Stored evidence pointer differs from original bytes")
        record = self.store.get_binding(saved.binding_id)
        if record.artifact_digest != saved.digest or record.artifact_name != artifact:
            raise RuntimeError("Stored artifact binding differs from declared context")
        if record.binding != binding:
            raise RuntimeError("Stored binding differs from declared context")
        self.last_binding = saved.binding_id
        return saved

    @property
    def projection_counts(self) -> dict[str, int]:
        return self.store.last_counts

    def check_healthy(self) -> None:
        if self.conn.in_transaction:
            raise RuntimeError("Database transaction was not rolled back")
        self.conn.execute("SELECT 1")

    def counts(self) -> dict[str, int]:
        tables = [
            row[0]
            for row in self.conn.execute("SELECT name FROM sqlite_schema WHERE type='table'")
            if not row[0].startswith("sqlite_")
        ]
        return {
            table: self.conn.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0]
            for table in tables
            if table == "artifact_evidence"
            or any(
                row[1] == "binding_id" for row in self.conn.execute(f'PRAGMA table_info("{table}")')
            )
        }

    def close(self) -> None:
        self.conn.close()


class RehearsalDatabase:
    def __init__(self, dsn: str) -> None:
        import psycopg

        self.conn = psycopg.connect(dsn, autocommit=True, connect_timeout=5)
        self.name = self.conn.info.dbname
        self.store: VerifiedStore | None = None

    def initialize(self) -> None:
        locked = self.conn.execute(
            "SELECT pg_try_advisory_lock(hashtext('traust:artifact-migration'))"
        ).fetchone()[0]
        if not locked:
            raise TargetInUse("Another migration is using this database")
        occupied = self.conn.execute(
            "SELECT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema' "
            "AND c.relkind IN ('r','p','v','m','S','f'))"
        ).fetchone()[0]
        if occupied:
            raise TargetNotEmpty("Target must be an empty dedicated database; nothing was reset")
        with self.conn.transaction():
            for path in bootstrap_files("postgres"):
                if path.parent.name != "views":
                    self.conn.execute(path.read_text(encoding="utf-8"))
        self.store = VerifiedStore(self.conn)

    def ingest(self, artifact: str, payload: bytes, binding: Binding) -> Any:
        assert self.store is not None
        saved = self.store.ingest(artifact, payload, binding)
        with self.conn.transaction():
            if saved.digest != hashlib.sha256(payload).hexdigest():
                raise RuntimeError("Stored evidence digest differs from original bytes")
            pointer = self.conn.execute(
                "SELECT byte_size FROM traust_storage.artifact_evidence WHERE digest=%s",
                (saved.digest,),
            ).fetchone()
            if pointer is None or pointer[0] != len(payload):
                raise RuntimeError("Stored evidence pointer differs from original bytes")
            row = self.store._binding_row(saved.binding_id)
            expected = (
                saved.digest,
                artifact,
                binding.scope_id,
                binding.subject_id,
                binding.run_id,
                binding.layer_id,
                binding.supersedes_binding_id,
            )
            if row is None or row[:7] != expected:
                raise RuntimeError("Stored artifact binding differs from declared context")
        return saved

    @property
    def projection_counts(self) -> dict[str, int]:
        assert self.store is not None
        return self.store.last_counts

    def check_healthy(self) -> None:
        if self.conn.closed or self.conn.info.transaction_status != 0:
            raise RuntimeError("Database unavailable or record rollback failed")
        self.conn.execute("SELECT 1")

    def counts(self) -> dict[str, int]:
        from psycopg import sql

        tables = self.conn.execute(
            "SELECT table_name FROM information_schema.columns "
            "WHERE table_schema='traust_storage' AND column_name='binding_id'"
        ).fetchall()
        names = {name for (name,) in tables} | {"artifact_evidence"}
        return {
            name: self.conn.execute(
                sql.SQL("SELECT count(*) FROM traust_storage.{}").format(sql.Identifier(name))
            ).fetchone()[0]
            for name in sorted(names)
        }

    def close(self) -> None:
        self.conn.close()
