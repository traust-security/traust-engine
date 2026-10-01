"""Verify stored projection values before the contracts transaction commits."""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from collections.abc import Hashable, Mapping
from decimal import Decimal
from typing import Any

from traust_contracts.v1.storage import Store
from traust_contracts.v1.storage.store import SQLValue, storage_profiles

INSERT = re.compile(r"INSERT INTO (?:traust_storage\.)?(\w+)\s*\((.*?)\)\s*VALUES", re.S)
# Families whose projection writes a parent row plus child rows in a second table.
# The `layer` family projects directly into layer_event (its profile projection),
# so it needs no child entry here.
CHILD_TABLES = {
    "report": "report_finding",
    "validation": "validation_finding",
    "cloud-config-findings-current": "cloud_config_finding",
}


class ProjectionMismatch(ValueError):
    """The database did not retain exactly the authored projection's values."""


def _row_key(value: Any) -> Hashable:
    if isinstance(value, dict):
        return "object", tuple((key, _row_key(item)) for key, item in sorted(value.items()))
    if isinstance(value, list):
        return "array", tuple(map(_row_key, value))
    if isinstance(value, bool):
        return "boolean", value
    if isinstance(value, (int, float)):
        # JSONB may render 1.0 as 1; lexical precision remains in exact artifact evidence.
        return "number", Decimal(str(value))
    return type(value).__name__, value


class ProjectionCapture(Store):
    """Reuse contracts' mapping without executing its writes or duplicating its rules."""

    def __init__(self, conn: Any) -> None:
        super().__init__(conn)
        self.rows: dict[str, list[dict[str, SQLValue]]] = defaultdict(list)

    def _execute(self, sql: str, values: Mapping[str, SQLValue] | None = None) -> Any:
        match = INSERT.match(sql.strip())
        if match and values is not None:
            columns = {column.strip() for column in match[2].split(",")}
            if columns != set(values):
                raise ProjectionMismatch("Unsupported projection column mapping")
            self.rows[match[1]].append(dict(values))
            return None
        if sql.lstrip().upper().startswith("SELECT"):
            return super()._execute(sql, values)
        raise ProjectionMismatch("Unsupported projection statement")


class VerifiedSQLiteStore(Store):
    """Check SQLite's inserted projection before the contract store commits."""

    def __init__(self, conn: Any) -> None:
        super().__init__(conn)
        self.last_counts: dict[str, int] = {}

    def _project(
        self, artifact: str, document: dict[str, Any], digest: str, binding_id_value: str
    ) -> None:
        super()._project(artifact, document, digest, binding_id_value)
        capture = ProjectionCapture(self.conn)
        capture._project(artifact, document, digest, binding_id_value)
        tables = {storage_profiles()[artifact]["projection"], *capture.rows}
        if child := CHILD_TABLES.get(artifact):
            tables.add(child)
        counts: dict[str, int] = {}
        for table in sorted(tables):
            expected = capture.rows[table]
            if not expected:
                count = self.conn.execute(
                    f'SELECT count(*) FROM "{table}" WHERE binding_id=?', (binding_id_value,)
                ).fetchone()[0]
                if count:
                    raise ProjectionMismatch("Unexpected projection rows")
                counts[table] = 0
                continue
            columns = sorted(expected[0])
            selected = ", ".join(f'"{column}"' for column in columns)
            cursor = self.conn.execute(
                f'SELECT {selected} FROM "{table}" WHERE binding_id=?', (binding_id_value,)
            )
            actual = Counter(_row_key(dict(zip(columns, row, strict=True))) for row in cursor)
            normalized = [
                {
                    key: int(value) if isinstance(value, bool) else value
                    for key, value in row.items()
                }
                for row in expected
            ]
            if actual != Counter(map(_row_key, normalized)):
                raise ProjectionMismatch("SQLite projection values or multiplicity differ")
            counts[table] = len(expected)
        self.last_counts = counts


class VerifiedStore(Store):
    def __init__(self, conn: Any) -> None:
        super().__init__(conn)
        with conn.transaction():
            columns = conn.execute(
                "SELECT table_name, column_name FROM information_schema.columns "
                "WHERE table_schema='traust_storage' AND data_type IN ('json','jsonb')"
            ).fetchall()
        self.json_columns = set(columns)
        self.last_counts: dict[str, int] = {}

    def _project(
        self, artifact: str, document: dict[str, Any], digest: str, binding_id_value: str
    ) -> None:
        from psycopg import sql

        super()._project(artifact, document, digest, binding_id_value)
        capture = ProjectionCapture(self.conn)
        capture._project(artifact, document, digest, binding_id_value)
        tables = {storage_profiles()[artifact]["projection"], *capture.rows}
        if child := CHILD_TABLES.get(artifact):
            tables.add(child)
        counts: dict[str, int] = {}
        for table in sorted(tables):
            expected = capture.rows[table]
            if not expected:
                count = self.conn.execute(
                    sql.SQL("SELECT count(*) FROM traust_storage.{} WHERE binding_id=%s").format(
                        sql.Identifier(table)
                    ),
                    (binding_id_value,),
                ).fetchone()[0]
                if count:
                    raise ProjectionMismatch("Unexpected projection rows")
                counts[table] = 0
                continue
            columns = sorted(expected[0])
            cursor = self.conn.execute(
                sql.SQL("SELECT {} FROM traust_storage.{} WHERE binding_id=%s").format(
                    sql.SQL(", ").join(map(sql.Identifier, columns)), sql.Identifier(table)
                ),
                (binding_id_value,),
            )
            actual = Counter(_row_key(dict(zip(columns, row, strict=True))) for row in cursor)
            normalized = []
            for row in expected:
                normalized.append(
                    {
                        key: json.loads(value)
                        if (table, key) in self.json_columns and value is not None
                        else value
                        for key, value in row.items()
                    }
                )
            if actual != Counter(map(_row_key, normalized)):
                raise ProjectionMismatch(
                    "Projection values or multiplicity differ from source mapping"
                )
            counts[table] = len(expected)
        self.last_counts = counts
