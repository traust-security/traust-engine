"""Read-only, fail-fast artifact validation before migration writes."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any

from traust_contracts.v1.storage.store import validators


def _pointer(parts: Iterable[object]) -> str:
    return "".join("/" + str(part).replace("~", "~0").replace("/", "~1") for part in parts)


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("duplicate JSON property")
        document[key] = value
    return document


def _constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


@dataclass(frozen=True)
class MigrationIssue:
    source_file: str
    artifact: str
    classification: str | None
    error_class: str
    factual_message: str
    source_digest: str | None = None
    source_json_pointer: str = ""
    schema_rule: str = ""
    missing_fields: tuple[str, ...] = ()
    value_type: str | None = None
    value_sha256: str | None = None
    value_length: int | None = None
    is_null: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"status": "failed", **asdict(self)}


class MigrationValidationError(ValueError):
    def __init__(self, issue: MigrationIssue, *others: MigrationIssue) -> None:
        self.issue = issue
        self.issues = (issue, *others)
        super().__init__(issue.factual_message)


@dataclass(frozen=True)
class ValidatedArtifact:
    path: Path
    artifact: str
    payload: bytes
    digest: str


class NumberRepresentationError(ValueError):
    pass


def _float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or Decimal(str(parsed)) != Decimal(value):
        raise NumberRepresentationError("JSON number cannot round-trip through the current parser")
    return parsed


def parse_document(payload: bytes) -> Any:
    return json.loads(
        payload, object_pairs_hook=_object, parse_constant=_constant, parse_float=_float
    )


def validate_artifact(
    path: Path, artifact: str, *, collect_all: bool = False, payload: bytes | None = None
) -> ValidatedArtifact:
    """Return original validated bytes or payload-safe issues; never repair input.

    Diagnostic rehearsals collect all schema errors and quarantine the artifact.
    Success covers this artifact only, not migration readiness or mapping parity.
    """
    validator = validators().get(artifact)
    if validator is None:
        raise MigrationValidationError(
            MigrationIssue(
                str(path), artifact, "mapping_bug", "unknown_contract", "Unknown artifact contract."
            )
        )
    try:
        if payload is None:
            payload = path.read_bytes()
    except OSError:
        raise MigrationValidationError(
            MigrationIssue(
                str(path),
                artifact,
                "source_defect",
                "unreadable_source",
                "Source file cannot be read; migration must not proceed.",
            )
        ) from None
    digest = hashlib.sha256(payload).hexdigest()
    try:
        document = parse_document(payload)
    except NumberRepresentationError as error:
        raise MigrationValidationError(
            MigrationIssue(str(path), artifact, None, "number_representation", str(error), digest)
        ) from None
    except (ValueError, UnicodeError):
        raise MigrationValidationError(
            MigrationIssue(
                str(path),
                artifact,
                "source_defect",
                "invalid_json",
                "Expected valid JSON without duplicate properties or non-finite numbers.",
                digest,
            )
        ) from None
    issues: list[MigrationIssue] = []
    for error in validator.iter_errors(document):
        missing = (
            tuple(key for key in error.validator_value if key not in error.instance)
            if error.validator == "required" and isinstance(error.instance, dict)
            else ()
        )
        value = json.dumps(error.instance, ensure_ascii=True, separators=(",", ":")).encode()
        message = (
            "Required fields missing: " + ", ".join(missing)
            if missing
            else f"Contract rule failed: {error.validator}"
        )
        issues.append(
            MigrationIssue(
                source_file=str(path),
                artifact=artifact,
                classification=None,
                error_class="contract_validation",
                factual_message=message,
                source_digest=digest,
                source_json_pointer=_pointer(error.absolute_path),
                schema_rule=f"{artifact}.schema.json#{_pointer(error.absolute_schema_path)}",
                missing_fields=missing,
                value_type=type(error.instance).__name__,
                value_sha256=hashlib.sha256(value).hexdigest(),
                value_length=len(value),
                is_null=error.instance is None,
            )
        )
        if not collect_all:
            break
    if issues:
        raise MigrationValidationError(*issues)
    return ValidatedArtifact(path, artifact, payload, digest)
