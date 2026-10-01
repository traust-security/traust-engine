"""Migration source checks never repair, coerce, or disclose finding payloads."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from traust_engine.corpus.migration_validation import (
    MigrationValidationError,
    parse_document,
    validate_artifact,
)


def report() -> dict:
    levels = ("critical", "high", "medium", "low", "informational")
    return {
        "title": "Synthetic security audit",
        "metadata": {
            "date": "2026-01-01",
            "scope": "Synthetic fixture repository",
            "additional": {"harness_version": "0.1.0-fixture"},
        },
        "executive_summary": {
            "prose": "Synthetic audit fixture. " * 4,
            "severity_counts": {level: int(level == "high") for level in levels},
        },
        "severity_criteria": [
            {"level": level, "definition": "Synthetic severity definition."} for level in levels
        ],
        "findings": [
            {
                "id": "FIND-001",
                "title": "Synthetic finding",
                "severity": "high",
                "cwes": ["CWE-79"],
                "locations": [{"path": "src/example.py"}],
                "description": "PRIVATE-FINDING-CONTENT " * 4,
                "remediation": "Apply the synthetic fix.",
            }
        ],
        "findings_summary": [
            {
                "severity": level,
                "count": int(level == "high"),
                "finding_ids": ["FIND-001"] if level == "high" else [],
            }
            for level in levels
        ],
        "remediation_roadmap": [
            {
                "priority": "high",
                "action": "Apply the synthetic fix.",
                "addresses": ["FIND-001"],
            }
        ],
    }


def test_missing_fingerprint_blocks_then_corrected_fixture_passes(tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    document = report()
    original = json.dumps(document, indent=2).encode() + b"\n"
    path.write_bytes(original)
    with pytest.raises(MigrationValidationError) as caught:
        validate_artifact(path, "report")
    issue = caught.value.issue
    assert issue.missing_fields == ("fingerprint",)
    assert issue.source_json_pointer == "/findings/0"
    assert issue.schema_rule.endswith("/required")
    assert issue.source_digest == hashlib.sha256(original).hexdigest()
    assert "PRIVATE-FINDING-CONTENT" not in json.dumps(issue.to_dict())
    assert path.read_bytes() == original

    document["findings"][0]["fingerprint"] = "a" * 64
    repaired = tmp_path / "corrected-fixture.json"
    repaired.write_text(json.dumps(document, indent=4) + "\n")
    validated = validate_artifact(repaired, "report")
    assert validated.payload == repaired.read_bytes()
    assert validated.digest == hashlib.sha256(validated.payload).hexdigest()
    assert path.read_bytes() == original


@pytest.mark.parametrize("payload", [b"{", b"\xff", b'{"x":1,"x":2}', b'{"x":NaN}'])
def test_invalid_json_fails_without_modification(tmp_path: Path, payload: bytes) -> None:
    path = tmp_path / "invalid.json"
    path.write_bytes(payload)
    with pytest.raises(MigrationValidationError) as caught:
        validate_artifact(path, "report")
    assert caught.value.issue.error_class == "invalid_json"
    assert path.read_bytes() == payload


def test_missing_source_is_not_skipped(tmp_path: Path) -> None:
    with pytest.raises(MigrationValidationError) as caught:
        validate_artifact(tmp_path / "missing.json", "report")
    assert caught.value.issue.error_class == "unreadable_source"
    assert not list(tmp_path.iterdir())


def test_unknown_contract_is_mapping_failure(tmp_path: Path) -> None:
    with pytest.raises(MigrationValidationError) as caught:
        validate_artifact(tmp_path / "missing.json", "unknown-family")
    assert caught.value.issue.classification == "mapping_bug"


@pytest.mark.parametrize("number", ["1e309", "1e-999", "0.100000000000000000001"])
def test_numeric_parser_limits_do_not_blame_or_rewrite_sources(tmp_path: Path, number: str) -> None:
    document = report()
    document["findings"][0]["fingerprint"] = "a" * 64
    document["metadata"]["additional"]["score"] = "NUMBER"
    original = json.dumps(document).replace('"NUMBER"', number).encode()
    path = tmp_path / "report.json"
    path.write_bytes(original)
    with pytest.raises(MigrationValidationError) as caught:
        validate_artifact(path, "report")
    assert caught.value.issue.error_class == "number_representation"
    assert caught.value.issue.classification is None
    assert path.read_bytes() == original


def test_numeric_parser_accepts_lossless_decimal_spellings() -> None:
    assert parse_document(b"[0.1, 1.000, 1e100, 123456789012345678901234567890]") == [
        0.1,
        1.0,
        1e100,
        123456789012345678901234567890,
    ]
