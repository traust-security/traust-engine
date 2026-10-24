"""Scanner findings retain contract metadata without claiming scanner IDs are domain identity."""

from __future__ import annotations

import pytest
from traust_core.v1.errors import DocumentError
from traust_core.v1.models.artifacts import AdapterResultArtifact

from traust_engine.adapters import gitleaks, grype
from traust_engine.adapters._contract_bridge import build_adapter_result


def finding() -> dict:
    return {
        "id": "SAMPLE-abcdef0-001",
        "title": "Synthetic scanner finding",
        "severity": "high",
        "cwes": ["CWE-79"],
        "locations": [{"path": "src/example.py", "lines": "12"}],
        "description": "A synthetic scanner observation retaining the original source claim and its context.",
        "remediation": "Validate untrusted input at the actual processing boundary.",
    }


def test_complete_adapter_evidence_survives_typed_conversion_and_artifact_admission():
    source = {
        **finding(),
        "kind": "vulnerability",
        "validation_status": "confirmed",
        "source_findings": ["opaque:original-scanner-result"],
        "fingerprint": "a" * 64,
        "fingerprint_algo": "v2",
        "remediation_effort": None,
        "blocked_external": False,
        "dependency": {
            "advisory": "CVE-2026-0001",
            "module": "example-module",
            "ecosystem": "pypi",
            "evidence_level": "manifest",
            "classification": "likely_affected",
        },
    }
    result = build_adapter_result("synthetic-repository", "fixture-scanner", [source])
    document = AdapterResultArtifact.from_document(result.to_dict())
    (recorded,) = document.findings
    assert recorded.fingerprint == source["fingerprint"]
    assert recorded.fingerprint_algo == "v2"
    assert recorded.dependency.classification == "likely_affected"
    assert recorded.dependency.evidence_level == "manifest"
    assert recorded.source_findings == ("opaque:original-scanner-result",)
    assert recorded.remediation_effort is None
    assert recorded.blocked_external is False
    assert document.metadata.tool == "fixture-scanner"
    assert document.summary.by_severity.high == 1


def test_explicit_invalid_severity_cannot_be_relabelled_as_low():
    with pytest.raises(ValueError):
        build_adapter_result(
            "synthetic-repository", "fixture-scanner", [{**finding(), "severity": "urgent"}]
        )


def test_undeclared_metadata_cannot_silently_disappear():
    with pytest.raises(
        ValueError, match="undeclared adapter finding fields: unrecognized_provenance"
    ):
        build_adapter_result(
            "synthetic-repository",
            "fixture-scanner",
            [{**finding(), "unrecognized_provenance": "original evidence"}],
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("origin", "gitleaks"),
        ("pqc_classification", "invented"),
        ("fingerprint", "scanner:local-id"),
        ("isolation_dimensions", []),
    ],
)
def test_invalid_optional_evidence_is_refused_at_artifact_admission(field, value):
    result = build_adapter_result(
        "synthetic-repository", "fixture-scanner", [{**finding(), field: value}]
    )
    with pytest.raises(DocumentError):
        AdapterResultArtifact.from_document(result.to_dict())


def test_native_secret_scanner_identity_is_not_a_domain_fingerprint(tmp_path):
    native = {
        "RuleID": "fixture-secret-rule",
        "Description": "Synthetic scanner observation retaining its source context without a real credential.",
        "File": "fixture.env",
        "StartLine": 3,
        "EndLine": 3,
        "Fingerprint": "fixture.env:fixture-secret-rule:3",
    }
    candidates = gitleaks.parse_report([native], tmp_path, "dir")
    assert candidates[0]["fingerprint"] == native["Fingerprint"]
    result = build_adapter_result(
        "synthetic-repository", "gitleaks", gitleaks._candidates_to_findings(candidates)
    )
    assert result.metadata.tool == "gitleaks"
    assert result.findings[0].locations[0].path == "fixture.env"
    assert result.findings[0].fingerprint is None
    assert result.findings[0].origin is None


def test_grype_package_locations_survive_conversion():
    raw = {
        "matches": [
            {
                "vulnerability": {"id": "CVE-2026-0001", "severity": "High"},
                "artifact": {
                    "name": "example-package",
                    "type": "rpm",
                    "version": "1.0",
                    "locations": [{"path": "usr/lib/example.so"}],
                },
            }
        ]
    }
    result = build_adapter_result("synthetic-repository", "grype", grype._parse_matches(raw))
    assert result.findings[0].locations[0].path == "usr/lib/example.so"
    assert result.metadata.tool == "grype"


@pytest.mark.parametrize("severity", ["Unknown", "urgent"])
def test_native_unknown_scanner_severity_cannot_be_relabelled_as_low(severity):
    raw = {
        "matches": [
            {
                "vulnerability": {"id": "CVE-2026-0001", "severity": severity},
                "artifact": {"name": "fixture", "type": "rpm", "version": "1"},
            }
        ]
    }
    with pytest.raises(ValueError):
        grype._parse_matches(raw)
