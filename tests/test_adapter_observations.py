"""Typed scanner observations retain native facts without authoring audit conclusions."""

import json
import shutil

import pytest

from traust_engine.adapters import gitleaks, grype
from traust_engine.adapters._contract_bridge import build_adapter_result
from traust_engine.assets import default_gitleaks_config
from traust_engine.reporting.validate import (
    SCHEMA_DIR,
    build_registry,
    load_schema,
    validate_report,
)


def _validate_result(result, tmp_path):
    path = tmp_path / "adapter-result.json"
    path.write_text(json.dumps(result.to_dict()), encoding="utf-8")
    return validate_report(
        str(path),
        load_schema(SCHEMA_DIR / "adapter-result.schema.json"),
        registry=build_registry(),
        strict=True,
    )


def test_supplied_finding_metadata_survives_normalization(tmp_path):
    metadata = {
        "asvs_references": ["V1.1.1"],
        "peach_references": ["PEACH-A"],
        "owasp_llm_references": ["LLM01"],
        "cvss": {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
        "capec": ["CAPEC-100"],
        "evidence": [{"code": "supplied snippet", "language": "python", "caption": "native"}],
        "attack_pattern": "Scanner-supplied attack pattern",
        "category": "supply-chain",
        "validation_status": "not_verified",
        "source_findings": ["GHSA-2345-6789-abcd"],
        "origin": "vuln-scan",
        "pqc_classification": "pqc-adoption",
        "remediation_effort": "m",
        "blocked_external": False,
        "isolation_dimensions": ["authentication"],
        "isolation_boundary": "tenant-api",
        "disposition": {
            "validity": "not_verified",
            "resolution": "open",
            "last_updated": "2026-10-23T00:00:00Z",
            "events": [],
        },
        "fingerprint": "a" * 64,
        "fingerprint_algo": "v2",
        "effective_severity": "medium",
        "passes": [1, 2],
        "dependency": {
            "advisory": "GHSA-2345-6789-abcd",
            "module": "example-package",
            "ecosystem": "pypi",
            "installed_version": "1.0.0",
            "fixed_version": "1.0.1",
        },
    }
    result = build_adapter_result(
        "target",
        "native-scanner",
        [
            {
                "id": "native:id@1",
                "title": "X",
                "severity": "HIGH",
                "locations": [{"path": "app.py"}],
                **metadata,
            }
        ],
    )
    finding = result.findings[0].to_dict()
    for key, value in metadata.items():
        assert finding[key] == value
    assert finding["severity"] == "high"
    assert result.summary.by_severity == {"high": 1}
    validation = _validate_result(result, tmp_path)
    assert validation.passed, validation.errors
    assert not validation.warnings


@pytest.mark.parametrize("severity", ["unknown", "urgent", "", None, 7])
def test_explicit_unknown_severity_is_not_rewritten(severity):
    with pytest.raises(ValueError):
        build_adapter_result(
            "target", "native-scanner", [{"id": "r", "title": "X", "severity": severity}]
        )


def test_supplied_unknown_classifier_is_not_dropped(tmp_path):
    result = build_adapter_result(
        "target",
        "native-scanner",
        [
            {
                "id": "r",
                "title": "X",
                "locations": [{"path": "app.py"}],
                "pqc_classification": "unknown",
            }
        ],
    )
    assert result.findings[0].pqc_classification == "unknown"
    validation = _validate_result(result, tmp_path)
    assert not validation.passed
    assert any("pqc_classification" in error for error in validation.errors)


def test_native_gitleaks_fingerprint_stays_in_raw_candidates(tmp_path):
    native_fingerprint = "settings.py:traust-openshift-sha256-token:1"
    candidates = gitleaks.parse_report(
        [
            {
                "RuleID": "traust-openshift-sha256-token",
                "Description": "OpenShift token",
                "File": "settings.py",
                "StartLine": 1,
                "EndLine": 1,
                "Fingerprint": native_fingerprint,
            }
        ],
        tmp_path,
        "dir",
    )
    result = build_adapter_result(
        str(tmp_path), "gitleaks", gitleaks._candidates_to_findings(candidates)
    )
    assert candidates[0]["fingerprint"] == native_fingerprint
    finding = result.findings[0].to_dict()
    assert "fingerprint" not in finding
    assert "origin" not in finding
    assert finding["cwes"] == []
    assert finding["remediation"] == ""
    assert not finding["evidence"]
    assert "validation_status" not in finding
    assert result.metadata.tool == "gitleaks"
    validation = _validate_result(result, tmp_path)
    assert validation.passed, validation.errors


def test_grype_native_locations_and_fixed_versions(tmp_path):
    findings = grype._parse_matches(
        {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2026-12345",
                        "severity": "High",
                        "fix": {"versions": ["1.0.1", "2.0.1"]},
                    },
                    "artifact": {
                        "name": "example-package",
                        "version": "1.0.0",
                        "type": "python",
                        "locations": [{"path": "/usr/lib/example-package/METADATA"}],
                    },
                }
            ],
        }
    )
    result = build_adapter_result("target", "grype", findings)
    finding = result.findings[0].to_dict()
    assert finding["locations"] == [{"path": "/usr/lib/example-package/METADATA"}]
    assert finding["remediation"] == "Upgrade example-package to 1.0.1, 2.0.1"
    assert "origin" not in finding
    assert "fingerprint" not in finding
    validation = _validate_result(result, tmp_path)
    assert validation.passed, validation.errors


@pytest.mark.integration
@pytest.mark.skipif(shutil.which("gitleaks") is None, reason="gitleaks not on PATH")
def test_real_gitleaks_bundled_canary_passes_adapter_contract(tmp_path):
    config = default_gitleaks_config()
    target = tmp_path / "target"
    target.mkdir()
    shutil.copyfile(config.parent / "fixtures" / "secrets-fixture.txt", target / "canary.txt")

    result = gitleaks.scan(target, config=config)

    observations = {finding.id: finding.to_dict() for finding in result.findings}
    assert "gitleaks/traust-openshift-sha256-token" in observations
    assert "gitleaks/traust-ansible-vault-payload" in observations
    assert result.metadata.tool == "gitleaks"
    for finding in observations.values():
        assert finding["locations"][0]["path"] == "canary.txt"
        assert finding["cwes"] == []
        assert finding["remediation"] == ""
        assert not finding["evidence"]
        assert "validation_status" not in finding
        assert "origin" not in finding
        assert "fingerprint" not in finding
    validation = _validate_result(result, tmp_path)
    assert validation.passed, validation.errors
    assert not validation.warnings


def test_undeclared_scanner_metadata_cannot_silently_disappear():
    with pytest.raises(ValueError):
        build_adapter_result(
            "target",
            "native-scanner",
            [{"id": "r", "title": "X", "unrecognized_provenance": "original metadata"}],
        )
