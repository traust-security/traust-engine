#!/usr/bin/env python3
"""Unit tests for validate_report.py and render_report.py."""

import copy
import hashlib
import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jsonschema
from traust_contracts.paths import schema_dir as _schema_dir

SCHEMA_DIR = _schema_dir()
from traust_engine import HarnessEngine
from traust_engine.reporting import lint, render, validate
from traust_engine.reporting.render import render_report
from traust_engine.reporting.validate import (
    ValidationResult,
    build_registry,
    collect_report_files,
    cross_validate,
    cross_validate_verification,
    load_schema,
    strict_checks,
    validate_report,
)


def _stamp_fixture(layer: dict) -> None:
    """Compute and set Merkle metadata on a test fixture layer.

    Pure hash computation (RFC 9162 §2.1) — no signing, no write path.
    Only used in tests to avoid merkle_root-absent errors masking the
    actual assertion.
    """
    events = layer.get("events") or []
    meta = layer.setdefault("metadata", {})

    def _leaf(data: bytes) -> bytes:
        return hashlib.sha256(b"\x00" + data).digest()

    def _node(left: bytes, right: bytes) -> bytes:
        return hashlib.sha256(b"\x01" + left + right).digest()

    def _mth(hashes: list[bytes]) -> bytes:
        n = len(hashes)
        if n == 0:
            return hashlib.sha256(b"").digest()
        if n == 1:
            return hashes[0]
        k = 1 << ((n - 1).bit_length() - 1)
        return _node(_mth(hashes[:k]), _mth(hashes[k:]))

    import json as _json

    leaves = [
        _leaf(
            _json.dumps(
                {k: v for k, v in evt.items() if not str(k).startswith("merkle_")},
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode()
        )
        for evt in events
    ]

    meta["merkle_root"] = _mth(leaves).hex()
    meta["merkle_size"] = len(events)
    meta["merkle_algorithm"] = "sha256"
    meta["leaf_format"] = 2
    if "merkle_epoch" not in meta:
        meta["merkle_epoch"] = 0


def _valid_report():
    """Return a minimal report dict that passes all validation."""
    rep = {
        "title": "Security Assessment — Test Widget",
        "metadata": {
            "date": "2026-05-21",
            "scope": "First-party Go source (cmd/, pkg/), Kubernetes manifests, Dockerfiles",
            "repository": "https://github.com/example/widget-operator",
        },
        "executive_summary": {
            "prose": (
                "The Widget Operator manages resources in OpenShift clusters. "
                "This assessment identified 2 findings across the codebase."
            ),
            "severity_counts": {
                "critical": 0,
                "high": 1,
                "medium": 1,
                "low": 0,
                "informational": 0,
            },
        },
        "severity_criteria": [
            {
                "level": "critical",
                "definition": "Remote attacker achieves node-root or cluster-admin without authentication.",
            },
            {
                "level": "high",
                "definition": "Authenticated user escalates privileges across namespace boundaries.",
            },
            {
                "level": "medium",
                "definition": "Requires elevated prerequisites or enables denial of service.",
            },
            {
                "level": "low",
                "definition": "Hardening gap or best-practice deviation with no direct exploitability.",
            },
        ],
        "findings": [
            {
                "id": "TEST-001",
                "title": "SSRF via Webhook Annotation",
                "severity": "high",
                "cwes": ["CWE-918"],
                "locations": [{"path": "pkg/webhook/handler.go", "lines": "42-58"}],
                "description": (
                    "The admission webhook reads a destination URL from a pod annotation "
                    "and makes an HTTP POST without validating against an allow-list."
                ),
                "remediation": "Validate the callback URL against a configurable allow-list of permitted hosts.",
            },
            {
                "id": "TEST-002",
                "title": "Unbounded Request Body Read",
                "severity": "medium",
                "cwes": ["CWE-770"],
                "locations": [{"path": "pkg/webhook/handler.go", "lines": "30-35"}],
                "description": (
                    "The admission webhook reads the entire request body with io.ReadAll "
                    "without setting a size limit, enabling memory exhaustion."
                ),
                "remediation": "Replace io.ReadAll with io.LimitReader(r.Body, maxBodySize).",
            },
        ],
        "findings_summary": [
            {"severity": "critical", "count": 0, "finding_ids": []},
            {"severity": "high", "count": 1, "finding_ids": ["TEST-001"]},
            {"severity": "medium", "count": 1, "finding_ids": ["TEST-002"]},
            {"severity": "low", "count": 0, "finding_ids": []},
        ],
        "remediation_roadmap": [
            {
                "priority": "P0",
                "action": "Implement URL allow-list validation for webhook callbacks",
                "addresses": ["TEST-001"],
            },
            {
                "priority": "P1",
                "action": "Add io.LimitReader to admission webhook body read",
                "addresses": ["TEST-002"],
            },
        ],
    }
    for f in rep["findings"]:
        f["fingerprint"] = hashlib.sha256(f["id"].encode()).hexdigest()
    return rep


SCHEMA = load_schema()


def _schema_errors(report):
    """Run JSON Schema validation and return list of error messages."""
    validator = jsonschema.Draft202012Validator(SCHEMA, format_checker=jsonschema.FormatChecker())
    return [e.message for e in validator.iter_errors(report)]


def _cross_errors(report):
    """Run cross-validation and return the ValidationResult."""
    result = ValidationResult(file_path="<test>")
    cross_validate(report, result)
    return result


# ---------------------------------------------------------------------------
# Good report
# ---------------------------------------------------------------------------


class TestValidReport(unittest.TestCase):
    def test_valid_report_passes_schema(self):
        errors = _schema_errors(_valid_report())
        self.assertEqual(errors, [])

    def test_valid_report_passes_cross_checks(self):
        result = _cross_errors(_valid_report())
        self.assertEqual(result.errors, [])

    def test_valid_report_strict_warnings(self):
        result = ValidationResult(file_path="<test>")
        strict_checks(_valid_report(), result)
        self.assertEqual(result.errors, [])
        warn_text = " ".join(result.warnings)
        self.assertIn("dependency_audit", warn_text)
        self.assertIn("negative_results", warn_text)
        self.assertIn("footer", warn_text)
        self.assertIn("CVSS", warn_text)

    def test_full_round_trip_via_file(self):
        report = _valid_report()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(report, f)
            path = f.name
        try:
            from traust_engine.reporting.validate import validate_report

            r = validate_report(path, SCHEMA)
            self.assertTrue(r.passed, r.errors)
        finally:
            Path(path).unlink()


# ---------------------------------------------------------------------------
# Schema violations — one per test
# ---------------------------------------------------------------------------


class TestSchemaViolations(unittest.TestCase):
    def _mutate(self, fn):
        """Deep-copy the valid report, apply fn, return schema errors."""
        r = copy.deepcopy(_valid_report())
        fn(r)
        return _schema_errors(r)

    def test_missing_title(self):
        errors = self._mutate(lambda r: r.pop("title"))
        self.assertTrue(any("'title' is a required property" in e for e in errors))

    def test_bad_title_no_security_keyword(self):
        errors = self._mutate(lambda r: r.__setitem__("title", "My Cool Project Report"))
        self.assertTrue(any("does not match" in e for e in errors))

    def test_missing_metadata_date(self):
        errors = self._mutate(lambda r: r["metadata"].pop("date"))
        self.assertTrue(any("'date' is a required property" in e for e in errors))

    def test_invalid_date_format(self):
        errors = self._mutate(lambda r: r["metadata"].__setitem__("date", "not-a-date"))
        self.assertTrue(
            any("is not a" in e.lower() or "format" in e.lower() for e in errors), errors
        )

    def test_missing_scope(self):
        errors = self._mutate(lambda r: r["metadata"].pop("scope"))
        self.assertTrue(any("'scope' is a required property" in e for e in errors))

    def test_scope_too_short(self):
        errors = self._mutate(lambda r: r["metadata"].__setitem__("scope", "x"))
        self.assertTrue(any("too short" in e or "minLength" in e for e in errors), errors)

    def test_invalid_severity_level(self):
        errors = self._mutate(lambda r: r["findings"][0].__setitem__("severity", "extreme"))
        self.assertTrue(any("'extreme' is not one of" in e for e in errors))

    def test_empty_cwes(self):
        errors = self._mutate(lambda r: r["findings"][0].__setitem__("cwes", []))
        self.assertTrue(any("non-empty" in e or "too short" in e for e in errors), errors)

    def test_bad_cwe_format(self):
        errors = self._mutate(lambda r: r["findings"][0].__setitem__("cwes", ["not-a-cwe"]))
        self.assertTrue(any("does not match" in e for e in errors))

    def test_empty_locations(self):
        errors = self._mutate(lambda r: r["findings"][0].__setitem__("locations", []))
        self.assertTrue(any("non-empty" in e or "too short" in e for e in errors), errors)

    def test_description_too_short(self):
        errors = self._mutate(lambda r: r["findings"][0].__setitem__("description", "short"))
        self.assertTrue(any("too short" in e or "minLength" in e for e in errors), errors)

    def test_missing_findings_summary(self):
        errors = self._mutate(lambda r: r.pop("findings_summary"))
        self.assertTrue(any("'findings_summary' is a required property" in e for e in errors))

    def test_missing_remediation_roadmap(self):
        errors = self._mutate(lambda r: r.pop("remediation_roadmap"))
        self.assertTrue(any("'remediation_roadmap' is a required property" in e for e in errors))

    def test_additional_property_rejected(self):
        errors = self._mutate(lambda r: r.__setitem__("bogus_field", "oops"))
        self.assertTrue(
            any("additional properties" in e.lower() or "unevaluated" in e.lower() for e in errors),
            errors,
        )

    def test_severity_criteria_too_few(self):
        errors = self._mutate(
            lambda r: r.__setitem__("severity_criteria", r["severity_criteria"][:2])
        )
        self.assertTrue(any("too short" in e or "minItems" in e for e in errors), errors)

    def test_missing_finding_title(self):
        errors = self._mutate(lambda r: r["findings"][0].pop("title"))
        self.assertTrue(any("'title' is a required property" in e for e in errors))

    def test_missing_finding_remediation(self):
        errors = self._mutate(lambda r: r["findings"][0].pop("remediation"))
        self.assertTrue(any("'remediation' is a required property" in e for e in errors))

    def test_invalid_cvss_score_too_high(self):
        def add_bad_cvss(r):
            r["findings"][0]["cvss"] = {"score": 11.0, "vector": "AV:N/AC:L"}

        errors = self._mutate(add_bad_cvss)
        self.assertTrue(any("11.0" in e or "maximum" in e for e in errors), errors)

    def test_invalid_capec_format(self):
        def add_bad_capec(r):
            r["findings"][0]["capec"] = ["not-capec"]

        errors = self._mutate(add_bad_capec)
        self.assertTrue(any("does not match" in e for e in errors))

    def test_roadmap_action_too_short(self):
        errors = self._mutate(lambda r: r["remediation_roadmap"][0].__setitem__("action", "fix"))
        self.assertTrue(any("too short" in e or "minLength" in e for e in errors), errors)


# ---------------------------------------------------------------------------
# Cross-validation violations
# ---------------------------------------------------------------------------


class TestCrossValidation(unittest.TestCase):
    def _mutate(self, fn):
        r = copy.deepcopy(_valid_report())
        fn(r)
        return _cross_errors(r)

    def test_duplicate_finding_id(self):
        result = self._mutate(lambda r: r["findings"][1].__setitem__("id", "TEST-001"))
        self.assertTrue(any("Duplicate finding ID" in e for e in result.errors), result.errors)

    def test_severity_count_mismatch(self):
        result = self._mutate(lambda r: r["findings_summary"][1].__setitem__("count", 5))
        self.assertTrue(any("count is 5" in e for e in result.errors), result.errors)

    def test_summary_ids_length_mismatch(self):
        def mutate(r):
            r["findings_summary"][1]["count"] = 2

        result = self._mutate(mutate)
        self.assertTrue(any("finding_ids has 1 entries" in e for e in result.errors), result.errors)

    def test_summary_references_unknown_id(self):
        def mutate(r):
            r["findings_summary"][1]["finding_ids"] = ["GHOST-999"]

        result = self._mutate(mutate)
        self.assertTrue(
            any("unknown finding ID: GHOST-999" in e for e in result.errors), result.errors
        )

    def test_finding_missing_from_summary(self):
        def mutate(r):
            r["findings_summary"][2]["finding_ids"] = []
            r["findings_summary"][2]["count"] = 0

        result = self._mutate(mutate)
        self.assertTrue(any("not listed" in e.lower() for e in result.errors), result.errors)

    def test_roadmap_references_unknown_id(self):
        def mutate(r):
            r["remediation_roadmap"][0]["addresses"] = ["NONEXISTENT-001"]

        result = self._mutate(mutate)
        self.assertTrue(
            any("unknown finding ID: NONEXISTENT-001" in e for e in result.errors), result.errors
        )

    def test_missing_mandatory_severity_criterion(self):
        def mutate(r):
            r["severity_criteria"] = [c for c in r["severity_criteria"] if c["level"] != "high"]
            # keep minItems happy by adding a duplicate
            r["severity_criteria"].append(r["severity_criteria"][0])

        result = self._mutate(mutate)
        self.assertTrue(
            any("missing mandatory level: high" in e for e in result.errors), result.errors
        )

    def test_executive_summary_count_mismatch(self):
        def mutate(r):
            r["executive_summary"]["severity_counts"]["high"] = 5

        result = self._mutate(mutate)
        self.assertTrue(
            any("executive_summary.severity_counts[high]" in e for e in result.errors),
            result.errors,
        )

    def test_executive_summary_counts_match_findings(self):
        result = self._mutate(lambda r: None)
        es_errors = [e for e in result.errors if "executive_summary.severity_counts" in e]
        self.assertEqual(es_errors, [])


# ---------------------------------------------------------------------------
# Directory validation (rglob)
# ---------------------------------------------------------------------------


class TestDirectoryValidation(unittest.TestCase):
    def test_directory_mode_finds_nested_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            nested = Path(tmpdir) / "product" / "repo"
            nested.mkdir(parents=True)
            report_path = nested / "repo-security-audit.json"
            report_path.write_text(json.dumps(_valid_report()), encoding="utf-8")

            target = Path(tmpdir)
            files = sorted(target.rglob("*.json"))
            self.assertEqual(len(files), 1)
            self.assertEqual(files[0].name, "repo-security-audit.json")

            r = validate_report(str(files[0]), SCHEMA)
            self.assertTrue(r.passed, r.errors)

    def test_collect_report_files_finds_nested_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            nested = Path(tmpdir) / "product" / "repo"
            nested.mkdir(parents=True)
            (nested / "repo-security-audit.json").write_text("{}", encoding="utf-8")
            (Path(tmpdir) / "top-level.json").write_text("{}", encoding="utf-8")

            files = collect_report_files(tmpdir)
            names = [f.name for f in files]
            self.assertIn("repo-security-audit.json", names)
            self.assertIn("top-level.json", names)
            self.assertEqual(len(files), 2)

    def test_collect_report_files_skips_hidden_directories(self):
        """Skill working state (.triage-state/ etc.) is not an artifact."""
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir) / "org" / "repo"
            (repo / ".triage-state").mkdir(parents=True)
            (repo / "repo-security-audit.json").write_text("{}", encoding="utf-8")
            (repo / ".triage-state" / "phase1.json").write_text("{}", encoding="utf-8")
            names = [f.name for f in collect_report_files(tmpdir)]
            self.assertEqual(names, ["repo-security-audit.json"])

    def test_collect_report_files_inside_a_hidden_root(self):
        """Only directories below the swept root count, so sweeping a path
        that itself sits under a dot-directory still finds its files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir) / ".cache" / "findings"
            root.mkdir(parents=True)
            (root / "repo-security-audit.json").write_text("{}", encoding="utf-8")
            self.assertEqual(len(collect_report_files(str(root))), 1)

    def test_a_document_that_is_not_report_shaped_fails_without_raising(self):
        """The identity and strict checks read findings directly; on a
        malformed document they used to raise and abort the whole sweep."""
        for document in (
            {"phase": 1, "findings": 3},
            {"phase": 1, "findings": ["FIND-001"]},
            {"metadata": "x", "findings": []},
            [1, 2, 3],
        ):
            with tempfile.TemporaryDirectory() as tmpdir:
                path = Path(tmpdir) / "phase1.json"
                path.write_text(json.dumps(document), encoding="utf-8")
                r = validate_report(str(path), SCHEMA, strict=True)
                self.assertFalse(r.passed, document)


# ---------------------------------------------------------------------------
# Renderer smoke test
# ---------------------------------------------------------------------------


class TestRenderer(unittest.TestCase):
    def test_render_produces_expected_sections(self):
        report = _valid_report()
        report["negative_results"] = [
            {"area": "SQL Injection", "result": "No issues found."},
        ]
        report["footer"] = "End of report."
        md = render_report(report)

        self.assertIn("# Security Assessment", md)
        self.assertIn("## 1. Executive Summary", md)
        self.assertIn("## 2. Severity Criteria", md)
        self.assertIn("## 3. Detailed Findings", md)
        self.assertIn("## 4. Findings Summary", md)
        self.assertIn("## 5. Remediation Roadmap", md)
        self.assertIn("Negative Results", md)
        self.assertIn("*End of report.*", md)

    def test_render_includes_finding_details(self):
        md = render_report(_valid_report())

        self.assertIn("TEST-001", md)
        self.assertIn("TEST-002", md)
        self.assertIn("CWE-918", md)
        self.assertIn("CWE-770", md)
        self.assertIn("**High**", md)
        self.assertIn("**Medium**", md)
        self.assertIn("handler.go:42-58", md)

    def test_render_evidence_code_block(self):
        report = copy.deepcopy(_valid_report())
        report["findings"][0]["evidence"] = [
            {"language": "go", "code": "http.Post(url, ct, body)", "caption": "Vulnerable call"},
        ]
        md = render_report(report)
        self.assertIn("```go", md)
        self.assertIn("http.Post(url, ct, body)", md)
        self.assertIn("*Vulnerable call*", md)

    def test_render_metadata_table_format(self):
        report = copy.deepcopy(_valid_report())
        report["metadata"]["repository"] = "github.com/example/test"
        report["metadata"]["commit"] = "abc123"
        md = render_report(report)
        self.assertIn("| **Date**", md)
        self.assertIn("| **Repository**", md)

    def test_render_metadata_inline_format(self):
        md = render_report(_valid_report())
        self.assertIn("**Date:** 2026-05-21", md)
        self.assertIn("**Scope:**", md)


# ---------------------------------------------------------------------------
# 0.15.0 consistency conventions
# ---------------------------------------------------------------------------


def _consistency_report():
    """Fixture upgraded to the 0.15.0 conventions (canonical IDs, commit,
    harness_version) so the CONSISTENCY_MIN_VERSION gates fire."""
    r = copy.deepcopy(_valid_report())
    r["metadata"]["commit"] = "abcdef0123456789abcdef0123456789abcdef01"
    r["metadata"]["additional"] = {"harness_version": "0.15.0-1234567"}
    text = json.dumps(r)
    text = text.replace("TEST-001", "TEST_WIDGET-abcdef0-001")
    text = text.replace("TEST-002", "TEST_WIDGET-abcdef0-002")
    r = json.loads(text)
    for f in r["findings"]:
        f["validation_status"] = "not_verified"
    r["peach_isolation_review"] = {
        "applicable": False,
        "rationale": "Single-tenant operator: one deployment serves exactly one cluster and trust domain.",
    }
    return r


class TestConsistencyGates(unittest.TestCase):
    """Hard cross-validation gates for harness >= 0.15.0."""

    def test_consistency_fixture_passes(self):
        result = _cross_errors(_consistency_report())
        self.assertEqual(result.errors, [])

    def test_missing_peach_review_is_error_at_0_15(self):
        r = _consistency_report()
        del r["peach_isolation_review"]
        result = _cross_errors(r)
        self.assertTrue(any("peach_isolation_review is required" in e for e in result.errors))

    def test_missing_peach_review_not_error_pre_0_15(self):
        r = _consistency_report()
        del r["peach_isolation_review"]
        r["metadata"]["additional"]["harness_version"] = "0.14.0-1234567"
        result = _cross_errors(r)
        self.assertFalse(any("peach_isolation_review" in e for e in result.errors))

    def test_missing_validation_status_is_error_at_0_15(self):
        r = _consistency_report()
        del r["findings"][0]["validation_status"]
        result = _cross_errors(r)
        self.assertTrue(any("validation_status is required" in e for e in result.errors))


class TestStrictConventions(unittest.TestCase):
    """Strict-mode warnings added with the 0.15.0 conventions."""

    def _warnings(self, report):
        result = ValidationResult(file_path="<test>")
        strict_checks(report, result)
        return result.warnings

    def test_repository_url_must_parse_org_repo(self):
        r = copy.deepcopy(_valid_report())
        r["metadata"]["repository"] = "https://github.com/someorg"
        self.assertTrue(
            any("metadata.repository" in w and "does not parse" in w for w in self._warnings(r))
        )
        r["metadata"]["repository"] = "free text about Azure repos"
        self.assertTrue(any("does not parse" in w for w in self._warnings(r)))
        r["metadata"]["repository"] = ""
        self.assertTrue(any("metadata.repository missing" in w for w in self._warnings(r)))
        # accepted shapes: plain, <>-wrapped, dot-leading repo, gitlab nesting
        for ok in (
            "https://github.com/org/repo",
            "<https://github.com/org/repo>",
            "https://github.com/org/.github",
            "https://gitlab.example.com/service/iac-declarations",
        ):
            r["metadata"]["repository"] = ok
            self.assertFalse(any("repository" in w for w in self._warnings(r)), ok)

    def test_no_cvss_warning_for_informational(self):
        r = copy.deepcopy(_valid_report())
        r["findings"][1]["severity"] = "informational"
        warns = self._warnings(r)
        self.assertTrue(any("TEST-001" in w and "CVSS" in w for w in warns))
        self.assertFalse(any("TEST-002" in w and "CVSS" in w for w in warns))

    def test_attack_pattern_warning_on_high_only(self):
        warns = self._warnings(_valid_report())
        self.assertTrue(any("TEST-001" in w and "attack_pattern" in w for w in warns))
        self.assertFalse(any("TEST-002" in w and "attack_pattern" in w for w in warns))

    def test_all_confirmed_warning(self):
        r = copy.deepcopy(_valid_report())
        r["findings"] = [
            dict(r["findings"][0], id=f"TEST-{i:03d}", validation_status="confirmed")
            for i in range(1, 6)
        ]
        warns = self._warnings(r)
        self.assertTrue(any("'confirmed'" in w and "not_verified" in w for w in warns))

    def test_mixed_statuses_no_overclaim_warning(self):
        r = copy.deepcopy(_valid_report())
        r["findings"] = [
            dict(
                r["findings"][0],
                id=f"TEST-{i:03d}",
                validation_status="confirmed" if i > 1 else "not_verified",
            )
            for i in range(1, 6)
        ]
        warns = self._warnings(r)
        self.assertFalse(any("'confirmed'" in w and "not_verified" in w for w in warns))

    def test_off_vocabulary_category_warning_at_0_15(self):
        r = _consistency_report()
        r["findings"][0]["category"] = "Improper Widget Management"
        r["findings"][1]["category"] = "Supply Chain"  # normalizes to supply-chain
        warns = self._warnings(r)
        self.assertTrue(any("Improper Widget Management" in w for w in warns))
        self.assertFalse(any("Supply Chain" in w for w in warns))

    def test_no_category_warning_pre_0_15(self):
        r = copy.deepcopy(_valid_report())
        r["findings"][0]["category"] = "Improper Widget Management"
        warns = self._warnings(r)
        self.assertFalse(any("vocabulary" in w for w in warns))

    def test_implausible_date_warning(self):
        r = copy.deepcopy(_valid_report())
        r["metadata"]["date"] = "2023-03-22"
        warns = self._warnings(r)
        self.assertTrue(any("audit execution date" in w for w in warns))

    def test_stale_date_warning(self):
        r = copy.deepcopy(_valid_report())
        r["metadata"]["date"] = (datetime.now(UTC).date() - timedelta(days=10)).isoformat()
        warns = self._warnings(r)
        self.assertTrue(any("audit execution date" in w for w in warns))

    def test_current_date_no_warning(self):
        r = copy.deepcopy(_valid_report())
        r["metadata"]["date"] = datetime.now(UTC).date().isoformat()
        warns = self._warnings(r)
        self.assertFalse(any("audit execution date" in w for w in warns))

    def test_yesterday_no_warning(self):
        r = copy.deepcopy(_valid_report())
        r["metadata"]["date"] = (datetime.now(UTC).date() - timedelta(days=1)).isoformat()
        warns = self._warnings(r)
        self.assertFalse(any("audit execution date" in w for w in warns))

    def test_short_peach_rationale_warning(self):
        r = copy.deepcopy(_valid_report())
        r["peach_isolation_review"] = {"applicable": False, "rationale": "single tenant"}
        warns = self._warnings(r)
        self.assertTrue(any("rationale" in w for w in warns))

    def test_loc_breakdown_warning_at_0_15(self):
        r = _consistency_report()
        r["metadata"]["loc_reviewed"] = "1234"
        warns = self._warnings(r)
        self.assertTrue(any("loc_breakdown" in w for w in warns))


class TestRendererNumbering(unittest.TestCase):
    def test_scanner_correlation_numbered(self):
        report = copy.deepcopy(_valid_report())
        report["scanner_correlation"] = [{"tool": "Trivy", "result": "not configured"}]
        md = render_report(report)
        self.assertIn("## 6. Scanner Correlation", md)


# ---------------------------------------------------------------------------
# Remediation verification reports (verification.schema.json)
# ---------------------------------------------------------------------------


VERIFICATION_SCHEMA = load_schema(SCHEMA_DIR / "verification.schema.json")
REGISTRY = build_registry()

ORIGINAL_SHA = "abcdef0123456789abcdef0123456789abcdef01"
PATCHED_SHA = "1234567890abcdef1234567890abcdef12345678"
FIX_SHA = "feedfacefeedfacefeedfacefeedfacefeedface"


def _valid_verification_report():
    """Return a minimal verification report that passes all validation."""
    return {
        "title": "example-app Remediation Verification",
        "metadata": {
            "date": "2026-07-10",
            "harness_version": "0.17.0-1234567",
            "original_report": "findings/example-operator/example-app/example-app-security-audit.json",
            "original_commit": ORIGINAL_SHA,
            "patched_commit": PATCHED_SHA,
            "patched_ref": "pull/42/head",
            "repository": "https://github.com/example-org/example-app",
        },
        "summary": {
            "total_findings": 2,
            "by_verdict": {
                "resolved": 1,
                "partially_resolved": 1,
                "unresolved": 0,
                "new_approach": 0,
                "regression": 0,
                "false_positive": 0,
                "risk_accepted": 0,
            },
            "regressions": 1,
        },
        "verified_findings": [
            {
                "original_id": "EXAMPLE_APP-abcdef0-001",
                "original_title": "SSRF via Webhook Annotation",
                "original_severity": "high",
                "verdict": "resolved",
                "remediation_commits": [
                    {
                        "sha": FIX_SHA,
                        "short_sha": FIX_SHA[:7],
                        "date": "2026-06-15T10:00:00+00:00",
                        "author": "Jane Dev <jane@example.com>",
                        "subject": "Validate webhook URL against allow-list (#42)",
                        "pr_number": 42,
                        "relevance": "direct",
                    }
                ],
                "unattributed": False,
                "evidence": {
                    "original_code": "http.Post(url, ct, body)",
                    "patched_code": "if !allowlist.Match(url) { return errDenied }",
                    "explanation": (
                        "Webhook callback URLs are now validated against a "
                        "configurable allow-list before any request is made."
                    ),
                    "framework_reference": "CWE-918",
                },
                "disposition_rationale": None,
                "residual_risk": None,
                "residual_severity": None,
            },
            {
                "original_id": "EXAMPLE_APP-abcdef0-002",
                "original_title": "Unbounded Request Body Read",
                "original_severity": "medium",
                "verdict": "partially_resolved",
                "remediation_commits": [
                    {
                        "sha": FIX_SHA,
                        "short_sha": FIX_SHA[:7],
                        "date": "2026-06-15T10:00:00+00:00",
                        "author": "Jane Dev <jane@example.com>",
                        "subject": "Validate webhook URL against allow-list (#42)",
                        "pr_number": 42,
                        "relevance": "partial",
                    }
                ],
                "unattributed": False,
                "evidence": {
                    "original_code": "body, _ := io.ReadAll(r.Body)",
                    "patched_code": "body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))",
                    "explanation": (
                        "The admission path now bounds the body read, but the "
                        "metrics path still calls io.ReadAll unbounded."
                    ),
                    "framework_reference": "CWE-770",
                },
                "disposition_rationale": None,
                "residual_risk": "Metrics endpoint body read remains unbounded.",
                "residual_severity": "low",
            },
        ],
        "regressions": [
            {
                "id": "EXAMPLE_APP-1234567-REG-001",
                "title": "Allow-list bypass via URL userinfo",
                "severity": "medium",
                "cwes": ["CWE-918"],
                "cvss": {
                    "score": 5.3,
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                },
                "locations": [{"path": "pkg/webhook/handler.go", "lines": "60-72"}],
                "description": (
                    "The new allow-list matcher compares the raw authority "
                    "before stripping userinfo, so https://allowed@evil.example "
                    "bypasses the check."
                ),
                "remediation": "Parse the URL and compare url.Hostname() only.",
                "evidence": [{"code": "if allowlist.Match(u.Host) {", "language": "go"}],
                "introduced_by": FIX_SHA,
            }
        ],
        "commit_timeline": [
            {
                "sha": FIX_SHA[:7],
                "full_sha": FIX_SHA,
                "date": "2026-06-15T10:00:00+00:00",
                "author": "Jane Dev <jane@example.com>",
                "subject": "Validate webhook URL against allow-list (#42)",
                "pr_number": 42,
                "addresses": ["EXAMPLE_APP-abcdef0-001", "EXAMPLE_APP-abcdef0-002"],
            }
        ],
        "recommendations": [
            "Bound the metrics endpoint body read to close EXAMPLE_APP-abcdef0-002."
        ],
    }


def _verification_schema_errors(report):
    validator = jsonschema.Draft202012Validator(
        VERIFICATION_SCHEMA,
        format_checker=jsonschema.FormatChecker(),
        registry=REGISTRY,
    )
    return [e.message for e in validator.iter_errors(report)]


def _verification_cross(report):
    result = ValidationResult(file_path="<test>")
    cross_validate_verification(report, result)
    return result


class TestVerificationSchema(unittest.TestCase):
    def _mutate(self, fn):
        r = copy.deepcopy(_valid_verification_report())
        fn(r)
        return _verification_schema_errors(r)

    def test_valid_report_passes_schema(self):
        self.assertEqual(_verification_schema_errors(_valid_verification_report()), [])

    def test_valid_report_passes_cross_checks(self):
        result = _verification_cross(_valid_verification_report())
        self.assertEqual(result.errors, [])
        self.assertEqual(result.warnings, [])

    def test_valid_report_round_trip_via_file(self):
        report = _valid_verification_report()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(report, f)
            path = f.name
        try:
            r = validate_report(path, VERIFICATION_SCHEMA, registry=REGISTRY)
            self.assertTrue(r.passed, r.errors)
        finally:
            Path(path).unlink()

    def test_unknown_verdict_rejected(self):
        errors = self._mutate(lambda r: r["verified_findings"][0].__setitem__("verdict", "fixed"))
        self.assertTrue(any("'fixed' is not one of" in e for e in errors), errors)

    def test_short_original_commit_rejected(self):
        errors = self._mutate(lambda r: r["metadata"].__setitem__("original_commit", "abcdef0"))
        self.assertTrue(any("does not match" in e for e in errors), errors)

    def test_regression_id_format_enforced(self):
        errors = self._mutate(lambda r: r["regressions"][0].__setitem__("id", "REG-001"))
        self.assertTrue(any("does not match" in e for e in errors), errors)

    def test_regression_requires_introduced_by(self):
        errors = self._mutate(lambda r: r["regressions"][0].pop("introduced_by"))
        self.assertTrue(any("'introduced_by' is a required property" in e for e in errors), errors)

    def test_missing_by_verdict_key_rejected(self):
        errors = self._mutate(lambda r: r["summary"]["by_verdict"].pop("false_positive"))
        self.assertTrue(any("'false_positive' is a required property" in e for e in errors), errors)

    def test_evidence_requires_explanation(self):
        errors = self._mutate(lambda r: r["verified_findings"][0]["evidence"].pop("explanation"))
        self.assertTrue(any("'explanation' is a required property" in e for e in errors), errors)


class TestVerificationCrossChecks(unittest.TestCase):
    def _mutate(self, fn):
        r = copy.deepcopy(_valid_verification_report())
        fn(r)
        return _verification_cross(r)

    def test_verdict_count_mismatch(self):
        result = self._mutate(lambda r: r["summary"]["by_verdict"].__setitem__("resolved", 2))
        self.assertTrue(any("by_verdict[resolved]" in e for e in result.errors), result.errors)

    def test_total_findings_mismatch(self):
        result = self._mutate(lambda r: r["summary"].__setitem__("total_findings", 5))
        self.assertTrue(any("summary.total_findings" in e for e in result.errors), result.errors)

    def test_regressions_count_mismatch(self):
        result = self._mutate(lambda r: r["summary"].__setitem__("regressions", 3))
        self.assertTrue(any("summary.regressions" in e for e in result.errors), result.errors)

    def test_duplicate_original_id(self):
        result = self._mutate(
            lambda r: r["verified_findings"][1].__setitem__(
                "original_id", "EXAMPLE_APP-abcdef0-001"
            )
        )
        self.assertTrue(any("Duplicate" in e for e in result.errors), result.errors)

    def test_false_positive_requires_disposition_rationale(self):
        def mutate(r):
            f = r["verified_findings"][0]
            f["verdict"] = "false_positive"
            f["remediation_commits"] = []
            f["unattributed"] = True
            r["summary"]["by_verdict"]["resolved"] = 0
            r["summary"]["by_verdict"]["false_positive"] = 1

        result = self._mutate(mutate)
        self.assertTrue(any("disposition_rationale" in e for e in result.errors), result.errors)

    def test_partially_resolved_requires_residual_risk(self):
        result = self._mutate(
            lambda r: r["verified_findings"][1].__setitem__("residual_risk", None)
        )
        self.assertTrue(any("residual_risk" in e for e in result.errors), result.errors)

    def test_resolved_without_commits_or_unattributed(self):
        def mutate(r):
            r["verified_findings"][0]["remediation_commits"] = []

        result = self._mutate(mutate)
        self.assertTrue(any("unattributed" in e for e in result.errors), result.errors)

    def test_unattributed_with_commits_contradiction(self):
        result = self._mutate(lambda r: r["verified_findings"][0].__setitem__("unattributed", True))
        self.assertTrue(any("unattributed is true" in e for e in result.errors), result.errors)

    def test_short_sha_not_prefix(self):
        result = self._mutate(
            lambda r: r["verified_findings"][0]["remediation_commits"][0].__setitem__(
                "short_sha", "1234567"
            )
        )
        self.assertTrue(any("not a prefix" in e for e in result.errors), result.errors)

    def test_timeline_out_of_order(self):
        def mutate(r):
            second = copy.deepcopy(r["commit_timeline"][0])
            second["date"] = "2026-06-01T10:00:00+00:00"
            r["commit_timeline"].append(second)

        result = self._mutate(mutate)
        self.assertTrue(any("chronological" in e for e in result.errors), result.errors)

    def test_timeline_unknown_finding_id(self):
        result = self._mutate(
            lambda r: r["commit_timeline"][0].__setitem__("addresses", ["GHOST-1234567-001"])
        )
        self.assertTrue(any("unknown finding ID" in e for e in result.errors), result.errors)

    def test_regression_shortsha_mismatch_warns(self):
        result = self._mutate(
            lambda r: r["regressions"][0].__setitem__("id", "EXAMPLE_APP-0000000-REG-001")
        )
        self.assertTrue(any("patched_commit" in w for w in result.warnings), result.warnings)

    def test_identical_commits_warn(self):
        result = self._mutate(lambda r: r["metadata"].__setitem__("patched_commit", ORIGINAL_SHA))
        self.assertTrue(any("identical" in w for w in result.warnings), result.warnings)

    def test_commit_missing_from_timeline_warns(self):
        result = self._mutate(lambda r: r.__setitem__("commit_timeline", []))
        self.assertTrue(
            any("not in commit_timeline" in w for w in result.warnings),
            result.warnings,
        )


# ---------------------------------------------------------------------------
# Findings disposition layers (layer.schema.json) and cumulative reports
# ---------------------------------------------------------------------------


class TestDispositionCrossChecks(unittest.TestCase):
    """Cumulative-report disposition consistency (base report schema)."""

    def _cumulative(self):
        r = _consistency_report()
        for f in r["findings"]:
            f["disposition"] = {
                "validity": f["validation_status"],
                "resolution": "open",
                "last_updated": "2026-07-10T12:00:00+00:00",
                "events": [],
            }
        r["disposition_summary"] = {
            "layer_ref": "test-widget-findings-layer.json",
            "generated_at": "2026-07-10T12:00:00+00:00",
            "by_resolution": {
                "open": 2,
                "fix_in_progress": 0,
                "resolved": 0,
                "partially_resolved": 0,
                "risk_accepted": 0,
                "regression_introduced": 0,
            },
            "by_validity": {
                "confirmed": 0,
                "corrected": 0,
                "false_positive": 0,
                "not_verified": 2,
            },
            "conflicts": [],
            "needs_review_count": 0,
        }
        return r

    def _mutate(self, fn):
        r = self._cumulative()
        fn(r)
        return _cross_errors(r)

    def test_valid_cumulative_passes(self):
        r = self._cumulative()
        self.assertEqual(_schema_errors(r), [])
        self.assertEqual(_cross_errors(r).errors, [])

    def test_validation_status_disposition_mismatch(self):
        result = self._mutate(
            lambda r: r["findings"][0]["disposition"].__setitem__("validity", "confirmed")
        )
        self.assertTrue(any("does not equal" in e for e in result.errors), result.errors)

    def test_resolution_count_mismatch(self):
        result = self._mutate(
            lambda r: r["disposition_summary"]["by_resolution"].__setitem__("resolved", 2)
        )
        self.assertTrue(any("by_resolution[resolved]" in e for e in result.errors), result.errors)

    def test_missing_disposition_on_one_finding(self):
        result = self._mutate(lambda r: r["findings"][1].pop("disposition"))
        self.assertTrue(any("no disposition block" in e for e in result.errors), result.errors)

    def test_conflict_flag_summary_mismatch(self):
        result = self._mutate(
            lambda r: r["findings"][0]["disposition"].__setitem__("conflict", True)
        )
        self.assertTrue(
            any("disposition_summary.conflicts" in e for e in result.errors), result.errors
        )

    def test_audit_report_without_dispositions_unaffected(self):
        result = _cross_errors(_consistency_report())
        self.assertEqual(result.errors, [])


if __name__ == "__main__":
    unittest.main()


class TestThreatModelArtifact(unittest.TestCase):
    """The threat model is authored as JSON and rendered, like every other
    artifact. Its schema is the contract; the code-audit cross-checks are
    not."""

    DOC = {
        "system": "example",
        "provenance": {
            "mode": "bootstrap",
            "date": "2026-01-02",
            "target": "https://example.test/repo @ abc1234",
        },
        "threats": [
            {
                "id": "T1",
                "threat": "Token theft via log leak",
                "actor": ["remote_auth"],
                "surface": "api",
                "asset": "tokens",
                "impact": "high",
                "likelihood": "likely",
                "status": "unmitigated",
                "controls": "none",
                "evidence": ["FIND-001"],
                "attack_refs": ["T1552"],
            }
        ],
    }

    def _write(self, tmp, document):
        path = Path(tmp) / "repo-threat-model.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def test_conformant_model_passes_without_code_audit_crosschecks(self):
        """It has no severity_criteria and no metadata.repository, and must
        not be failed for lacking either — those describe a finding report."""
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, self.DOC)
            schema = json.loads(validate.detect_schema_path(path).read_text(encoding="utf-8"))
            result = validate.validate_report(str(path), schema)
            self.assertTrue(result.passed, result.errors)

    def test_off_contract_enum_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            document = json.loads(json.dumps(self.DOC))
            document["threats"][0]["status"] = "open"
            path = self._write(tmp, document)
            schema = json.loads(validate.detect_schema_path(path).read_text(encoding="utf-8"))
            result = validate.validate_report(str(path), schema)
            self.assertFalse(result.passed)
            self.assertTrue(any("status" in e for e in result.errors), result.errors)

    def test_render_round_trips_the_authored_document(self):
        """The prose is generated from the artifact, so it cannot disagree."""
        markdown = render.render_threat_model(self.DOC)
        self.assertTrue(markdown.startswith("# Threat Model: example"))
        self.assertIn("Token theft via log leak", markdown)
        self.assertIn("| T1 |", markdown)
        self.assertIn("- mode: bootstrap", markdown)
        # sections 1-7 are REQUIRED and always emitted, in order
        positions = [markdown.index(f"## {n}. ") for n in range(1, 8)]
        self.assertEqual(positions, sorted(positions))

    def test_rendering_passes_the_prose_linter(self):
        """The Markdown is a rendering, so it must satisfy the prose
        contract by construction — never by someone editing it after."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "repo-threat-model.md"
            path.write_text(render.render_threat_model(self.DOC), encoding="utf-8")
            errors, _ = lint.lint_file(path)
            self.assertEqual(errors, [], errors)

    def test_empty_optional_sections_are_omitted_not_emitted_empty(self):
        """The linter reads a present-but-empty section 9/10 as an error and
        an absent one as fine, so an empty optional section must not be
        rendered at all."""
        markdown = render.render_threat_model(self.DOC)
        self.assertNotIn("## 9. Attack scenarios", markdown)
        self.assertNotIn("## 10. Tenant boundaries", markdown)
        populated = dict(self.DOC)
        populated["tenant_boundaries"] = [
            {"boundary_id": "B1", "interface": "api", "kind": "http", "exposure": "public"}
        ]
        self.assertIn("## 10. Tenant boundaries", render.render_threat_model(populated))


class TestArtifactKindDetection(unittest.TestCase):
    """Artifacts that are not audit reports get their own schema by filename
    and are not failed by the code-audit cross-checks."""

    REFUTED_REGISTER = {
        "source": "repo-triage.json",
        "generated_at": "2026-01-01T00:00:00Z",
        "entries": [
            {
                "finding_ref": "FIND-001",
                "title": "Refuted claim",
                "refute_reasons": ["misread_code"],
                "tier": "countersign",
                "evidence_refs": ["src/main.py:1"],
                "asserted_at": "2026-01-01T00:00:00Z",
                "asserted_by": "triage/1.0.0",
                "note": "Execution evidence overrides.",
            }
        ],
    }
    PRIV_PROFILE = {
        "repo": "example-operator",
        "summary": {
            "workloads": 1,
            "privileged_or_host_workloads": 0,
            "rbac_rules": 1,
            "distinct_rule_triples": 1,
            "distinct_cluster_triples": 0,
            "cluster_scoped_rules": 0,
            "scc_requests": [],
            "wildcard_rules": 0,
            "no_scc_request_recorded": True,
        },
    }

    def _validate(self, name, document, strict=False):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / name
            path.write_text(json.dumps(document), encoding="utf-8")
            schema = load_schema(validate.detect_schema_path(path))
            return validate.validate_report(
                str(path), schema, strict=strict, registry=validate.build_registry()
            )

    def test_a_verification_report_passes_its_own_checks(self):
        result = self._validate("repo-remediation-verification.json", _valid_verification_report())
        self.assertTrue(result.passed, result.errors)

    def test_registers_and_profiles_skip_the_audit_crosschecks(self):
        """They have no severity_criteria or findings_summary, and must not
        be failed for lacking them."""
        for name, document in (
            ("repo-refuted-register.json", self.REFUTED_REGISTER),
            ("repo-priv-profile.json", self.PRIV_PROFILE),
        ):
            result = self._validate(name, document, strict=True)
            self.assertTrue(result.passed, (name, result.errors))
            self.assertEqual(result.warnings, [], name)

    def test_the_schema_still_applies(self):
        document = copy.deepcopy(self.REFUTED_REGISTER)
        del document["entries"]
        result = self._validate("repo-refuted-register.json", document)
        self.assertFalse(result.passed)
        self.assertTrue(any("entries" in e for e in result.errors), result.errors)


def _valid_live_validation_report():
    return {
        "title": "Live validation of a synthetic application",
        "metadata": {
            "date": "2026-10-23",
            "harness_version": "0.175.0",
            "scope_binding_mode": "explicit",
            "target_fingerprint": [],
        },
        "source_reports": [{"kind": "security-audit", "path": "source-audit.json"}],
        "summary": {
            "by_verdict": {
                "confirmed": 0,
                "refuted": 0,
                "inconclusive": 0,
                "blocked_by_scope": 0,
                "not_attempted": 0,
            },
            "by_technique": {},
        },
        "validated_findings": [],
        "attack_chains": [],
        "novel_findings": [],
        "execution_log_ref": "validation-audit.jsonl",
    }


def _valid_readiness_report():
    return {
        "title": "Synthetic PQC readiness assessment",
        "metadata": {
            "repository": "https://github.com/example/widget",
            "assessment_basis": "source",
            "tool": {"pqc_scan_commit": "fixture", "rules_sha256": "a" * 64},
        },
        "summary": {"by_rule": {}},
        "status": "ready",
        "who_sets_tls": "this_app",
        "quantum_ready": "yes_by_default",
        "why_not": [],
        "do_next": [],
        "capabilities": {},
        "scores": {
            **{domain: {"score": 0, "checks": []} for domain in ("VULN", "AGIL", "PQCA", "HNDL")},
            "overall": 0,
        },
        "flags": {
            "has_2030_clock_items": False,
            "hndl_priority": False,
            "runtime_verification_required": True,
        },
        "provenance_summary": {"counts": {}, "dominant": "none"},
        "readiness_bucket": "ready",
    }


class TestReportingFamilyDispatch(unittest.TestCase):
    def setUp(self):
        self.engine = HarnessEngine.load(config_home=Path(__file__).parent / "fixtures" / "config")

    def test_each_family_enforces_its_own_contract_and_semantics(self):
        cases = (
            ("sample-validation.json", _valid_live_validation_report, "validation"),
            ("sample-verification.json", _valid_verification_report, "verification"),
            ("sample-pqc-readiness.json", _valid_readiness_report, "readiness"),
        )
        with tempfile.TemporaryDirectory() as directory:
            for name, build, family in cases:
                with self.subTest(family=family):
                    document = build()
                    path = Path(directory) / name
                    path.write_text(json.dumps(document), encoding="utf-8")
                    (valid,) = self.engine.reporting.validate(path, strict=True)
                    self.assertTrue(valid.passed, valid.errors)
                    if family == "validation":
                        document["summary"]["by_verdict"]["confirmed"] = 1
                    elif family == "verification":
                        document["summary"]["total_findings"] += 1
                    else:
                        document["provenance_summary"]["dominant"] = "invented"
                    path.write_text(json.dumps(document), encoding="utf-8")
                    (invalid,) = self.engine.reporting.validate(path)
                    self.assertFalse(invalid.passed, invalid.errors)

    def test_directory_sweep_does_not_validate_readiness_as_an_audit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, document in (
                ("sample-validation.json", _valid_live_validation_report()),
                ("sample-remediation-verification.json", _valid_verification_report()),
                ("sample-pqc-readiness.json", _valid_readiness_report()),
            ):
                (root / name).write_text(json.dumps(document), encoding="utf-8")
            results = self.engine.reporting.validate(root, strict=True)
            self.assertEqual(
                {Path(result.file_path).name for result in results},
                {
                    "sample-validation.json",
                    "sample-remediation-verification.json",
                    "sample-pqc-readiness.json",
                },
            )
            self.assertTrue(
                all(result.passed for result in results),
                [result.errors for result in results if not result.passed],
            )

    def test_explicit_schema_override_takes_precedence_over_filename(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample-validation.json"
            path.write_text(json.dumps(_valid_verification_report()), encoding="utf-8")
            (automatic,) = self.engine.reporting.validate(path)
            self.assertFalse(automatic.passed)
            (explicit,) = self.engine.reporting.validate(
                path, schema=SCHEMA_DIR / "verification.schema.json"
            )
            self.assertTrue(explicit.passed, explicit.errors)
