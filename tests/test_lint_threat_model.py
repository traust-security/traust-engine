#!/usr/bin/env python3
"""Unit tests for traust reporting lint."""

import tempfile
import unittest
from pathlib import Path

from traust_engine.reporting.lint import collect, lint_file

VALID = """# Threat Model: example-service

## 1. System context

An attacker could take over the service by uploading a malformed audio
file. The most important action is sandboxing the decoder.

example-service decodes user-supplied audio files.

### Threat actor landscape

`opportunistic` — internet-exposed decoder with public exploit history.

## 2. Assets

| asset | description | sensitivity | regulatory_scope | example_records |
|---|---|---|---|---|
| host process integrity | native decoder memory | critical | none | |
| user PII | uploader account records | high | GDPR | name, email |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| audio file upload | WAV/FLAC decode path | untrusted file → process memory | host process integrity |
| admin API | operator-only config | remote_auth → admin | user PII |

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | RCE via untrusted audio file parsing | remote_unauth | audio file upload | host process integrity | critical | likely | unmitigated | none | CVE-2026-29022, abc1234def |
| T2 | linddun: re-identification via exported logs | remote_auth | admin API | user PII | medium | possible | partially_mitigated | RBAC | |

## 5. Deprioritized

| threat | reason |
|---|---|
| physical access | out of scope |

## 6. Open questions

- Is the decoder sandboxed in production?

## 7. Provenance

- mode: bootstrap
- date: 2026-07-12
- target: targets/example @ abc1234
- inputs: none
- owner: unset
- harness_version: 0.33.0-abc1234

### Update history

| date | changes | reason |
|---|---|---|
| 2026-07-12 | added T2 | LINDDUN overlay |

## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| sandbox the decoder process | T1 | yes | M |

## 9. Attack scenarios

### T1 — RCE via untrusted audio file parsing

An opportunistic attacker uploads a crafted WAV file. The decoder trusts
the length field and corrupts memory, handing over the process. Every
upload endpoint reaches this code, and no sandbox contains it.
"""


VALID_ISOLATION = """# Threat Model: example-mt-service

## 1. System context

A tenant could read another tenant's records through an authorization gap
in the shared API. The most important action is scoping queries by tenant.

example-mt-service serves many tenants from one shared deployment.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| tenant data | per-tenant records | critical |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| tenant api | REST API, per-tenant tokens | tenant → shared service | tenant data |

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence | attack_refs | isolation_dimensions |
|---|---|---|---|---|---|---|---|---|---|---|---|
| T1 | Cross-tenant data read via missing query scoping on the tenant api | remote_auth | tenant api | tenant data | critical | possible | unmitigated | none | | | privilege, authentication |
| T2 | DoS via tenant api flood | remote_unauth | tenant api | tenant data | medium | possible | mitigated | rate limit | | | |

## 5. Deprioritized

| threat | reason |
|---|---|

## 6. Open questions

- none

## 7. Provenance

- mode: bootstrap
- date: 2026-07-20
- target: targets/example-mt @ abc1234
- inputs: none
- owner: unset
- harness_version: 0.119.0-abc1234

## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| scope every query by the caller's tenant id | T1 | yes | S |

## 10. Tenant boundaries

| boundary_id | interface | kind | exposure | complexity | privilege | encryption | authentication | connectivity | hygiene | threat_ids | isolation_review_ref |
|---|---|---|---|---|---|---|---|---|---|---|---|
| IF-1 | tenant api | api | tenant | high | partial | yes | no | yes | partial | T1 | 0f0e1d2c-3b4a-4968-87a9-8c7d6e5f4a3b |
| IF-2 | metrics store | data-store | internal | low | yes | na | yes | yes | yes | | |
"""


def lint_text(text, strict=False):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "THREAT_MODEL.md"
        p.write_text(text, encoding="utf-8")
        return lint_file(p, strict=strict)


class TestValidModel(unittest.TestCase):
    def test_valid_passes(self):
        errors, warnings = lint_text(VALID)
        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])


class TestStructure(unittest.TestCase):
    def test_missing_title(self):
        errors, _ = lint_text(VALID.replace("# Threat Model: example-service", "# example"))
        self.assertTrue(any("first line" in e for e in errors))

    def test_missing_required_section(self):
        errors, _ = lint_text(VALID.replace("## 6. Open questions", "## 6. Questions"))
        self.assertTrue(any("6. Open questions" in e for e in errors))

    def test_wrong_threat_columns(self):
        errors, _ = lint_text(
            VALID.replace(
                "| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |",
                "| id | threat | actor | surface | asset | impact | likelihood | status | evidence |",
            )
        )
        self.assertTrue(any("section 4 columns" in e for e in errors))


class TestEnums(unittest.TestCase):
    def test_bad_actor(self):
        errors, _ = lint_text(VALID.replace("remote_unauth", "hacker"))
        self.assertTrue(any("actor 'hacker'" in e for e in errors))

    def test_multi_actor_ok(self):
        errors, _ = lint_text(VALID.replace("| remote_unauth |", "| remote_unauth, supply_chain |"))
        self.assertEqual([e for e in errors if "actor" in e], [])

    def test_multi_actor_bad_member(self):
        errors, _ = lint_text(VALID.replace("| remote_unauth |", "| remote_unauth, tenant |"))
        self.assertTrue(any("actor 'tenant'" in e for e in errors))

    def test_effort_xs_and_closes_class_no_ok(self):
        errors, _ = lint_text(
            VALID.replace(
                "| sandbox the decoder process | T1 | yes | M |",
                "| sandbox the decoder process | T1 | no | XS |",
            )
        )
        self.assertEqual([e for e in errors if "section 8" in e], [])

    def test_bad_impact(self):
        errors, _ = lint_text(VALID.replace("| critical | likely |", "| severe | likely |"))
        self.assertTrue(any("impact 'severe'" in e for e in errors))

    def test_bad_sensitivity(self):
        errors, _ = lint_text(
            VALID.replace(
                "| native decoder memory | critical |", "| native decoder memory | urgent |"
            )
        )
        self.assertTrue(any("sensitivity 'urgent'" in e for e in errors))


class TestIds(unittest.TestCase):
    def test_duplicate_id(self):
        errors, _ = lint_text(VALID.replace("| T2 | linddun:", "| T1 | linddun:"))
        self.assertTrue(any("duplicate id 'T1'" in e for e in errors))

    def test_section8_unknown_id(self):
        errors, _ = lint_text(
            VALID.replace(
                "| sandbox the decoder process | T1 |", "| sandbox the decoder process | T9 |"
            )
        )
        self.assertTrue(any("unknown threat id 'T9'" in e for e in errors))

    def test_section9_unknown_id(self):
        errors, _ = lint_text(VALID.replace("### T1 — RCE", "### T7 — RCE"))
        self.assertTrue(any("scenario 'T7'" in e for e in errors))


class TestCoverageInvariant(unittest.TestCase):
    def test_uncovered_entry_point(self):
        broken = VALID.replace(
            "| admin API | operator-only config | remote_auth → admin | user PII |",
            "| admin API | operator-only config | remote_auth → admin | user PII |\n"
            "| metrics endpoint | prometheus scrape | unauth network → metrics | user PII |",
        )
        errors, _ = lint_text(broken)
        self.assertTrue(any("coverage: entry point 'metrics endpoint'" in e for e in errors))

    def test_deprioritized_covers(self):
        parked = VALID.replace(
            "| physical access | out of scope |",
            "| physical access | out of scope |\n| metrics endpoint | scrape-only, no data |",
        ).replace(
            "| admin API | operator-only config | remote_auth → admin | user PII |",
            "| admin API | operator-only config | remote_auth → admin | user PII |\n"
            "| metrics endpoint | prometheus scrape | unauth network → metrics | user PII |",
        )
        errors, _ = lint_text(parked)
        self.assertEqual([e for e in errors if "coverage" in e], [])


class TestEvidenceHygiene(unittest.TestCase):
    def test_file_line_in_evidence_is_error(self):
        errors, _ = lint_text(VALID.replace("CVE-2026-29022, abc1234def", "src/decode.c:412"))
        self.assertTrue(any("file:line" in e for e in errors))

    def test_unknown_token_warns(self):
        errors, warnings = lint_text(VALID.replace("CVE-2026-29022, abc1234def", "we saw it once"))
        self.assertEqual([e for e in errors if "evidence" in e], [])
        self.assertTrue(any("not a recognized vuln reference" in w for w in warnings))

    def test_canonical_ledger_id_ok(self):
        _, warnings = lint_text(
            VALID.replace("CVE-2026-29022, abc1234def", "EXAMPLE_PRODUCT-abc1234-010")
        )
        self.assertEqual([w for w in warnings if "evidence" in w], [])

    def test_prose_forms_ok(self):
        _, warnings = lint_text(
            VALID.replace(
                "CVE-2026-29022, abc1234def",
                "EXAMPLE_PRODUCT-abc1234-010, -011, "
                "commit a1b2c3d (exploited in the wild), commits e4f5a6b",
            )
        )
        self.assertEqual([w for w in warnings if "evidence" in w], [])


class TestProvenance(unittest.TestCase):
    def test_missing_key(self):
        errors, _ = lint_text(VALID.replace("- owner: unset\n", ""))
        self.assertTrue(any("missing 'owner'" in e for e in errors))

    def test_bad_mode(self):
        errors, _ = lint_text(VALID.replace("- mode: bootstrap", "- mode: quick"))
        self.assertTrue(any("mode 'quick'" in e for e in errors))

    def test_missing_harness_version_warns_only(self):
        errors, warnings = lint_text(VALID.replace("- harness_version: 0.33.0-abc1234\n", ""))
        self.assertEqual([e for e in errors if "harness_version" in e], [])
        self.assertTrue(any("harness_version" in w for w in warnings))

    def test_bad_update_history_date(self):
        errors, _ = lint_text(VALID.replace("| 2026-07-12 | added T2 |", "| July 12 | added T2 |"))
        self.assertTrue(any("update-history date" in e for e in errors))


class TestSortWarning(unittest.TestCase):
    def test_unsorted_warns(self):
        swapped = VALID.replace(
            "| T1 | RCE via untrusted audio file parsing | remote_unauth | audio file upload | host process integrity | critical | likely | unmitigated | none | CVE-2026-29022, abc1234def |\n"
            "| T2 | linddun: re-identification via exported logs | remote_auth | admin API | user PII | medium | possible | partially_mitigated | RBAC | |",
            "| T2 | linddun: re-identification via exported logs | remote_auth | admin API | user PII | medium | possible | partially_mitigated | RBAC | |\n"
            "| T1 | RCE via untrusted audio file parsing | remote_unauth | audio file upload | host process integrity | critical | likely | unmitigated | none | CVE-2026-29022, abc1234def |",
        )
        errors, warnings = lint_text(swapped)
        self.assertEqual([e for e in errors if "sort" in e.lower()], [])
        self.assertTrue(any("not sorted" in w for w in warnings))


class TestEscapedPipes(unittest.TestCase):
    def test_escaped_pipe_in_cell_does_not_split(self):
        piped = VALID.replace(
            "| none | CVE-2026-29022, abc1234def |",
            "| `--max-time 3` and `\\|\\| true` only | CVE-2026-29022, abc1234def |",
        ).replace(
            "| sandbox the decoder process | T1 | yes | M |",
            "| enforce `^(a\\.com\\|b\\.net)$` allowlist | T1 | yes | M |",
        )
        errors, _ = lint_text(piped)
        self.assertEqual(errors, [])


class TestTenantBoundaries(unittest.TestCase):
    """PEACH isolation lens Phase 1: optional section 10 +
    optional trailing isolation_dimensions column. Both must lint clean
    when present and remain optional when absent (TestValidModel covers
    the without-case: VALID has neither and passes)."""

    def test_isolation_fixture_passes(self):
        errors, warnings = lint_text(VALID_ISOLATION)
        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])

    def test_isolation_column_without_section10_ok(self):
        no_sec10 = VALID_ISOLATION[: VALID_ISOLATION.index("## 10. Tenant boundaries")]
        errors, _ = lint_text(no_sec10)
        self.assertEqual(errors, [])

    def test_bad_isolation_dimension_token(self):
        errors, _ = lint_text(
            VALID_ISOLATION.replace("| privilege, authentication |", "| privilege, network |")
        )
        self.assertTrue(any("isolation_dimensions 'network'" in e for e in errors))

    def test_bad_boundary_kind(self):
        errors, _ = lint_text(
            VALID_ISOLATION.replace(
                "| tenant api | api | tenant |", "| tenant api | rest | tenant |"
            )
        )
        self.assertTrue(any("kind 'rest'" in e for e in errors))

    def test_bad_exposure(self):
        errors, _ = lint_text(
            VALID_ISOLATION.replace(
                "| tenant api | api | tenant | high |", "| tenant api | api | everyone | high |"
            )
        )
        self.assertTrue(any("exposure 'everyone'" in e for e in errors))

    def test_bad_complexity(self):
        errors, _ = lint_text(
            VALID_ISOLATION.replace("| api | tenant | high |", "| api | tenant | extreme |")
        )
        self.assertTrue(any("complexity 'extreme'" in e for e in errors))

    def test_bad_dimension_result(self):
        errors, _ = lint_text(
            VALID_ISOLATION.replace(
                "| partial | yes | no | yes | partial |",
                "| partial | yes | maybe | yes | partial |",
            )
        )
        self.assertTrue(any("authentication 'maybe'" in e for e in errors))

    def test_unknown_threat_id_in_boundary(self):
        errors, _ = lint_text(VALID_ISOLATION.replace("| partial | T1 |", "| partial | T9 |"))
        self.assertTrue(any("unknown threat id 'T9'" in e and "section 10" in e for e in errors))

    def test_bad_boundary_id(self):
        errors, _ = lint_text(VALID_ISOLATION.replace("| IF-2 |", "| B2 |"))
        self.assertTrue(any("boundary_id 'B2'" in e for e in errors))

    def test_duplicate_boundary_id(self):
        errors, _ = lint_text(VALID_ISOLATION.replace("| IF-2 |", "| IF-1 |"))
        self.assertTrue(any("duplicate boundary_id 'IF-1'" in e for e in errors))

    def test_bad_isolation_review_ref(self):
        errors, _ = lint_text(
            VALID_ISOLATION.replace(
                "0f0e1d2c-3b4a-4968-87a9-8c7d6e5f4a3b", "somewhere/else/entirely"
            )
        )
        self.assertTrue(any("isolation_review_ref" in e for e in errors))

    def test_isolation_review_ref_is_an_artifact_id(self):
        """A boundary names its isolation review by the artifact row's id — the store owns
        artifacts, and a file path is not an id."""
        errors, _ = lint_text(
            VALID_ISOLATION.replace(
                "analysis-results/isolation/example-mt-service/",
                "0f0e1d2c-3b4a-4968-87a9-8c7d6e5f4a3b",
            )
        )
        self.assertEqual(errors, [])

    def test_wrong_section10_columns(self):
        errors, _ = lint_text(
            VALID_ISOLATION.replace("| boundary_id | interface |", "| id | interface |")
        )
        self.assertTrue(any("section 10 columns" in e for e in errors))


class TestCollect(unittest.TestCase):
    def test_collect_both_filenames_and_skips_symlinks(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "a").mkdir()
            (root / "a" / "THREAT_MODEL.md").write_text(VALID)
            (root / "a" / "svc-threat-model.md").write_text(VALID)
            (root / "a" / "link-threat-model.md").symlink_to(root / "a" / "svc-threat-model.md")
            files = collect([str(root)])
            names = sorted(f.name for f in files)
            self.assertEqual(names, ["THREAT_MODEL.md", "svc-threat-model.md"])

    def test_collect_skips_artifacts_dirs_in_sweeps(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "repo" / "artifacts" / "worker-01").mkdir(parents=True)
            (root / "repo").joinpath("repo-threat-model.md").write_text(VALID)
            (root / "repo" / "artifacts" / "worker-01" / "THREAT_MODEL.md").write_text("scratch")
            files = collect([str(root)])
            self.assertEqual([f.name for f in files], ["repo-threat-model.md"])
            # explicit file path still lints
            explicit = collect([str(root / "repo" / "artifacts" / "worker-01" / "THREAT_MODEL.md")])
            self.assertEqual(len(explicit), 1)


if __name__ == "__main__":
    unittest.main()
