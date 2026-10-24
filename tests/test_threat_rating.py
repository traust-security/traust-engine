"""OWASP Risk Rating in threat models: schema, rendering, lint, corpus parse.

The worked example is the one in the OWASP Risk Rating Methodology
(https://owasp.org/www-community/OWASP_Risk_Rating_Methodology): likelihood
4.375 (medium), technical impact 7.25 (high), severity high; business impact
2.25 (low), severity low.
"""

import copy
import json
import tempfile
import unittest
from pathlib import Path

from traust_contracts.v1 import risk_rating as rr

from traust_engine.reporting import lint, render, threat_rating, validate

LIKELIHOOD = {
    "skill_level": 5,
    "motive": 2,
    "opportunity": 7,
    "population_size": 1,
    "ease_of_discovery": 3,
    "ease_of_exploit": 6,
    "awareness": 9,
    "intrusion_detection": 2,
}
TECHNICAL = {"confidentiality": 9, "integrity": 7, "availability": 5, "accountability": 8}
BUSINESS = {"financial": 1, "reputation": 2, "non_compliance": 1, "privacy": 5}

LEGACY_THREAT = {
    "id": "T2",
    "threat": "Denial of service via decode exhaustion",
    "actor": ["remote_unauth"],
    "surface": "api",
    "asset": "availability",
    "impact": "medium",
    "likelihood": "possible",
    "status": "unmitigated",
    "controls": "none",
    "evidence": [],
    "attack_refs": ["T1499"],
}


def rated_threat(tid="T1", business=None, basis=None):
    return {
        "id": tid,
        "threat": "Token theft via log leak",
        "actor": ["remote_auth"],
        "surface": "api",
        "asset": "tokens",
        "risk_rating": rr.rate(
            LIKELIHOOD,
            TECHNICAL,
            business,
            basis=basis,
            rationale={"awareness": "the leak pattern is publicly documented"},
        ),
        "status": "unmitigated",
        "controls": "none",
        "evidence": ["FIND-001"],
        "attack_refs": ["T1552"],
    }


def document(*threats):
    return {
        "system": "example",
        "provenance": {
            "mode": "bootstrap",
            "date": "2026-09-30",
            "target": "https://example.test/repo @ abc1234",
            "harness_version": "0.13.0",
        },
        "threats": list(threats),
    }


def lint_markdown(markdown):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "repo-threat-model.md"
        path.write_text(markdown, encoding="utf-8")
        return lint.lint_file(path)


class TestSchema(unittest.TestCase):
    def _validate(self, doc):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "repo-threat-model.json"
            path.write_text(json.dumps(doc), encoding="utf-8")
            schema = json.loads(validate.detect_schema_path(path).read_text(encoding="utf-8"))
            return validate.validate_report(str(path), schema)

    def test_rated_threat_without_legacy_labels_validates(self):
        result = self._validate(document(rated_threat()))
        self.assertTrue(result.passed, result.errors)

    def test_derived_values_that_disagree_with_the_factors_fail(self):
        threat = rated_threat()
        threat["risk_rating"]["severity"] = "critical"
        threat["risk_rating"]["likelihood"]["score"] = 7
        result = self._validate(document(threat))
        self.assertFalse(result.passed)
        self.assertTrue(
            any("T1" in e and "likelihood.score is 7" in e for e in result.errors), result.errors
        )
        self.assertTrue(any("severity is 'critical'" in e for e in result.errors), result.errors)

    def test_threat_with_neither_rating_fails(self):
        threat = rated_threat()
        del threat["risk_rating"]
        self.assertFalse(self._validate(document(threat)).passed)


class TestRender(unittest.TestCase):
    def test_rated_model_uses_owasp_columns_and_cells(self):
        markdown = render.render_threat_model(document(rated_threat()))
        header = "| " + " | ".join(render.THREAT_COLUMNS_OWASP) + " |"
        self.assertIn(header, markdown)
        self.assertIn("| high | medium 4.375 | high 7.25 technical |", markdown)
        self.assertIn("## 11. Risk ratings", markdown)
        self.assertIn(rr.SOURCE, markdown)
        self.assertIn("| awareness | 9 | the leak pattern is publicly documented |", markdown)

    def test_business_basis_is_written_in_the_impact_cell(self):
        markdown = render.render_threat_model(document(rated_threat(business=BUSINESS)))
        self.assertIn("| low | medium 4.375 | low 2.25 business |", markdown)
        self.assertIn("| privacy | 5 |", markdown)

    def test_unrated_threat_in_a_rated_model_keeps_its_legacy_labels(self):
        markdown = render.render_threat_model(document(rated_threat(), LEGACY_THREAT))
        self.assertIn("| unrated | legacy possible | legacy medium |", markdown)
        self.assertNotIn("### T2", markdown)

    def test_legacy_model_renders_unchanged(self):
        markdown = render.render_threat_model(document(LEGACY_THREAT))
        self.assertIn("| " + " | ".join(render.THREAT_COLUMNS) + " |", markdown)
        self.assertNotIn("severity", markdown)
        self.assertNotIn("## 11.", markdown)


class TestLint(unittest.TestCase):
    def test_rendered_rated_models_lint_clean(self):
        for doc in (
            document(rated_threat()),
            document(rated_threat(business=BUSINESS)),
            document(rated_threat(business=BUSINESS, basis="technical")),
            document(rated_threat(), LEGACY_THREAT),
        ):
            errors, _ = lint_markdown(render.render_threat_model(doc))
            self.assertEqual(errors, [], errors)

    def test_rated_model_with_update_history_lints_clean(self):
        doc = document(rated_threat(), LEGACY_THREAT)
        doc["update_history"] = [
            {"date": "2026-10-01", "changes": "rated T1 with OWASP", "reason": "migration"}
        ]
        markdown = render.render_threat_model(doc)
        provenance = markdown[markdown.index("## 7. Provenance") : markdown.index("## 11.")]
        self.assertIn("### Update history", provenance)
        errors, _ = lint_markdown(markdown)
        self.assertEqual(errors, [], errors)

    def test_optional_asset_columns_and_scenario_prose_survive(self):
        doc = document(rated_threat())
        doc["assets"] = [
            {
                "asset": "tokens",
                "description": "API tokens",
                "sensitivity": "high",
                "regulatory_scope": "GDPR",
                "example_records": "bearer tokens",
            }
        ]
        doc["attack_scenarios"] = [
            {"id": "T1", "threat": "Token theft", "steps": ["An attacker reads the log."]}
        ]
        markdown = render.render_threat_model(doc)
        self.assertIn(
            "| asset | description | sensitivity | regulatory_scope | example_records |", markdown
        )
        self.assertIn("| tokens | API tokens | high | GDPR | bearer tokens |", markdown)
        self.assertIn("### T1 — Token theft\n\nAn attacker reads the log.\n", markdown)
        errors, _ = lint_markdown(markdown)
        self.assertEqual(errors, [], errors)

    def test_severity_that_does_not_follow_from_the_levels_fails(self):
        markdown = render.render_threat_model(document(rated_threat()))
        bad = markdown.replace(
            "| high | medium 4.375 | high 7.25 technical |",
            "| critical | medium 4.375 | high 7.25 technical |",
        )
        errors, _ = lint_markdown(bad)
        self.assertTrue(any("severity 'critical' should be 'high'" in e for e in errors), errors)

    def test_level_that_does_not_match_its_score_fails(self):
        markdown = render.render_threat_model(document(rated_threat()))
        bad = markdown.replace("medium 4.375", "high 4.375")
        errors, _ = lint_markdown(bad)
        self.assertTrue(any("likelihood level 'high' should be 'medium'" in e for e in errors))

    def test_factor_table_must_reproduce_the_row(self):
        markdown = render.render_threat_model(document(rated_threat()))
        bad = markdown.replace("| confidentiality | 9 |", "| confidentiality | 1 |")
        errors, _ = lint_markdown(bad)
        self.assertTrue(any("factors give impact_score 5.25" in e for e in errors), errors)

    def test_missing_factor_fails(self):
        markdown = render.render_threat_model(document(rated_threat()))
        lines = [line for line in markdown.splitlines() if not line.startswith("| motive |")]
        errors, _ = lint_markdown("\n".join(lines) + "\n")
        self.assertTrue(any("missing factor(s) ['motive']" in e for e in errors), errors)

    def test_rated_model_without_section_11_fails(self):
        markdown = render.render_threat_model(document(rated_threat()))
        cut = markdown[: markdown.index("## 11. Risk ratings")]
        errors, _ = lint_markdown(cut)
        self.assertTrue(any("section 11 (Risk ratings) is missing" in e for e in errors), errors)

    def test_legacy_label_under_a_rated_severity_fails(self):
        markdown = render.render_threat_model(document(rated_threat(), LEGACY_THREAT))
        bad = markdown.replace("| unrated | legacy possible |", "| medium | legacy possible |")
        errors, _ = lint_markdown(bad)
        self.assertTrue(any("section 4 T2: likelihood" in e for e in errors), errors)

    def test_unsorted_rated_rows_warn(self):
        low = rated_threat("T2", business=BUSINESS)
        markdown = render.render_threat_model(document(low, rated_threat("T1")))
        _, warnings = lint_markdown(markdown)
        self.assertTrue(any("not sorted by (severity desc" in w for w in warnings), warnings)


class TestOrdering(unittest.TestCase):
    def test_crosswalk_orders_legacy_labels_on_the_owasp_table(self):
        self.assertEqual(threat_rating.legacy_severity("existential", "almost_certain"), "critical")
        self.assertEqual(threat_rating.legacy_severity("critical", "rare"), "medium")
        self.assertEqual(threat_rating.legacy_severity("low", "very_rare"), "note")
        self.assertIsNone(threat_rating.legacy_severity("bogus", "likely"))

    def test_rated_rows_sort_ahead_of_crosswalked_rows_of_the_same_severity(self):
        rated = threat_rating.parse_row(
            {"severity": "high", "likelihood": "medium 4.375", "impact": "high 7.25 technical"}
        )
        legacy = threat_rating.parse_row({"impact": "critical", "likelihood": "possible"})
        self.assertEqual(legacy["severity"], "high")
        self.assertLess(threat_rating.order_key(rated), threat_rating.order_key(legacy))

    def test_threat_severity_prefers_the_rating(self):
        self.assertEqual(threat_rating.threat_severity(rated_threat()), ("high", "owasp"))
        self.assertEqual(
            threat_rating.threat_severity(copy.deepcopy(LEGACY_THREAT)),
            ("medium", "legacy-crosswalk"),
        )


if __name__ == "__main__":
    unittest.main()
