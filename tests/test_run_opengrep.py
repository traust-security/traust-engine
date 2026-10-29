#!/usr/bin/env python3
"""run_opengrep.py tests — normalization is pure-python; end-to-end runs
only when the opengrep binary is on PATH (skipped otherwise)."""

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import pytest
from traust_contracts import optional_config_path

from traust_engine.adapters import opengrep as R
from traust_engine.assets import default_rule_pack_dir


def _deployment_allowlist():
    """The DEPLOYMENT's rule-pack allowlist — the promotion record these
    tests audit. Lives in the deployment config dir, not the package; skip
    when this checkout has none (open-source CI)."""
    p = optional_config_path("rule-pack-allowlist.yaml")
    if p is None or not p.is_file():
        pytest.skip("no deployment config dir with rule-pack-allowlist.yaml")
    return p


TRAUST_PACK = default_rule_pack_dir()

RAW = {
    "results": [
        {
            "check_id": "rules.go-sqli-taint",
            "path": "/repo/main.go",
            "start": {"line": 10},
            "end": {"line": 11},
            "extra": {
                "severity": "ERROR",
                "message": "tainted query",
                "lines": "db.Query(q)",
                "dataflow_trace": {"taint_source": []},
                "metadata": {"cwe": "CWE-89", "owasp": ["A03:2021"], "confidence": "HIGH"},
            },
        },
        {
            "check_id": "rules.llm-output-to-sql",
            "path": "/repo/ask.py",
            "start": {"line": 5},
            "end": {"line": 5},
            "extra": {
                "severity": "ERROR",
                "message": "model output to SQL",
                "metadata": {"cwe": ["CWE-1426", "CWE-89"], "owasp_llm": "LLM05"},
            },
        },
        {
            "check_id": "rules.open-encoding",
            "path": "/repo/test/util_test.py",
            "start": {"line": 3},
            "end": {"line": 3},
            "extra": {"severity": "INFO", "message": "m", "metadata": {}},
        },
    ],
    "errors": [
        {"level": "warn", "type": "ParseError", "message": "x" * 500, "path": "/repo/gen.go"}
    ],
    "paths": {"scanned": ["/repo/main.go", "/repo/test/util_test.py"]},
    "skipped_rules": [],
}


class TestNormalize(unittest.TestCase):
    def test_fact_shape_and_severity_mapping(self):
        facts, _errors = R.normalize(RAW, Path("/repo"))
        self.assertEqual(len(facts), 3)
        f = facts[0]
        # check_id path prefixes are stripped to the bare rule id
        self.assertEqual(f["rule_id"], "go-sqli-taint")
        self.assertEqual(f["severity_hint"], "high")
        self.assertEqual(f["file"], "main.go")
        self.assertEqual((f["start_line"], f["end_line"]), (10, 11))
        self.assertEqual(f["cwe"], ["CWE-89"])  # str normalized to list
        self.assertEqual(f["owasp"], ["A03:2021"])
        self.assertEqual(f["owasp_llm"], [])
        self.assertTrue(f["taint"])
        self.assertFalse(f["test_path"])

    def test_test_path_tagged_and_info_is_low(self):
        facts, _ = R.normalize(RAW, Path("/repo"))
        self.assertTrue(facts[2]["test_path"])
        self.assertEqual(facts[2]["severity_hint"], "low")
        self.assertFalse(facts[2]["taint"])

    def test_owasp_llm_carried_and_str_normalized(self):
        facts, _ = R.normalize(RAW, Path("/repo"))
        self.assertEqual(facts[1]["owasp_llm"], ["LLM05"])
        self.assertEqual(facts[1]["cwe"], ["CWE-1426", "CWE-89"])

    def test_bare_rule_id_strips_dotted_path_prefixes(self):
        cases = {
            "traust-go-ssrf-request-taint": "traust-go-ssrf-request-taint",
            "go.traust-go-ssrf-request-taint": "traust-go-ssrf-request-taint",
            "skills.secure-code-audit.opengrep-rules.bash."
            "traust-bash-data-exposure-xtrace": "traust-bash-data-exposure-xtrace",
            "": "",
        }
        for check_id, want in cases.items():
            self.assertEqual(R.bare_rule_id(check_id), want, check_id)

    def test_errors_surfaced_and_trimmed(self):
        _, errors = R.normalize(RAW, Path("/repo"))
        self.assertEqual(len(errors), 1)
        self.assertLessEqual(len(errors[0]["message"]), 300)


class TestRulesResolution(unittest.TestCase):
    def test_auto_is_refused(self):
        with self.assertRaises(SystemExit) as cm:
            R.resolve_rules(["auto"], Path())
        self.assertEqual(cm.exception.code, 2)

    def test_registry_shorthand_carries_license_note(self):
        resolved = R.resolve_rules(["p/golang"], Path())
        self.assertEqual(resolved[0]["config"], ["p/golang"])
        self.assertIn("license", resolved[0]["license_note"].lower())

    def test_local_path_used_as_is(self):
        with tempfile.TemporaryDirectory() as d:
            rules = Path(d) / "r.yaml"
            rules.write_text("rules: []\n")
            resolved = R.resolve_rules([str(rules)], Path())
            self.assertEqual(resolved[0]["config"], [str(rules.resolve())])

    def test_missing_local_path_exits(self):
        with self.assertRaises(SystemExit) as cm:
            R.resolve_rules(["/nonexistent/rules.yaml"], Path())
        self.assertEqual(cm.exception.code, 2)

    def test_default_is_traust_pack_language_filtered(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "main.go").write_text("package main")
            resolved = R.resolve_rules([], Path(d))
        self.assertEqual(len(resolved), 1)
        self.assertIn("traust rule pack", resolved[0]["source"])
        self.assertEqual(resolved[0]["config"], [str(TRAUST_PACK / "go")])
        self.assertIn("no external restrictions", resolved[0]["license_note"])

    def test_javascript_scans_with_the_typescript_rules(self):
        for name in ("app.js", "app.jsx", "app.mjs", "app.cjs"):
            with self.subTest(name), tempfile.TemporaryDirectory() as d:
                (Path(d) / name).write_text("module.exports = {};\n")
                (Path(d) / "ci.yaml").write_text("k: v\n")
                resolved = R.resolve_rules([], Path(d))
                self.assertEqual(
                    resolved[0]["config"],
                    [str(TRAUST_PACK / "typescript"), str(TRAUST_PACK / "yaml")],
                )

    def test_fork_supplement_pin_constants(self):
        # The fork stays available as an internal-run supplement.
        self.assertIn("opengrep-rules", R.FORK_RULES_REPO)
        self.assertEqual(len(R.FORK_RULES_SHA), 40)

    def test_traust_pack_exists_with_expected_languages(self):
        for lang in ("go", "python", "typescript", "yaml"):
            self.assertTrue((TRAUST_PACK / lang).is_dir(), lang)


class TestLanguageDetection(unittest.TestCase):
    def test_detects_and_excludes_vendor(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "a.go").write_text("package a")
            (root / "vendor").mkdir()
            (root / "vendor" / "b.py").write_text("x=1")
            self.assertEqual(R.detect_language_dirs(root), {"go"})


@pytest.mark.integration
@unittest.skipUnless(shutil.which("opengrep"), "opengrep not on PATH")
class TestEndToEnd(unittest.TestCase):
    def test_traust_pack_rule_tests_pass(self):
        for lang in ("go", "python", "typescript", "yaml"):
            proc = subprocess.run(
                # opengrep >= 1.25 moved fixture testing from
                # `scan --test` to the `test` subcommand
                ["opengrep", "test", str(TRAUST_PACK / lang)],
                capture_output=True,
                text=True,
            )
            self.assertIn("All tests passed", proc.stdout + proc.stderr, lang)

    def test_scan_with_local_rule(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "main.go").write_text(
                'package main\nimport "os/exec"\nfunc f(c string) { exec.Command("sh", "-c", c) }\n'
            )
            (root / "rule.yaml").write_text(
                "rules:\n"
                "  - id: sh-c\n"
                "    languages: [go]\n"
                "    severity: WARNING\n"
                "    message: shell exec\n"
                '    pattern: exec.Command("sh", "-c", ...)\n'
            )
            out = root / "facts.json"
            from traust_engine import HarnessEngine

            engine = HarnessEngine.load()
            report = R._execute_opengrep_scan(
                root,
                [str(root / "rule.yaml")],
                timeout=900,
                opengrep_bin="opengrep",
                rule_pack=TRAUST_PACK,
                rule_allow=None,
                allowlist=engine.adapters.allowlist_for_opengrep(),
                loc=engine.ctx.locations,
            )
            out.write_text(json.dumps(report), encoding="utf-8")
            rc = 0
            self.assertEqual(rc, 0)
            report = json.loads(out.read_text())
            self.assertEqual(report["stats"]["facts"], 1)
            fact = report["facts"][0]
            self.assertEqual(Path(fact["file"]).name, "main.go")
            self.assertEqual(fact["severity_hint"], "medium")
            self.assertTrue(report["opengrep_version"])


class TestCoverageBlock(unittest.TestCase):
    def test_javascript_coverage_counts_the_typescript_rules(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "server.js").write_text("module.exports = {};\n")
            cov = R.coverage_block(Path(d))
            self.assertEqual(cov["detected_languages"], ["javascript"])
            self.assertEqual(
                cov["traust_rules_by_language"]["javascript"],
                R.pack_rule_counts()["typescript"],
            )
            self.assertNotIn("javascript", cov["uncovered_languages"])

    def test_thin_and_uncovered_languages(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "a.py").write_text("x = 1\n")
            (root / "b.sh").write_text("echo hi\n")
            (root / "d.kt").write_text("fun main() {}\n")
            (root / "c.yaml").write_text("k: v\n")  # manifest — excluded
            cov = R.coverage_block(root)
            self.assertIn("python", cov["detected_languages"])
            self.assertIn("bash", cov["detected_languages"])
            self.assertNotIn("yaml", cov["detected_languages"])
            # python is at pack parity (>= threshold): neither thin nor
            # uncovered; bash has rules below the threshold: thin; kotlin
            # has no pack dir: uncovered
            self.assertGreaterEqual(
                cov["traust_rules_by_language"]["python"], R.THIN_RULE_THRESHOLD
            )
            self.assertNotIn("python", cov["thin_languages"])
            self.assertIn("bash", cov["thin_languages"])
            self.assertNotIn("bash", cov["uncovered_languages"])
            self.assertIn("kotlin", cov["uncovered_languages"])


if __name__ == "__main__":
    unittest.main()


class TestRuleAllowlist:
    """A calibrated subset of a large external pack must be enablable
    without its noisy remainder. argus ships 640 rules of which 19 are
    86% of volume; without this, shipping the 16 gate-clearing TLS rules
    meant shipping those 19 too."""

    def test_inline_list(self):
        allow, src = R.load_rule_allowlist("a-rule, b-rule")
        assert allow == {"a-rule", "b-rule"} and src == "inline"

    def test_none_means_no_filtering(self):
        assert R.load_rule_allowlist(None) == (None, None)
        assert R.load_rule_allowlist("") == (None, None)

    def test_reads_a_yaml_list_file(self, tmp_path):
        f = tmp_path / "a.yaml"
        f.write_text(
            "pack-name:\n  - go-tls-bypass   # 42 repos\n  - java-tls-bypass\n# a comment line\n"
        )
        allow, src = R.load_rule_allowlist(f"@{f}")
        assert allow == {"go-tls-bypass", "java-tls-bypass"}
        assert src == str(f)

    def test_empty_allowlist_fails_closed(self, tmp_path):
        """A filter that quietly stops filtering is worse than none: it
        would silently re-enable all 640 rules."""
        f = tmp_path / "empty.yaml"
        f.write_text("# nothing here\n")
        with pytest.raises(SystemExit):
            R.load_rule_allowlist(f"@{f}")
        with pytest.raises(SystemExit):
            R.load_rule_allowlist(",  ,")

    def test_missing_file_fails_closed(self, tmp_path):
        with pytest.raises(SystemExit):
            R.load_rule_allowlist(f"@{tmp_path / 'nope.yaml'}")

    def test_shipped_allowlist_matches_the_documented_tranche(self):
        """The config is the promotion record; drift between it and the
        evaluation's 16-rule tranche would be silent."""
        cfg = _deployment_allowlist()
        allow, _ = R.load_rule_allowlist(f"@{cfg}")
        assert len(allow) == 15
        assert "go-tls-bypass" in allow
        assert "typescript-http-client-tls-override" in allow
        # the excluded families must never appear here
        for banned in (
            "go-reflection-basic-usage",
            "python-pqc-oauth-jwt-saml",
            "go-unsafe-pointer-operations",
        ):
            assert banned not in allow


class TestSupplementalPacks:
    """The allowlist is the enable switch. Without audits reading it,
    the /mine-ledger lane could only observe a list it had no way to act
    on, and precision -- which exists only after a rule has run -- could
    never start accruing. That deadlock is what this wire closes."""

    def _cfg(self, tmp_path, enabled=True, rules=("r1", "r2"), source="https://x/y@" + "a" * 40):
        f = tmp_path / "rule-pack-allowlist.yaml"
        body = [
            "packs:",
            "  p:",
            f"    enabled: {str(enabled).lower()}",
            f"    source: {source}",
            "    rules:",
        ]
        body += [f"      - {r}" for r in rules]
        f.write_text("\n".join(body) + "\n")
        return f

    def test_reads_enabled_packs(self, tmp_path):
        got = R.load_supplemental_packs(self._cfg(tmp_path))
        assert len(got) == 1
        assert got[0]["name"] == "p" and got[0]["rules"] == ["r1", "r2"]

    def test_disabled_pack_is_off(self, tmp_path):
        assert R.load_supplemental_packs(self._cfg(tmp_path, enabled=False)) == []

    def test_pack_without_rules_is_ignored(self, tmp_path):
        """An enabled pack with no allowlist would mean 'everything' —
        exactly the wholesale enablement this design forbids."""
        assert R.load_supplemental_packs(self._cfg(tmp_path, rules=())) == []

    def test_malformed_config_does_not_break_the_default_scan(self, tmp_path):
        f = tmp_path / "bad.yaml"
        f.write_text("packs: [oh no\n  : :\n")
        assert R.load_supplemental_packs(f) == []

    def test_missing_config_is_simply_off(self, tmp_path):
        assert R.load_supplemental_packs(tmp_path / "nope.yaml") == []

    def test_shipped_config_enables_exactly_the_tranche(self):
        from traust_engine import HarnessEngine

        allowlist = HarnessEngine.load().adapters.allowlist_for_opengrep()
        packs = R.load_supplemental_packs(allowlist=allowlist)
        argus = [p for p in packs if p["name"] == "argus-observe-rules"]
        assert len(argus) == 1
        assert len(argus[0]["rules"]) == 15
        assert "@" in argus[0]["source"], "supplemental packs must be SHA-pinned"
        for banned in (
            "go-reflection-basic-usage",
            "python-pqc-oauth-jwt-saml",
            "go-unsafe-pointer-operations",
        ):
            assert banned not in argus[0]["rules"]

    def test_traust_pack_ids_are_not_suppressed(self):
        """Filtering is scoped to the supplement; our own calibrated
        rules must survive it."""
        ids = R.harness_pack_rule_ids()
        assert len(ids) > 20
        assert all(i.startswith("traust-") for i in ids)


class TestHeldBackRules:
    """A rule can clear the rediscovery gate and still be too expensive
    to switch on first. Held-back rules stay in the config as the record
    -- deleting them would lose the calibration and the reason -- but
    must never load."""

    def test_held_back_rules_do_not_load(self):
        from traust_engine import HarnessEngine

        allowlist = HarnessEngine.load().adapters.allowlist_for_opengrep()
        packs = R.load_supplemental_packs(allowlist=allowlist)
        argus = next(p for p in packs if p["name"] == "argus-observe-rules")
        assert "go-crypto-tls-version" not in argus["rules"]

    def test_held_back_record_is_retained_with_a_readmit_criterion(self):
        import yaml

        cfg = yaml.safe_load(_deployment_allowlist().read_text())
        held = cfg["packs"]["argus-observe-rules"]["held_back"]
        assert [h["rule"] for h in held] == ["go-crypto-tls-version"]
        for h in held:
            assert h.get("readmit_when"), "a hold needs an exit condition"

    def test_calibrated_total_is_enabled_plus_held_back(self):
        """16 rules cleared the gate; 15 are on. The deployment decision
        must not overwrite the calibration result."""
        import yaml

        cfg = yaml.safe_load(_deployment_allowlist().read_text())["packs"]["argus-observe-rules"]
        assert len(cfg["rules"]) + len(cfg["held_back"]) == 16


class TestProgrammaticScan:
    """scan() receives a resolved allowlist; it never self-loads config."""

    @pytest.fixture
    def target_dir(self, tmp_path):
        root = tmp_path / "repo"
        root.mkdir()
        (root / "main.go").write_text("package main\n")
        return root

    def test_scan_default_allowlist_is_none(self, target_dir, monkeypatch):
        captured: dict = {}

        def fake_execute(target, rule_sources, **kw):
            captured["allowlist"] = kw.get("allowlist")
            return {"facts": [], "opengrep_version": "test"}

        monkeypatch.setattr(R, "_execute_opengrep_scan", fake_execute)
        monkeypatch.setattr(R.shutil, "which", lambda _: "/usr/bin/opengrep")

        R.scan(target_dir)
        assert captured["allowlist"] is None

    def test_scan_forwards_explicit_allowlist(self, target_dir, monkeypatch):
        from traust_contracts import RulePackAllowlist

        allowlist = RulePackAllowlist(
            packs={
                "p": {
                    "enabled": True,
                    "source": "https://example.com/rules@" + "a" * 40,
                    "rules": ["r1"],
                }
            }
        )
        captured: dict = {}

        def fake_execute(target, rule_sources, **kw):
            captured["allowlist"] = kw.get("allowlist")
            return {"facts": [], "opengrep_version": "test"}

        monkeypatch.setattr(R, "_execute_opengrep_scan", fake_execute)
        monkeypatch.setattr(R.shutil, "which", lambda _: "/usr/bin/opengrep")

        R.scan(target_dir, allowlist=allowlist)
        assert captured["allowlist"] is allowlist

    def test_load_supplemental_packs_none_means_off(self):
        assert R.load_supplemental_packs(allowlist=None) == []

    def test_adapters_ops_scan_injects_context_allowlist(self, target_dir, monkeypatch):
        from traust_engine import HarnessEngine

        h = HarnessEngine.load()
        expected = h.adapters.allowlist_for_opengrep()
        captured: dict = {}

        def fake_scan(*_args, **kwargs):
            captured["allowlist"] = kwargs.get("allowlist")
            captured["loc"] = kwargs.get("loc")
            return R.build_scan_result(
                str(target_dir),
                "opengrep",
                [],
                scanned_at=R.utc_now(),
                scanner_version="test",
            )

        monkeypatch.setattr("traust_engine.adapters.opengrep.scan", fake_scan)

        h.adapters.scan(target_dir)
        assert captured["allowlist"] is expected
        assert captured["loc"] is h.ctx.locations
