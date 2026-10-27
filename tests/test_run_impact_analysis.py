"""Tests for traust impact analyze — semver, classification, analyzers, schema."""

import json
import unittest
from pathlib import Path

from traust_contracts.paths import schema_dir as _schema_dir

SCHEMA_DIR = _schema_dir()
from traust_engine.impact.analyzer import (
    ANALYZERS,
    ECOSYSTEM_ANALYZERS,
    TIER_MAP,
    AnalysisContext,
    GoAnalyzer,
    JavaAnalyzer,
    JavaScriptAnalyzer,
    NuGetAnalyzer,
    PythonAnalyzer,
    RepoEvidence,
    RubyAnalyzer,
    RustAnalyzer,
    SurfaceAnalyzer,
    analyzer_for_ecosystem,
    blast_radius_seed,
    classify,
    detect_language,
    parse_semver,
    parse_version,
    repo_slug_from_id,
    repo_url_from_id,
    valid_advisory_id,
    version_in_range,
)


class TestSemver(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(parse_semver("v1.64.1"), (1, 64, 1))

    def test_no_v_prefix(self):
        self.assertEqual(parse_semver("1.2.3"), (1, 2, 3))

    def test_prerelease(self):
        self.assertEqual(parse_semver("v1.2.3-rc1"), (1, 2, 3))

    def test_invalid(self):
        self.assertIsNone(parse_semver(""))
        self.assertIsNone(parse_semver("latest"))


class TestVersionInRange(unittest.TestCase):
    def test_below_fix(self):
        self.assertTrue(version_in_range("v1.63.2", "< v1.64.1", "v1.64.1"))

    def test_at_fix(self):
        self.assertFalse(version_in_range("v1.64.1", "< v1.64.1", "v1.64.1"))

    def test_above_fix(self):
        self.assertFalse(version_in_range("v1.65.0", "< v1.64.1", "v1.64.1"))

    def test_fixed_version_only(self):
        self.assertTrue(version_in_range("v1.63.2", "", "v1.64.1"))
        self.assertFalse(version_in_range("v1.64.1", "", "v1.64.1"))

    def test_invalid_version(self):
        self.assertIsNone(version_in_range("latest", "< v1.64.1", "v1.64.1"))


class TestClassify(unittest.TestCase):
    def test_version_not_in_range(self):
        ev = RepoEvidence(l1_version_in_range=False)
        self.assertEqual(classify(ev), "version_not_in_range")

    def test_govulncheck_reachable(self):
        ev = RepoEvidence(
            l1_version_in_range=True,
            l4_package_imported=True,
            l4_packages_found=["google.golang.org/grpc/authz"],
            govulncheck="symbol_reachable",
            govulncheck_trace=["main() -> grpc.Dial()"],
        )
        self.assertEqual(classify(ev), "affected")

    def test_feature_pattern_match(self):
        ev = RepoEvidence(
            l1_version_in_range=True,
            l4_package_imported=True,
            feature_pattern_matches=3,
        )
        self.assertEqual(classify(ev), "affected")

    def test_feature_pattern_govulncheck_negative(self):
        ev = RepoEvidence(
            l1_version_in_range=True,
            l4_package_imported=True,
            govulncheck="package_imported_not_observed",
            feature_pattern_matches=3,
        )
        self.assertEqual(classify(ev), "likely_affected")

    def test_feature_pattern_govulncheck_module_only_negative(self):
        ev = RepoEvidence(
            l1_version_in_range=True,
            govulncheck="module_required_not_observed",
            feature_pattern_matches=1,
        )
        self.assertEqual(classify(ev), "likely_affected")

    def test_binary_scan_present_with_l4(self):
        ev = RepoEvidence(
            l1_version_in_range=True,
            l4_package_imported=True,
            binary_string_scan="package_path_present",
        )
        self.assertEqual(classify(ev), "likely_affected")

    def test_binary_scan_present_without_l4(self):
        ev = RepoEvidence(
            l1_version_in_range=True,
            binary_string_scan="package_path_present",
        )
        self.assertEqual(classify(ev), "likely_affected")

    def test_package_not_imported(self):
        ev = RepoEvidence(
            l1_version_in_range=True,
            l4_package_imported=False,
        )
        self.assertEqual(classify(ev), "not_observed")

    def test_govulncheck_not_observed(self):
        ev = RepoEvidence(
            l1_version_in_range=True,
            l4_package_imported=True,
            govulncheck="package_imported_not_observed",
        )
        self.assertEqual(classify(ev), "not_observed")

    def test_binary_scan_absent(self):
        ev = RepoEvidence(
            l1_version_in_range=True,
            binary_string_scan="package_path_absent",
        )
        self.assertEqual(classify(ev), "not_observed")

    def test_likely_affected_no_deep_scan(self):
        ev = RepoEvidence(
            l1_version_in_range=True,
            l4_package_imported=True,
            l4_packages_found=["google.golang.org/grpc/authz"],
        )
        self.assertEqual(classify(ev), "likely_affected")

    def test_inconclusive_no_data(self):
        ev = RepoEvidence()
        self.assertEqual(classify(ev), "inconclusive")

    def test_manifest_ecosystem_missing_import_does_not_demote(self):
        # PyPI: urllib3/aiohttp load an installed brotli with no
        # first-party import, so L4 "not imported" is not absence.
        ev = RepoEvidence(l1_version_in_range=True, l4_package_imported=False)
        self.assertEqual(classify(ev, "pypi"), "inconclusive")
        self.assertEqual(classify(ev), "not_observed")  # Go keeps the tier

    def test_manifest_ecosystem_pin_decides_despite_missing_import(self):
        ev = RepoEvidence(
            l1_version_in_range=True,
            l4_package_imported=False,
            manifest_scan="module_pinned_in_range",
        )
        self.assertEqual(classify(ev, "pypi"), "likely_affected")

    def test_manifest_ecosystem_import_defers_to_fresher_pin(self):
        ev = RepoEvidence(
            l1_version_in_range=True,
            l4_package_imported=True,
            manifest_scan="module_pinned_out_of_range",
        )
        self.assertEqual(classify(ev, "npm"), "version_not_in_range")

    def test_manifest_ecosystem_import_counts_as_source_import(self):
        ev = RepoEvidence(
            l1_version_in_range=True,
            l4_package_imported=True,
            manifest_scan="module_not_in_manifests",
        )
        self.assertEqual(classify(ev, "pypi"), "likely_affected")


class TestRepoEvidence(unittest.TestCase):
    def test_to_dict_omits_none(self):
        ev = RepoEvidence(l1_version_in_range=True, l4_package_imported=False)
        d = ev.to_dict()
        self.assertNotIn("govulncheck", d)
        self.assertNotIn("notes", d)
        self.assertTrue(d["l1_depends_on"])
        self.assertTrue(d["l1_version_in_range"])
        self.assertFalse(d["l4_package_imported"])


class TestDetectLanguage(unittest.TestCase):
    def test_go(self, tmp_path=None):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "go.mod").touch()
            self.assertEqual(detect_language(p), "go")

    def test_python(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "pyproject.toml").touch()
            self.assertEqual(detect_language(p), "python")

    def test_unknown(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(detect_language(Path(d)))


class TestAnalyzerRegistry(unittest.TestCase):
    def test_go_registered(self):
        self.assertIn("go", ANALYZERS)
        self.assertEqual(ANALYZERS["go"], GoAnalyzer)

    def test_tier_map_schema_values(self):
        self.assertEqual(TIER_MAP["govulncheck_source"], "govulncheck")
        self.assertEqual(TIER_MAP["elf_string_scan"], "binary_scan")


class TestRepoHelpers(unittest.TestCase):
    def test_url_from_id(self):
        self.assertEqual(
            repo_url_from_id("repo:github.com/openshift/foo"),
            "https://github.com/openshift/foo",
        )

    def test_slug_from_id(self):
        self.assertEqual(repo_slug_from_id("repo:github.com/openshift/foo"), "openshift-foo")

    def test_url_non_repo(self):
        self.assertIsNone(repo_url_from_id("module:example.com/foo"))


class TestSchemaValid(unittest.TestCase):
    def test_minimal_report(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema not installed")

        schema = json.loads((SCHEMA_DIR / "impact-analysis.schema.json").read_text())

        report = {
            "metadata": {
                "cve": "CVE-2026-33186",
                "module": "google.golang.org/grpc",
                "vulnerable_range": "< v1.64.1",
                "fixed_version": "v1.64.1",
                "vulnerable_symbols": [],
                "vulnerable_packages": ["google.golang.org/grpc/authz"],
                "feature_description": "gRPC path-based authorization",
                "advisory_sources": [],
                "portfolio_graph_db": "/tmp/test.db",
                "portfolio_graph_version": "2026-07-20",
                "harness_version": "0.115.0-abc1234",
                "generated_at": "2026-07-20T13:42:00Z",
                "tiers_executed": ["L1", "L4"],
                "options": {
                    "govulncheck": False,
                    "binary_scan": False,
                    "sweep": False,
                },
            },
            "summary": {
                "repos_in_blast_radius": 2,
                "version_in_range": 1,
                "affected": 0,
                "likely_affected": 0,
                "not_observed": 1,
                "version_not_in_range": 1,
                "not_imported": 0,
                "inconclusive": 0,
                "product_surfaces": ["OCP 4.18"],
            },
            "repos": [
                {
                    "repo": "repo:github.com/openshift/foo",
                    "products": ["OCP 4.18"],
                    "classification": "not_observed",
                    "version": "v1.63.2",
                    "direct": True,
                    "evidence": {
                        "l1_depends_on": True,
                        "l1_version_in_range": True,
                        "l4_package_imported": False,
                    },
                },
                {
                    "repo": "repo:github.com/openshift/bar",
                    "products": [],
                    "classification": "version_not_in_range",
                    "version": "v1.65.0",
                    "direct": False,
                    "evidence": {
                        "l1_depends_on": True,
                        "l1_version_in_range": False,
                    },
                },
            ],
        }
        jsonschema.validate(report, schema)


class TestSchemaEvidence(unittest.TestCase):
    def test_needs_manual_trace_validates(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema not installed")

        schema = json.loads((SCHEMA_DIR / "impact-analysis.schema.json").read_text())
        evidence_schema = schema["$defs"]["evidence"]
        evidence = {
            "l1_depends_on": True,
            "l1_version_in_range": True,
            "govulncheck": "package_imported_not_observed",
            "needs_manual_trace": True,
            "notes": "unsafe/reflect/cgo usage detected",
        }
        jsonschema.validate(evidence, evidence_schema)

    def test_to_dict_includes_false_booleans(self):
        ev = RepoEvidence(l1_version_in_range=True)
        d = ev.to_dict()
        self.assertIn("l1_depends_on", d)
        self.assertIn("needs_manual_trace", d)
        self.assertFalse(d["needs_manual_trace"])


class TestCrossValidation(unittest.TestCase):
    def test_summary_mismatch_detected(self):
        from traust_engine.reporting.validate import (
            ValidationResult,
            cross_validate_impact_analysis,
        )

        report = {
            "summary": {
                "repos_in_blast_radius": 1,
                "version_in_range": 1,
                "affected": 99,
                "likely_affected": 0,
                "not_observed": 0,
                "version_not_in_range": 0,
                "not_imported": 0,
                "inconclusive": 0,
            },
            "repos": [
                {
                    "repo": "repo:example",
                    "classification": "not_observed",
                    "evidence": {},
                },
            ],
        }
        result = ValidationResult(file_path="test.json")
        cross_validate_impact_analysis(report, result)
        self.assertFalse(result.passed)
        self.assertTrue(any("affected" in e for e in result.errors))


class TestManifestClassify(unittest.TestCase):
    """Manifest-tier ecosystems: ceiling is likely_affected, never affected."""

    def test_pinned_in_range_is_likely(self):
        ev = RepoEvidence()
        ev.manifest_scan = "module_pinned_in_range"
        self.assertEqual(classify(ev), "likely_affected")

    def test_pinned_out_of_range(self):
        ev = RepoEvidence()
        ev.manifest_scan = "module_pinned_out_of_range"
        self.assertEqual(classify(ev), "version_not_in_range")

    def test_absent_and_no_imports_not_observed(self):
        ev = RepoEvidence()
        ev.manifest_scan = "module_not_in_manifests"
        ev.source_import_scan = "imports_not_found"
        self.assertEqual(classify(ev), "not_observed")

    def test_absent_but_imported_is_likely(self):
        ev = RepoEvidence()
        ev.manifest_scan = "module_not_in_manifests"
        ev.source_import_scan = "imports_found"
        self.assertEqual(classify(ev), "likely_affected")

    def test_linked_library_is_likely(self):
        ev = RepoEvidence()
        ev.binary_linked_library = "linked"
        self.assertEqual(classify(ev), "likely_affected")

    def test_not_linked_no_includes_not_observed(self):
        ev = RepoEvidence()
        ev.binary_linked_library = "not_linked"
        ev.source_import_scan = "imports_not_found"
        self.assertEqual(classify(ev), "not_observed")

    def test_manifest_never_beats_go_negative(self):
        # Go evidence present: manifest fields must not change the verdict
        ev = RepoEvidence()
        ev.govulncheck = "package_imported_not_observed"
        ev.manifest_scan = "module_pinned_in_range"
        self.assertEqual(classify(ev), "not_observed")

    def test_symbol_usage_is_likely_never_affected(self):
        ev = RepoEvidence()
        ev.symbol_usage_scan = "symbols_used"
        ev.manifest_scan = "module_not_in_manifests"  # e.g. vendored copy
        self.assertEqual(classify(ev), "likely_affected")

    def test_symbol_usage_beats_manifest_not_observed(self):
        # symbols used must win over the manifest-absent not_observed rule
        ev = RepoEvidence()
        ev.symbol_usage_scan = "symbols_used"
        ev.manifest_scan = "module_not_in_manifests"
        ev.source_import_scan = "imports_not_found"
        self.assertEqual(classify(ev), "likely_affected")

    def test_sbom_scan_is_evidence_only(self):
        # sbom fields alone never produce a classification
        ev = RepoEvidence()
        ev.sbom_scan = "shipped_in_range"
        ev.sbom_shipped_version = "1.0.0"
        self.assertEqual(classify(ev), "inconclusive")


class TestLockfileExtractors(unittest.TestCase):
    def test_python_requirements(self):
        pins = PythonAnalyzer().extract_pins(
            "requirements.txt", "requests==2.31.0\nurllib3>=1.26.5\n"
        )
        self.assertEqual(pins.get("requests"), "2.31.0")
        self.assertEqual(pins.get("urllib3"), "1.26.5")

    def test_python_pipfile_lock(self):
        text = '{"default": {"cryptography": {"version": "==41.0.3"}}}'
        pins = PythonAnalyzer().extract_pins("Pipfile.lock", text)
        self.assertEqual(pins.get("cryptography"), "41.0.3")

    def test_rust_cargo_lock(self):
        text = '[[package]]\nname = "openssl"\nversion = "0.10.55"\n'
        pins = RustAnalyzer().extract_pins("Cargo.lock", text)
        self.assertEqual(pins.get("openssl"), "0.10.55")

    def test_js_package_lock_v3(self):
        text = '{"packages": {"node_modules/lodash": {"version": "4.17.20"}}, "dependencies": {}}'
        pins = JavaScriptAnalyzer().extract_pins("package-lock.json", text)
        self.assertEqual(pins.get("lodash"), "4.17.20")

    def test_java_pom(self):
        text = (
            "<dependency><groupId>com.fasterxml.jackson.core</groupId>"
            "<artifactId>jackson-databind</artifactId>"
            "<version>2.15.2</version></dependency>"
        )
        pins = JavaAnalyzer().extract_pins("pom.xml", text)
        self.assertEqual(pins.get("jackson-databind"), "2.15.2")

    def test_java_coordinates_match_artifact(self):
        ctx_names = JavaAnalyzer().module_names(
            _ctx(module="com.fasterxml.jackson.core:jackson-databind")
        )
        self.assertIn("jackson-databind", ctx_names)


class TestDetectLanguageC(unittest.TestCase):
    def test_c_detected(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "Makefile").write_text("all:\n")
            (Path(d) / "main.c").write_text("int main(){}\n")
            self.assertEqual(detect_language(Path(d)), "c")

    def test_go_takes_precedence(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "Makefile").write_text("all:\n")
            (Path(d) / "go.mod").write_text("module x\n")
            self.assertEqual(detect_language(Path(d)), "go")


def _ctx(module: str):
    return AnalysisContext(
        cve="CVE-0000-0000",
        module=module,
        packages=[],
        symbols=[],
        vulnerable_range="",
        fixed_version=None,
        feature_desc=None,
        db_path=None,
        con=None,
    )


class TestRubyExtractor(unittest.TestCase):
    def test_gemfile_lock_specs(self):
        text = (
            "GEM\n"
            "  remote: https://rubygems.org/\n"
            "  specs:\n"
            "    actionpack (7.0.4)\n"
            "      actionview (= 7.0.4)\n"
            "    nokogiri (1.13.9)\n"
            "\n"
            "PLATFORMS\n"
            "  ruby\n"
        )
        pins = RubyAnalyzer().extract_pins("Gemfile.lock", text)
        # 4-space top-level specs are pinned...
        self.assertEqual(pins.get("actionpack"), "7.0.4")
        self.assertEqual(pins.get("nokogiri"), "1.13.9")
        # ...6-space sub-dep constraints (= 7.0.4) are NOT pins.
        self.assertNotIn("actionview", pins)

    def test_gemspec_add_dependency(self):
        text = (
            "Gem::Specification.new do |s|\n"
            "  s.name = 'mygem'\n"
            "  s.add_dependency 'rack', '>= 2.2.3'\n"
            "  s.add_runtime_dependency('nokogiri')\n"
            "end\n"
        )
        pins = RubyAnalyzer().extract_pins("mygem.gemspec", text)
        self.assertIn("rack", pins)
        self.assertEqual(pins.get("rack"), ">= 2.2.3")
        self.assertIn("nokogiri", pins)


class TestNuGetExtractor(unittest.TestCase):
    def test_packages_lock_json_resolved(self):
        text = json.dumps(
            {
                "version": 1,
                "dependencies": {
                    "net6.0": {
                        "Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.1"},
                        "System.Text.Json": {"type": "Transitive", "resolved": "6.0.0"},
                    }
                },
            }
        )
        pins = NuGetAnalyzer().extract_pins("packages.lock.json", text)
        self.assertEqual(pins.get("Newtonsoft.Json"), "13.0.1")
        self.assertEqual(pins.get("System.Text.Json"), "6.0.0")

    def test_csproj_package_reference(self):
        text = (
            '<Project Sdk="Microsoft.NET.Sdk">\n'
            "  <ItemGroup>\n"
            '    <PackageReference Include="Serilog" Version="2.12.0" />\n'
            "  </ItemGroup>\n"
            "</Project>\n"
        )
        pins = NuGetAnalyzer().extract_pins("app.csproj", text)
        self.assertEqual(pins.get("Serilog"), "2.12.0")

    def test_source_scan_is_noop(self):
        # NuGet source-import scanning is a deliberate no-op (package name
        # does not map to a C# namespace); the tier must not run.
        import tempfile
        from pathlib import Path

        ev = RepoEvidence()
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "foo.cs").write_text("using Serilog;\n")
            ran = NuGetAnalyzer()._source_scan(Path(d), ev, _ctx("Serilog"))
        self.assertFalse(ran)
        self.assertIsNone(ev.source_import_scan)


class TestDetectLanguageRubyNuGet(unittest.TestCase):
    def test_ruby_from_gemfile_lock(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "Gemfile.lock").write_text("GEM\n  specs:\n")
            self.assertEqual(detect_language(Path(d)), "ruby")

    def test_ruby_from_gemspec(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "mygem.gemspec").write_text("Gem::Specification.new\n")
            self.assertEqual(detect_language(Path(d)), "ruby")

    def test_nuget_from_csproj(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "app.csproj").write_text("<Project></Project>\n")
            self.assertEqual(detect_language(Path(d)), "nuget")

    def test_go_still_takes_precedence_over_ruby(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "go.mod").write_text("module x\n")
            (Path(d) / "Gemfile").write_text("source 'https://rubygems.org'\n")
            self.assertEqual(detect_language(Path(d)), "go")


class TestParseVersion(unittest.TestCase):
    def test_npm_strips_v(self):
        self.assertEqual(parse_version("v1.2.3", "npm"), (1, 2, 3))

    def test_npm_takes_first_three(self):
        self.assertEqual(parse_version("1.2.3.4", "npm"), (1, 2, 3))

    def test_maven_drops_qualifier(self):
        self.assertEqual(parse_version("1.0.0.Final", "maven"), (1, 0, 0))
        self.assertEqual(parse_version("5.3.2-RELEASE", "maven"), (5, 3, 2))

    def test_pypi_epoch(self):
        self.assertEqual(parse_version("1!2.3.4", "pypi"), (2, 3, 4))
        self.assertEqual(parse_version("2.3.4rc1", "pypi"), (2, 3, 4))

    def test_ruby_nuget_dotted(self):
        self.assertEqual(parse_version("1.13.9", "ruby"), (1, 13, 9))
        self.assertEqual(parse_version("13.0.1", "nuget"), (13, 0, 1))

    def test_go_unchanged(self):
        # Go path delegates to parse_semver — requires exactly 3 components.
        self.assertEqual(parse_version("v1.64.1", "go"), (1, 64, 1))
        self.assertIsNone(parse_version("1.64", "go"))

    def test_garbage_is_none(self):
        for eco in ("go", "npm", "maven", "pypi", "ruby", "nuget", "cargo"):
            self.assertIsNone(parse_version("latest", eco), eco)
            self.assertIsNone(parse_version("", eco), eco)

    def test_none_range_is_inconclusive(self):
        # Unparseable version -> version_in_range None -> classify falls
        # through to inconclusive (repo still gets deep-scanned).
        self.assertIsNone(version_in_range("garbage", "< 2.0.0", "2.0.0", "nuget"))
        ev = RepoEvidence()
        ev.l1_version_in_range = version_in_range("garbage", "< 2.0.0", "2.0.0", "nuget")
        self.assertEqual(classify(ev), "inconclusive")

    def test_non_go_range_compare(self):
        self.assertTrue(version_in_range("1.13.8", "", "1.13.9", "ruby"))
        self.assertFalse(version_in_range("1.13.9", "", "1.13.9", "ruby"))


class TestBlastRadiusSeed(unittest.TestCase):
    def test_go_seed_is_module_id(self):
        self.assertEqual(
            blast_radius_seed("google.golang.org/grpc", "go"),
            "module:google.golang.org/grpc",
        )

    def test_npm_seed_is_pkg_id(self):
        self.assertEqual(blast_radius_seed("lodash", "npm"), "pkg:npm/lodash")

    def test_nuget_seed_is_pkg_id(self):
        self.assertEqual(
            blast_radius_seed("Newtonsoft.Json", "nuget"),
            "pkg:nuget/Newtonsoft.Json",
        )

    def test_actions_seed_is_pkg_id(self):
        self.assertEqual(
            blast_radius_seed("actions/checkout", "actions"),
            "pkg:actions/actions/checkout",
        )

    def test_docker_seed_is_pkg_id(self):
        self.assertEqual(blast_radius_seed("alpine", "docker"), "pkg:docker/alpine")

    def test_helm_seed_is_pkg_id(self):
        self.assertEqual(blast_radius_seed("redis", "helm"), "pkg:helm/redis")


class TestAdvisoryId(unittest.TestCase):
    def test_accepts_cve(self):
        self.assertTrue(valid_advisory_id("CVE-2026-1234"))

    def test_accepts_osv_family(self):
        for good in (
            "GHSA-abcd-efgh-ijkl",
            "MAL-2025-0001",
            "PYSEC-2024-1",
            "GO-2024-1234",
            "RUSTSEC-2021-0001",
            "OSV-2023-1",
        ):
            self.assertTrue(valid_advisory_id(good), good)

    def test_rejects_injection_and_junk(self):
        for bad in ("foo; rm -rf", "../etc", "a b", "", "CVE_2026_1", "ghsa-lower"):
            self.assertFalse(valid_advisory_id(bad), repr(bad))


class TestSurfaceAnalyzer(unittest.TestCase):
    """actions/docker/helm: manifest-level re-check, ceiling likely_affected."""

    @staticmethod
    def _ctx(module, ecosystem, vulnerable_range="", fixed_version=None):
        return AnalysisContext(
            cve="GHSA-abcd-efgh-ijkl",
            module=module,
            packages=[],
            symbols=[],
            vulnerable_range=vulnerable_range,
            fixed_version=fixed_version,
            feature_desc=None,
            db_path=None,
            con=None,
            ecosystem=ecosystem,
        )

    def test_actions_present_is_likely(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            wf = Path(d) / ".github" / "workflows"
            wf.mkdir(parents=True)
            (wf / "ci.yml").write_text(
                "jobs:\n  b:\n    steps:\n      - uses: actions/checkout@v3\n"
            )
            ev = RepoEvidence()
            tiers = SurfaceAnalyzer("actions").analyze(
                Path(d), "repo:x", ev, self._ctx("actions/checkout", "actions")
            )
            self.assertIn("manifest_scan", tiers)
            self.assertEqual(ev.manifest_scan, "module_pinned_in_range")
            self.assertEqual(classify(ev), "likely_affected")
            self.assertNotEqual(classify(ev), "affected")

    def test_actions_absent_is_not_observed(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            wf = Path(d) / ".github" / "workflows"
            wf.mkdir(parents=True)
            (wf / "ci.yml").write_text(
                "jobs:\n  b:\n    steps:\n      - uses: actions/setup-go@v5\n"
            )
            ev = RepoEvidence()
            SurfaceAnalyzer("actions").analyze(
                Path(d), "repo:x", ev, self._ctx("actions/checkout", "actions")
            )
            self.assertEqual(ev.manifest_scan, "module_not_in_manifests")
            self.assertEqual(classify(ev), "not_observed")

    def test_docker_present_is_likely_never_affected(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "Dockerfile").write_text("FROM alpine:3.10\n")
            ev = RepoEvidence()
            SurfaceAnalyzer("docker").analyze(Path(d), "repo:x", ev, self._ctx("alpine", "docker"))
            self.assertEqual(ev.manifest_scan, "module_pinned_in_range")
            self.assertEqual(classify(ev), "likely_affected")

    def test_docker_out_of_range_is_version_not_in_range(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "Dockerfile").write_text("FROM alpine:3.20\n")
            ev = RepoEvidence()
            SurfaceAnalyzer("docker").analyze(
                Path(d),
                "repo:x",
                ev,
                self._ctx("alpine", "docker", fixed_version="3.15"),
            )
            self.assertEqual(ev.manifest_scan, "module_pinned_out_of_range")
            self.assertEqual(classify(ev), "version_not_in_range")

    def test_helm_present_is_likely(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "Chart.yaml").write_text(
                "name: mychart\ndependencies:\n  - name: redis\n    version: 17.0.0\n"
            )
            ev = RepoEvidence()
            SurfaceAnalyzer("helm").analyze(Path(d), "repo:x", ev, self._ctx("redis", "helm"))
            self.assertEqual(ev.manifest_scan, "module_pinned_in_range")
            self.assertEqual(classify(ev), "likely_affected")

    def test_no_manifests_is_inconclusive(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            ev = RepoEvidence()
            SurfaceAnalyzer("docker").analyze(Path(d), "repo:x", ev, self._ctx("alpine", "docker"))
            self.assertEqual(ev.manifest_scan, "no_manifests_found")
            self.assertEqual(classify(ev), "inconclusive")


class TestSchemaEcosystem(unittest.TestCase):
    def _schema(self):
        try:
            import jsonschema  # noqa: F401
        except ImportError:
            self.skipTest("jsonschema not installed")
        return json.loads((SCHEMA_DIR / "impact-analysis.schema.json").read_text())

    def _report(self, with_ecosystem: bool):
        meta = {
            "cve": "CVE-2026-0001",
            "module": "lodash",
            "vulnerable_range": "< 4.17.21",
            "harness_version": "0.1.0-abc1234",
            "generated_at": "2026-08-04T00:00:00Z",
            "tiers_executed": ["L1"],
            "options": {"govulncheck": False, "binary_scan": False, "sweep": False},
        }
        if with_ecosystem:
            meta["ecosystem"] = "npm"
        return {
            "metadata": meta,
            "summary": {
                "repos_in_blast_radius": 0,
                "version_in_range": 0,
                "affected": 0,
                "likely_affected": 0,
                "not_observed": 0,
                "version_not_in_range": 0,
                "not_imported": 0,
                "inconclusive": 0,
            },
            "repos": [],
        }

    def test_validates_with_ecosystem(self):
        import jsonschema

        jsonschema.validate(self._report(True), self._schema())

    def test_validates_without_ecosystem(self):
        import jsonschema

        jsonschema.validate(self._report(False), self._schema())

    def test_validates_surface_ecosystems(self):
        import jsonschema

        schema = self._schema()
        for eco in ("actions", "docker", "helm"):
            rep = self._report(False)
            rep["metadata"]["ecosystem"] = eco
            jsonschema.validate(rep, schema)

    def test_validates_ghsa_advisory_id(self):
        import jsonschema

        rep = self._report(False)
        rep["metadata"]["cve"] = "GHSA-abcd-efgh-ijkl"
        jsonschema.validate(rep, self._schema())


class TestVersionInRangeLowerBound(unittest.TestCase):
    """version_in_range honors `>=`/`>` LOWER bounds from vulnerable_range,
    ANDed with the fixed_version / upper-bound constraints."""

    def test_below_lower_bound_not_in_range(self):
        # 2.5.2 is below the >=2.5.3 lower bound -> NOT vulnerable, even
        # though it is below the fix (the false-positive Bug-2 fixes).
        self.assertFalse(version_in_range("2.5.2", ">=2.5.3", "2.8.0", "npm"))

    def test_at_lower_bound_in_range(self):
        self.assertTrue(version_in_range("2.5.3", ">=2.5.3", "2.8.0", "npm"))

    def test_at_fix_not_in_range(self):
        # >= fixed -> not vulnerable regardless of the lower bound.
        self.assertFalse(version_in_range("2.8.0", ">=2.5.3", "2.8.0", "npm"))

    def test_both_bounds_range(self):
        r = ">=2.5.3 <2.8.0"
        self.assertTrue(version_in_range("2.5.3", r, None, "npm"))  # at lower
        self.assertTrue(version_in_range("2.6.0", r, None, "npm"))  # inside
        self.assertFalse(version_in_range("2.5.2", r, None, "npm"))  # below lower
        self.assertFalse(version_in_range("2.8.0", r, None, "npm"))  # at upper

    def test_gt_strict_lower_bound(self):
        self.assertFalse(version_in_range("2.5.3", ">2.5.3", None, "npm"))
        self.assertTrue(version_in_range("2.5.4", ">2.5.3", None, "npm"))

    def test_no_constraints_is_none(self):
        self.assertIsNone(version_in_range("1.0.0", "", None, "npm"))

    # --- regression guards: pre-fix behavior must be byte-identical ---
    def test_regression_fixed_only(self):
        self.assertTrue(version_in_range("v1.63.2", "", "v1.64.1"))
        self.assertFalse(version_in_range("v1.64.1", "", "v1.64.1"))

    def test_regression_single_upper_bound(self):
        self.assertTrue(version_in_range("v1.63.2", "< v1.64.1", "v1.64.1"))
        self.assertFalse(version_in_range("v1.65.0", "< v1.64.1", "v1.64.1"))
        # upper bound alone (no fix)
        self.assertTrue(version_in_range("1.0.0", "< 2.0.0", None, "npm"))
        self.assertFalse(version_in_range("2.0.0", "< 2.0.0", None, "npm"))

    def test_regression_unparseable_stays_none(self):
        self.assertIsNone(version_in_range("latest", ">=2.5.3", "2.8.0", "npm"))


class TestEcosystemAnalyzerMapping(unittest.TestCase):
    """analyzer_for_ecosystem maps a specific --ecosystem to its analyzer,
    independent of detect_language (BUG-1)."""

    def test_specific_ecosystems_map_to_analyzers(self):
        cases = {
            "go": GoAnalyzer,
            "npm": JavaScriptAnalyzer,
            "pypi": PythonAnalyzer,
            "cargo": RustAnalyzer,
            "maven": JavaAnalyzer,
            "ruby": RubyAnalyzer,
            "nuget": NuGetAnalyzer,
        }
        for eco, cls in cases.items():
            self.assertIsInstance(analyzer_for_ecosystem(eco), cls, eco)
        # The mapping dict agrees with the resolver.
        self.assertEqual(ECOSYSTEM_ANALYZERS["npm"], JavaScriptAnalyzer)

    def test_surface_ecosystems_map_to_surface_analyzer(self):
        for eco in ("actions", "docker", "helm"):
            a = analyzer_for_ecosystem(eco)
            self.assertIsInstance(a, SurfaceAnalyzer)
            self.assertEqual(a.name, eco)


class TestPolyglotDispatch(unittest.TestCase):
    """A Go repo with a JS UI subdir (example/prometheus on MAL-EXAMPLE-001):
    --ecosystem npm must run the
    JS analyzer and OBSERVE the JS devDependency, not fall through to a Go
    not_observed. detect_language picking 'go' (go.mod-wins) is exactly
    why the ecosystem must override language detection."""

    def _polyglot_dir(self, d):
        p = Path(d)
        (p / "go.mod").write_text("module github.com/example/prometheus\n")
        react = p / "web" / "ui" / "react-app"
        react.mkdir(parents=True)
        (react / "package.json").write_text(
            json.dumps(
                {
                    "name": "prometheus-ui",
                    "devDependencies": {"jest-canvas-mock": "^2.5.3"},
                }
            )
        )
        return p

    def _ctx(self, ecosystem):
        return AnalysisContext(
            cve="MAL-EXAMPLE-001",
            module="jest-canvas-mock",
            packages=[],
            symbols=[],
            vulnerable_range=">=2.5.3",
            fixed_version="2.8.0",
            feature_desc=None,
            db_path=None,
            con=None,
            ecosystem=ecosystem,
        )

    def test_npm_ecosystem_finds_js_devdependency(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            p = self._polyglot_dir(d)
            # Root cause: language detection picks Go, so the legacy
            # detect_language path would run GoAnalyzer and never see
            # web/ui/react-app/package.json.
            self.assertEqual(detect_language(p), "go")

            ctx = self._ctx("npm")
            analyzer = analyzer_for_ecosystem(ctx.ecosystem)
            self.assertIsInstance(analyzer, JavaScriptAnalyzer)

            ev = RepoEvidence()
            tiers = analyzer.analyze(p, "repo:github.com/example/prometheus", ev, ctx)
            self.assertIn("manifest_scan", tiers)
            # The subdir JS dep was OBSERVED (not a Go not_observed).
            self.assertEqual(ev.manifest_version, "2.5.3")
            self.assertEqual(ev.manifest_scan, "module_pinned_in_range")
            self.assertEqual(classify(ev), "likely_affected")

    def test_go_ecosystem_still_dispatches_go_analyzer(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            p = self._polyglot_dir(d)
            # Default/unspecified ecosystem 'go' keeps the legacy routing:
            # the resolver and detect_language both land on Go.
            self.assertIsInstance(analyzer_for_ecosystem("go"), GoAnalyzer)
            self.assertEqual(detect_language(p), "go")

    def test_safe_version_below_lower_bound_not_flagged(self):
        # Bugs 1+2 together: a frontend pinned to the SAFE 2.5.2 must be
        # version_not_in_range under the >=2.5.3 range, never likely_affected.
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "package.json").write_text(
                json.dumps(
                    {
                        "name": "frontend",
                        "devDependencies": {"jest-canvas-mock": "2.5.2"},
                    }
                )
            )
            ctx = self._ctx("npm")
            ev = RepoEvidence()
            analyzer_for_ecosystem("npm").analyze(p, "repo:x", ev, ctx)
            self.assertEqual(ev.manifest_version, "2.5.2")
            self.assertEqual(ev.manifest_scan, "module_pinned_out_of_range")
            self.assertEqual(classify(ev), "version_not_in_range")


if __name__ == "__main__":
    unittest.main()
