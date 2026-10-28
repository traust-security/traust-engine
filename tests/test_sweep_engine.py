#!/usr/bin/env python3
"""sweep_engine.py tests — collect classification, draft dedup, sweep
run (opengrep-gated like the other opengrep tests), emit schema, and
stage resumability. All on fixtures; never touches the real corpus."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

import pytest
from traust_contracts import CorpusConfig

from traust_engine.sweep import engine as SE

MINIMAL_CORPUS = CorpusConfig.model_validate(
    {
        "version": 1,
        "trees": {
            "findings": {"label": "Findings", "ownership": "owned", "business_unit": "example_bu"}
        },
    }
)


def write_json(path: Path, doc) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=1), encoding="utf-8")


def make_fixtures(root: Path) -> tuple[Path, Path, Path]:
    """(results_root, phase0_root, sweeps_root) with one of each source."""
    results = root / "findings"
    phase0 = root / "phase0"
    sweeps = root / "sweeps"

    # ledger: confirmed CWE-78 go (expressible), confirmed CWE-306
    # (semantic), proposed CWE-89 (not confirmed), confirmed CWE-1395
    # (dependency-version)
    write_json(
        results / "prod" / "repoa" / "repoa-findings-current.json",
        {
            "metadata": {"repository": "https://github.com/org/repoa", "commit": "abc1234"},
            "findings": [
                {
                    "id": "FIND-001",
                    "title": "cmd injection via exec sh -c",
                    "severity": "high",
                    "cwes": ["CWE-78"],
                    "category": "injection",
                    "locations": [{"path": "pkg/run.go", "lines": "10"}],
                    "disposition": {"validity": "confirmed"},
                },
                {
                    "id": "FIND-002",
                    "title": "no authn on admin endpoint",
                    "severity": "critical",
                    "cwes": ["CWE-306"],
                    "locations": [{"path": "pkg/srv.go"}],
                    "disposition": {"validity": "confirmed"},
                },
                {
                    "id": "FIND-003",
                    "title": "sqli maybe",
                    "severity": "high",
                    "cwes": ["CWE-89"],
                    "locations": [{"path": "pkg/db.go"}],
                    "disposition": {"validity": "proposed"},
                },
                {
                    "id": "FIND-004",
                    "title": "vulnerable quic-go pin",
                    "severity": "high",
                    "cwes": ["CWE-1395"],
                    "locations": [{"path": "go.mod"}],
                    "disposition": {"validity": "confirmed"},
                },
            ],
        },
    )

    # fast-track triage shape: one TP CWE-532 python, one FP (dropped)
    write_json(
        phase0 / "fast-track-criticals-triage.json",
        {
            "findings": [
                {
                    "id": "f001",
                    "source": "example-delta.json#0",
                    "title": "secret logged in plaintext",
                    "cwe": "CWE-532",
                    "file": "collector/filter.py",
                    "line": 12,
                    "claimed_severity": "high",
                    "verdict": "true_positive",
                },
                {
                    "id": "f002",
                    "source": "example-delta.json#1",
                    "title": "bogus",
                    "cwe": "CWE-78",
                    "file": "x.go",
                    "verdict": "false_positive",
                },
            ],
        },
    )
    # fast-track wave shape: confirmed result (dup of ledger FIND-001 by
    # a different title — must survive as its own record)
    write_json(
        phase0 / "fast-track-criticals-w2.json",
        {
            "results": [
                {
                    "slug": "repoc",
                    "url": "https://github.com/org/repoc",
                    "confirmed": True,
                    "finding": {
                        "title": "hardcoded AWS key literal",
                        "severity": "critical",
                        "cwe": "CWE-798",
                        "file": "cmd/main.go",
                        "line": 9,
                    },
                },
                {
                    "slug": "repoc",
                    "url": "https://github.com/org/repoc",
                    "confirmed": False,
                    "finding": {"title": "nope", "cwe": "CWE-78", "file": "a.go"},
                },
            ],
        },
    )
    # matrix stage-2: candidates + votes join
    write_json(
        phase0 / "matrix" / "adj" / "stage2-candidates.json",
        [
            {
                "target_index": 0,
                "uid": "t0-u01",
                "target": {"target": "https://github.com/org/repod @ 1111111"},
                "finding": {
                    "title": "InsecureSkipVerify true in client",
                    "severity": "high",
                    "cwe": "CWE-295",
                    "file": "pkg/tls.go",
                    "line": 33,
                },
            },
            {
                "target_index": 1,
                "uid": "t0-u02",
                "target": {"target": "https://github.com/org/repoe @ 2222222"},
                "finding": {
                    "title": "race in token refresh",
                    "severity": "medium",
                    "cwe": "CWE-362",
                    "file": "pkg/tok.go",
                    "line": 5,
                },
            },
        ],
    )
    write_json(
        phase0 / "matrix" / "adj" / "stage2-chunkA-votes.json",
        {
            "results": [
                {"idx": 0, "confirmed": True, "votes": []},
                {"idx": 1, "confirmed": True, "votes": []},
            ],
        },
    )
    # 0d fresh-only: confirmed dependency finding (not expressible) with
    # CWE inside the "class" field
    write_json(
        phase0 / "dual" / "0d-freshonly-triage-results.json",
        {
            "results": [
                {
                    "slug": "repof",
                    "url": "https://github.com/org/repof",
                    "confirmed": True,
                    "finding": {
                        "severity": "high",
                        "class": "CWE-1395 vulnerable dependencies",
                        "title": "46 npm advisories in yarn.lock",
                        "file": "yarn.lock",
                    },
                },
            ],
        },
    )
    return results, phase0, sweeps


class TestClassify(unittest.TestCase):
    def test_syntactic_sink_is_expressible(self):
        ok, reason = SE.classify({"cwe": "CWE-78", "file": "a.go", "language": "go"})
        self.assertTrue(ok)
        self.assertIn("syntactic", reason)

    def test_semantic_dependency_language_and_anchor_reasons(self):
        cases = [
            ({"cwe": "CWE-306", "file": "a.go", "language": "go"}, "semantic_logic_class"),
            (
                {"cwe": "CWE-1395", "file": "go.mod", "language": "unknown"},
                "dependency_version_class",
            ),
            ({"cwe": "CWE-78", "file": "a.tf", "language": "unknown"}, "language_not_ruleable"),
            ({"cwe": None, "file": "a.go", "language": "go"}, "no_cwe"),
            ({"cwe": "CWE-78", "file": None, "language": "go"}, "no_location_anchor"),
        ]
        for finding, expect in cases:
            ok, reason = SE.classify(finding)
            self.assertFalse(ok, finding)
            self.assertIn(expect, reason)


class TestCollect(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="sweep-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.results, self.phase0, self.sweeps = make_fixtures(self.tmp)

    def test_confirmed_weaknesses_do_not_become_exploitable_rule_mining_seeds(self):
        base = {
            "source": "example-delta.json#0",
            "title": "Security claim",
            "cwe": "CWE-532",
            "file": "collector/filter.py",
            "claimed_severity": "high",
        }
        write_json(
            self.phase0 / "fast-track-criticals-triage.json",
            {
                "findings": [
                    {**base, "id": "unknown-kind", "verdict": "true_positive"},
                    {
                        **base,
                        "id": "vulnerability",
                        "verdict": "true_positive",
                        "kind": "vulnerability",
                    },
                    {
                        **base,
                        "id": "weakness",
                        "verdict": "true_positive",
                        "kind": "weakness",
                        "severity": None,
                        "exclusion_rule": "13",
                    },
                    {**base, "id": "historical-weakness", "verdict": "hardening"},
                ]
            },
        )
        findings = SE.collect_fast_track(self.phase0)
        self.assertEqual(
            {
                f["finding_id"]
                for f in findings
                if f["artifact"] == "fast-track-criticals-triage.json"
            },
            {"unknown-kind", "vulnerability"},
        )

    def test_collect_classifies_all_sources(self):
        res = SE.do_collect(self.results, self.phase0, self.sweeps)
        self.assertFalse(res["skipped"])
        state = json.loads((self.sweeps / "_state" / "collect.json").read_text())
        # 3 confirmed ledger (proposed FIND-003 excluded) + 1 fast-track
        # triage TP + 1 wave TP + 2 matrix + 1 0d = 8
        self.assertEqual(state["stats"]["confirmed_findings"], 8)
        self.assertEqual(
            state["stats"]["by_source"],
            {"ledger": 3, "fast-track": 2, "matrix-stage2": 2, "dual-0d": 1},
        )
        # expressible: CWE-78/go, CWE-532/python, CWE-798/go, CWE-295/go
        class_ids = {c["class_id"] for c in state["classes"]}
        self.assertEqual(class_ids, {"CWE-78/go", "CWE-532/python", "CWE-798/go", "CWE-295/go"})
        self.assertEqual(state["stats"]["rule_expressible"], 4)
        # every non-expressible record carries a reason
        reasons = {
            f["reason"].split(":")[0] for f in state["findings"] if not f["rule_expressible"]
        }
        self.assertEqual(reasons, {"semantic_logic_class", "dependency_version_class"})

    def test_collect_is_resumable(self):
        first = SE.do_collect(self.results, self.phase0, self.sweeps)
        self.assertFalse(first["skipped"])
        second = SE.do_collect(self.results, self.phase0, self.sweeps)
        self.assertTrue(second["skipped"])
        forced = SE.do_collect(self.results, self.phase0, self.sweeps, force=True)
        self.assertFalse(forced["skipped"])


class TestDraft(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="sweep-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.results, self.phase0, self.sweeps = make_fixtures(self.tmp)
        SE.do_collect(self.results, self.phase0, self.sweeps)
        # fixture pack already covers CWE-78/go
        self.pack = self.tmp / "pack"
        (self.pack / "go").mkdir(parents=True)
        (self.pack / "go" / "injection.yaml").write_text(
            "rules:\n"
            "  - id: traust-go-cmd-injection\n"
            "    languages: [go]\n"
            "    severity: ERROR\n"
            "    message: m\n"
            "    metadata:\n"
            '      cwe: ["CWE-78"]\n'
            '    pattern: exec.Command("sh", "-c", ...)\n'
        )
        self.drafts = self.tmp / "rule-drafts"
        self.drafts.mkdir()

    def test_draft_dedups_against_pack_and_existing_drafts(self):
        res = SE.do_draft(self.sweeps, self.pack, self.drafts)
        emitted = set(res["emitted"])
        self.assertEqual(emitted, {"sweep-python-cwe-532", "sweep-go-cwe-798", "sweep-go-cwe-295"})
        covered = [s for s in res["skipped"] if s["class"] == "CWE-78/go"]
        self.assertEqual(len(covered), 1)
        self.assertIn("covered_by_pack", covered[0]["reason"])
        # draft dir follows the C6 conventions and cites sources
        d = self.drafts / "sweep-go-cwe-798"
        self.assertTrue((d / "DRAFT.md").is_file())
        skeleton = (d / "rule.skeleton.yaml").read_text()
        self.assertIn("id: traust-go-sweep-cwe-798", skeleton)
        self.assertIn("generalized_from", skeleton)
        self.assertIn("repoc", skeleton)
        self.assertIn("cmd/main.go", (d / "DRAFT.md").read_text())

    def test_draft_rerun_skips_existing(self):
        SE.do_draft(self.sweeps, self.pack, self.drafts)
        res2 = SE.do_draft(self.sweeps, self.pack, self.drafts)
        self.assertEqual(res2["emitted"], [])
        self.assertTrue(
            all(s["reason"] == "draft_exists" for s in res2["skipped"] if s["class"] != "CWE-78/go")
        )


AUTHORED_RULE = """rules:
  - id: traust-go-sweep-cwe-78
    languages: [go]
    severity: ERROR
    message: sh -c command execution sink
    metadata:
      cwe: ["CWE-78"]
      category: sweep-generalization
      generalized_from:
        - source_finding: "FIND-001"
          repo: "repoa"
          location: "pkg/run.go:10"
          artifact: "ledger:prod/repoa"
    pattern: exec.Command("sh", "-c", ...)
"""


class TestSweepAndEmit(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="sweep-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.sweeps = self.tmp / "sweeps"
        self.pack = self.tmp / "pack"
        self.pack.mkdir()
        self.drafts = self.tmp / "rule-drafts"
        self.drafts.mkdir()
        self.rule = self.tmp / "rule.yaml"
        self.rule.write_text(AUTHORED_RULE)
        # fixture "corpus": two local repos, one with the vulnerable shape
        hit = self.tmp / "repos" / "hit-repo"
        hit.mkdir(parents=True)
        (hit / "main.go").write_text(
            'package main\nimport "os/exec"\nfunc f(c string) { exec.Command("sh", "-c", c) }\n'
        )
        clean = self.tmp / "repos" / "clean-repo"
        clean.mkdir()
        (clean / "main.go").write_text("package main\nfunc f() {}\n")
        self.repos = self.tmp / "repos.json"
        # scan-in-place needs the explicit dir: prefix (plan P3)
        self.repos.write_text(
            json.dumps(
                [
                    {"slug": "hit-repo", "url": f"dir:{hit}"},
                    {"slug": "clean-repo", "url": f"dir:{clean}"},
                ]
            )
        )

    def test_sweep_refuses_unauthored_skeleton(self):
        todo = self.tmp / "todo.yaml"
        todo.write_text("rules:\n  - id: x-sweep\n    pattern: TODO\n")
        with self.assertRaises(SystemExit):
            SE.do_sweep(
                str(todo),
                self.sweeps,
                self.pack,
                self.drafts,
                None,
                self.repos,
                10,
                None,
                "opengrep",
                60,
                cfg=MINIMAL_CORPUS,
            )

    @pytest.mark.integration
    @unittest.skipUnless(shutil.which("opengrep"), "opengrep not on PATH")
    def test_sweep_collects_hits_and_resumes(self):
        res = SE.do_sweep(
            str(self.rule),
            self.sweeps,
            self.pack,
            self.drafts,
            None,
            self.repos,
            10,
            None,
            "opengrep",
            120,
            cfg=MINIMAL_CORPUS,
        )
        self.assertEqual(res["rule_id"], "traust-go-sweep-cwe-78")
        self.assertEqual((res["swept"], res["skipped"]), (2, 0))
        self.assertEqual(res["hits"], 1)
        per_repo = json.loads(
            (self.sweeps / "traust-go-sweep-cwe-78" / "repos" / "hit-repo.json").read_text()
        )
        self.assertEqual(per_repo["facts"][0]["file"], "main.go")
        # resumability: second run sweeps nothing
        res2 = SE.do_sweep(
            str(self.rule),
            self.sweeps,
            self.pack,
            self.drafts,
            None,
            self.repos,
            10,
            None,
            "opengrep",
            120,
            cfg=MINIMAL_CORPUS,
        )
        self.assertEqual((res2["swept"], res2["skipped"]), (0, 2))

    def test_emit_schema_and_resumability(self):
        # per-repo results staged directly — emit needs no opengrep
        rid = "traust-go-sweep-cwe-78"
        repo_dir = self.sweeps / rid / "repos"
        repo_dir.mkdir(parents=True)
        write_json(
            repo_dir / "hit-repo.json",
            {
                "slug": "hit-repo",
                "url": "https://github.com/org/hit-repo",
                "rule_id": rid,
                "files_scanned": 3,
                "engine_errors": 0,
                "facts": [
                    {
                        "rule_id": rid,
                        "severity_hint": "high",
                        "file": "main.go",
                        "start_line": 3,
                        "end_line": 3,
                        "message": "sink",
                        "cwe": ["CWE-78"],
                        "owasp": [],
                        "confidence": None,
                        "taint": False,
                        "snippet": 'exec.Command("sh", "-c", c)',
                        "test_path": False,
                    }
                ],
            },
        )
        write_json(
            repo_dir / "err-repo.json",
            {"slug": "err-repo", "url": "https://x", "rule_id": rid, "error": "clone_failed"},
        )
        res = SE.do_emit(str(self.rule), self.sweeps, self.pack, self.drafts)
        self.assertFalse(res["skipped"])
        report = json.loads(Path(res["out"]).read_text())
        # triage-input header is explicit in the artifact itself
        self.assertEqual(report["artifact"], "sweep-candidates")
        self.assertIn("never files findings", report["purpose"])
        self.assertIn("triage workflow", report["purpose"])
        self.assertEqual(report["rule_id"], rid)
        self.assertEqual(report["repos_swept"], 2)
        self.assertEqual(report["repos_with_hits"], 1)
        self.assertEqual(report["repo_errors"], 1)
        cand = report["candidates"][0]
        for key in (
            "repo",
            "url",
            "file",
            "line",
            "location",
            "excerpt",
            "rule_id",
            "source_finding_provenance",
        ):
            self.assertIn(key, cand)
        self.assertEqual(cand["location"], "main.go:3")
        self.assertEqual(cand["source_finding_provenance"], ["FIND-001"])
        # provenance from rule metadata
        self.assertEqual(report["source_findings"][0]["source_finding"], "FIND-001")
        summary = (self.sweeps / rid / "sweep-summary.md").read_text()
        self.assertIn("never files findings", summary)
        self.assertIn("triage workflow", summary)
        # resumability
        res2 = SE.do_emit(str(self.rule), self.sweeps, self.pack, self.drafts)
        self.assertTrue(res2["skipped"])
        res3 = SE.do_emit(str(self.rule), self.sweeps, self.pack, self.drafts, force=True)
        self.assertFalse(res3["skipped"])

    def test_resolve_rule_by_id_and_draft_dir(self):
        # by draft dir name
        d = self.drafts / "sweep-go-cwe-78"
        d.mkdir()
        (d / "rule.skeleton.yaml").write_text(AUTHORED_RULE)
        self.assertEqual(
            SE.resolve_rule("sweep-go-cwe-78", self.pack, self.drafts),
            (d / "rule.skeleton.yaml").resolve(),
        )
        # by bare rule id (found in drafts)
        self.assertEqual(
            SE.resolve_rule("traust-go-sweep-cwe-78", self.pack, self.drafts),
            (d / "rule.skeleton.yaml").resolve(),
        )
        with self.assertRaises(SystemExit):
            SE.resolve_rule("no-such-rule", self.pack, self.drafts)


if __name__ == "__main__":
    unittest.main()
