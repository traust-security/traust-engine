"""Below-range applicability evidence: candidates, fix choice, matching, packets."""

import io
import json
import tarfile
import zipfile
from collections import Counter

import pytest

from traust_engine.applicability import BELOW_RANGE, GAP, classify
from traust_engine.applicability.fetch import Fetcher, FetchRefused, extract
from traust_engine.applicability.fixes import (
    Commit,
    FileChange,
    narrow,
    only_adds,
    parse_mbox,
    patch_url,
    references,
    release_like,
)
from traust_engine.applicability.matching import anchor, presence
from traust_engine.applicability.packet import build
from traust_engine.osv import BatchOutcome


def _rec(
    *ranges,
    name="example.com/lib",
    eco="Go",
    vid="GHSA-test-0001",
    aliases=("CVE-2026-0001",),
    refs=(),
):
    return {
        "id": vid,
        "aliases": list(aliases),
        "summary": "flaw in parse",
        "affected": [{"package": {"name": name, "ecosystem": eco}, "ranges": list(ranges)}],
        "references": list(refs),
    }


def _semver(*events):
    return {"type": "SEMVER", "events": list(events)}


# ----------------------------------------------------------------- candidates


def test_below_every_stated_start_is_a_candidate():
    rec = _rec(_semver({"introduced": "2.0.0"}, {"fixed": "2.3.0"}))
    c = classify(rec, "Go", "example.com/lib", "1.4.0")
    assert c.kind == BELOW_RANGE and c.stated_start == "2.0.0" and c.major_distance == 1


def test_inside_a_span_or_listed_is_not_a_candidate():
    rec = _rec(_semver({"introduced": "2.0.0"}, {"fixed": "2.3.0"}))
    assert classify(rec, "Go", "example.com/lib", "2.1.0") is None
    rec["affected"][0]["versions"] = ["1.4.0"]
    assert classify(rec, "Go", "example.com/lib", "1.4.0") is None


def test_after_an_unfixed_span_and_before_the_next_is_a_gap():
    rec = _rec(
        _semver(
            {"introduced": "0"},
            {"last_affected": "1.5.0"},
            {"introduced": "2.0.0"},
            {"fixed": "2.3.0"},
        )
    )
    c = classify(rec, "Go", "example.com/lib", "1.7.0")
    assert c.kind == GAP and c.stated_start == "2.0.0"


def test_after_a_fixed_span_is_not_a_gap():
    # urllib3 shape: the 1.x line is fixed in 1.26.17; 1.26.18 is simply fixed
    rec = _rec(
        _semver(
            {"introduced": "0"}, {"fixed": "1.26.17"}, {"introduced": "2.0.0"}, {"fixed": "2.2.2"}
        )
    )
    assert classify(rec, "Go", "example.com/lib", "1.26.18") is None


def test_introduced_zero_and_above_every_fix_are_not_candidates():
    rec = _rec(_semver({"introduced": "0"}, {"fixed": "1.5.0"}))
    assert classify(rec, "Go", "example.com/lib", "1.6.0") is None


def test_pypi_names_compare_normalized():
    rec = _rec(
        {"type": "ECOSYSTEM", "events": [{"introduced": "3.2"}, {"fixed": "3.2.21"}]},
        name="Example_Lib",
        eco="PyPI",
    )
    c = classify(rec, "PyPI", "example-lib", "2.2.2")
    assert c is not None and c.kind == BELOW_RANGE


# ----------------------------------------------------------------- fix choice


def test_references_rank_git_fixed_then_fix_then_links():
    rec = _rec(
        {
            "type": "GIT",
            "repo": "https://github.com/ex/lib",
            "events": [{"introduced": "0"}, {"fixed": "a" * 40}],
        },
        refs=[
            {"type": "WEB", "url": "https://github.com/ex/lib/pull/7"},
            {"type": "FIX", "url": "https://github.com/ex/lib/commit/" + "b" * 40},
            {"type": "WEB", "url": "https://evil.example/ex/lib/commit/" + "c" * 40},
        ],
    )
    ranked = references(rec, frozenset({"github.com"}))
    assert [r for r, _ in ranked] == [0, 1, 2]
    assert all("evil.example" not in u for _, u in ranked)


def test_patch_url_forms():
    assert (
        patch_url("https://github.com/o/r/commit/" + "a" * 40)
        == "https://github.com/o/r/commit/" + "a" * 40 + ".patch"
    )
    assert patch_url("https://github.com/o/r/pull/12") == "https://github.com/o/r/pull/12.patch"
    assert patch_url("https://github.com/o/r/issues/3") is None


BUNDLE = (
    "From " + "1" * 40 + " Mon Sep 17 00:00:00 2001\n"
    "Subject: [PATCH 1/2] refactor imports\n\n---\n"
    "diff --git a/lib/a.go b/lib/a.go\n--- a/lib/a.go\n+++ b/lib/a.go\n@@ -1 +1 @@\n-import x\n+import y\n"
    "From " + "2" * 40 + " Mon Sep 17 00:00:00 2001\n"
    "Subject: [PATCH 2/2] fix CVE-2026-0001: bound the parser\n\n---\n"
    "diff --git a/lib/parse.go b/lib/parse.go\n--- a/lib/parse.go\n+++ b/lib/parse.go\n@@ -3,2 +3,2 @@\n"
    "-\treturn parse(s)\n+\treturn parseBounded(s)\n"
    "diff --git a/lib/parse_test.go b/lib/parse_test.go\n--- a/lib/parse_test.go\n+++ b/lib/parse_test.go\n@@ -1 +1 @@\n-x\n+y\n"
)


def test_bundle_narrows_to_the_commit_naming_the_advisory_and_drops_tests():
    commits = parse_mbox(BUNDLE)
    assert [c.subject for c in commits] == [
        "refactor imports",
        "fix CVE-2026-0001: bound the parser",
    ]
    (named,) = narrow(commits, {"CVE-2026-0001"})
    assert [f.path for f in named.files] == ["lib/parse.go"]


def test_only_adds_marks_a_feature_introduction():
    assert only_adds([FileChange("a.go", [{"removed": [], "added": ["x"]}])])
    assert not only_adds([FileChange("a.go", [{"removed": ["y"], "added": ["x"]}])])


# ----------------------------------------------------------------- matching


def test_anchor_strips_a_consistent_prefix_and_never_matches_by_base_name(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "parse.go").write_text("x")
    (tmp_path / "lib" / "web" / "cache").mkdir(parents=True)
    (tmp_path / "lib" / "web" / "cache" / "cache.js").write_text("unrelated")
    files = [FileChange("sub/pkg/parse.go"), FileChange("lib/util/cache.js")]
    strip, found = anchor(files, tmp_path)
    assert strip == 1 and set(found) == {"sub/pkg/parse.go"}


def test_presence_counts_removed_and_added_lines(tmp_path):
    (tmp_path / "parse.go").write_text("func f() {\n\treturn parse(s)\n}\n")
    rows = presence(
        [
            FileChange(
                "parse.go",
                [{"removed": ["\treturn parse(s)"], "added": ["\treturn parseBounded(s)"]}],
            )
        ],
        tmp_path,
    )
    assert rows[0]["hunks"] == [
        {"removed_lines": 1, "removed_present": 1, "added_lines": 1, "added_present": 0}
    ]


# ----------------------------------------------------------------- fetching


def test_fetcher_refuses_hosts_and_redirects_off_the_list():
    f = Fetcher(transport=lambda u: (b"x", u))
    with pytest.raises(FetchRefused):
        f.patch("https://evil.example/o/r/commit/abc.patch")
    with pytest.raises(FetchRefused):
        f.patch("http://github.com/o/r/commit/abc.patch")
    bounced = Fetcher(transport=lambda u: (b"x", "https://evil.example/x"))
    with pytest.raises(FetchRefused):
        bounced.patch("https://github.com/o/r/commit/abc.patch")
    proxied = Fetcher(transport=lambda u: (b"x", "https://storage.googleapis.com/blob"))
    assert proxied.get("https://proxy.golang.org/m/@v/v1.0.0.zip", proxied.registries) == b"x"


def test_extract_skips_escapes_and_links(tmp_path):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in (("pkg-1.0/ok.py", b"ok"), ("../escape.py", b"bad"), ("/abs.py", b"bad")):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo("pkg-1.0/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        tf.addfile(link)
    n = extract(buf.getvalue(), "tar", tmp_path / "out")
    assert n == 1 and (tmp_path / "out" / "pkg-1.0" / "ok.py").read_text() == "ok"
    assert not (tmp_path / "escape.py").exists()


# ----------------------------------------------------------------- end to end


class FakeOsv:
    def __init__(self, recs):
        self.recs = recs

    def query_batch(self, queries):
        ids = [
            [r["id"] for r in self.recs if r["affected"][0]["package"]["name"] == q.name]
            for q in queries
        ]
        return BatchOutcome(ids, Counter())

    def get_vulns(self, ids):
        return {r["id"]: r for r in self.recs if r["id"] in set(ids)}, Counter()


def _module_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("example.com/lib@v1.4.0/go.mod", "module example.com/lib\n")
        z.writestr(
            "example.com/lib@v1.4.0/parse.go",
            "package lib\nfunc P(s string) {\n\treturn parse(s)\n}\n",
        )
    return buf.getvalue()


FEATURE = (
    "From " + "3" * 40 + " Mon Sep 17 00:00:00 2001\nSubject: [PATCH] add streaming API\n\n---\n"
    "diff --git a/stream.go b/stream.go\n--- /dev/null\n+++ b/stream.go\n@@ -0,0 +1 @@\n+package lib\n"
)
FIX = (
    "From "
    + "4" * 40
    + " Mon Sep 17 00:00:00 2001\nSubject: [PATCH] bound the parser (CVE-2026-0001)\n\n---\n"
    "diff --git a/parse.go b/parse.go\n--- a/parse.go\n+++ b/parse.go\n@@ -2,2 +2,2 @@\n"
    "-\treturn parse(s)\n+\treturn parseBounded(s)\n"
)


def test_build_writes_a_packet_and_picks_the_real_fix(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "go.mod").write_text("module example.com/app\n\nrequire example.com/lib v1.4.0\n")
    rec = _rec(
        _semver({"introduced": "2.0.0"}, {"fixed": "2.3.0"}),
        refs=[
            {"type": "WEB", "url": "https://github.com/ex/lib/commit/" + "3" * 40},
            {"type": "WEB", "url": "https://github.com/ex/lib/commit/" + "4" * 40},
        ],
    )
    bodies = {
        "https://github.com/ex/lib/commit/" + "3" * 40 + ".patch": FEATURE.encode(),
        "https://github.com/ex/lib/commit/" + "4" * 40 + ".patch": FIX.encode(),
        "https://proxy.golang.org/example.com/lib/@v/v1.4.0.zip": _module_zip(),
    }
    fetcher = Fetcher(transport=lambda u: (bodies[u], u))
    index = build(repo, tmp_path / "out", client=FakeOsv([rec]), fetcher=fetcher)
    assert index["candidates"] == 1 and len(index["packets"]) == 1 and index["coverage_gaps"] == []
    packet = json.loads(
        (tmp_path / "out" / index["packets"][0]["case"] / "packet.json").read_text()
    )
    assert packet["fix"]["chosen"]["url"].endswith("4" * 40)
    assert packet["fix"]["chosen"]["names_advisory"] is True
    (row,) = packet["hunk_presence"]
    assert row["installed_path"] == "parse.go"
    assert row["hunks"][0]["removed_present"] == 1 and row["hunks"][0]["added_present"] == 0


def test_build_accounts_for_a_missing_source_as_a_gap(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "go.mod").write_text("module example.com/app\n\nrequire example.com/lib v1.4.0\n")
    rec = _rec(_semver({"introduced": "2.0.0"}, {"fixed": "2.3.0"}))

    def transport(url):
        raise OSError("404")

    index = build(
        repo, tmp_path / "out", client=FakeOsv([rec]), fetcher=Fetcher(transport=transport)
    )
    assert index["packets"] == [] and [g["reason"] for g in index["coverage_gaps"]] == [
        "source_unavailable"
    ]


def test_alias_records_supply_fix_commits():
    ghsa = _rec(
        _semver({"introduced": "2.0.0"}, {"fixed": "2.3.0"}),
        refs=[{"type": "PACKAGE", "url": "https://github.com/ex/lib"}],
    )
    cve = {
        "id": "CVE-2026-0001",
        "affected": [
            {
                "ranges": [
                    {
                        "type": "GIT",
                        "repo": "https://github.com/ex/lib",
                        "events": [{"fixed": "4" * 40}],
                    }
                ]
            }
        ],
    }
    assert references(ghsa, frozenset({"github.com"})) == []
    assert references(ghsa, frozenset({"github.com"}), [cve]) == [
        (0, "https://github.com/ex/lib/commit/" + "4" * 40)
    ]


def test_two_records_for_one_cve_make_one_candidate():
    from traust_engine.applicability.packet import candidates

    ghsa = _rec(_semver({"introduced": "2.0.0"}, {"fixed": "2.3.0"}), vid="GHSA-aaaa-bbbb-cccc")
    go = _rec(_semver({"introduced": "2.0.0"}, {"fixed": "2.3.0"}), vid="GO-2026-0001")
    out, unanswered = candidates([("Go", "example.com/lib", "1.4.0")], FakeOsv([ghsa, go]))
    assert unanswered == [] and len(out) == 1
    _c, rec, aliases = out[0]
    assert rec["id"] == "GHSA-aaaa-bbbb-cccc" and [a["id"] for a in aliases] == ["GO-2026-0001"]


def test_release_commits_are_recognised():
    bump = [Commit("1" * 40, "[6.0.x] Bumped version for 6.0.6 release.", "", [])]
    assert release_like(
        bump, [FileChange("django/__init__.py", [{"removed": ["a"], "added": ["b"]}])]
    )
    assert release_like(
        [], [FileChange("docs/releases/4.2.txt", [{"removed": [], "added": ["x"]}])]
    )
    real = [Commit("2" * 40, "Fixed CVE-2026-0001 -- bounded the parser.", "", [])]
    assert not release_like(
        real, [FileChange("django/utils/html.py", [{"removed": ["a"], "added": ["b"]}])]
    )
