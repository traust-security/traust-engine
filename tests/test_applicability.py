"""Below-range applicability evidence: candidates, fix choice, matching, packets."""

import io
import json
import tarfile
import zipfile
from collections import Counter

import pytest

from traust_engine.applicability import BELOW_RANGE, GAP, classify
from traust_engine.applicability.fetch import (
    Fetcher,
    FetchRefused,
    archive_url,
    extract,
    nuget_version,
)
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


# ----------------------------------------------------------------- npm, Maven, Cargo


def test_registry_urls_for_npm_maven_and_cargo():
    f = Fetcher()
    assert f.source_url("npm", "@scope/pkg", "1.2.3") == (
        "https://registry.npmjs.org/@scope/pkg/-/pkg-1.2.3.tgz",
        "tar",
    )
    assert f.source_url("crates.io", "tokio", "1.38.0") == (
        "https://static.crates.io/crates/tokio/tokio-1.38.0.crate",
        "tar",
    )
    assert f.source_url("Maven", "com.fasterxml.jackson.core:jackson-databind", "2.13.4") == (
        "https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-databind/2.13.4/"
        "jackson-databind-2.13.4-sources.jar",
        "zip",
    )
    with pytest.raises(FetchRefused):
        f.source_url("Maven", "no-group", "1.0")


def test_exact_installs_per_ecosystem():
    from traust_engine.applicability.packet import exact

    assert exact("crates.io", "1.38.0", "locked") and not exact("crates.io", "1", "manifest-floor")
    assert exact("npm", "4.17.21", "manifest-floor") and not exact("npm", "4.17", "manifest-floor")
    assert exact("Maven", "2.13.4", "manifest-floor") and exact("Go", "1.4.0", "manifest-floor")
    assert not exact("PyPI", "2.2", "manifest-floor") and exact("PyPI", "2.2.2", "locked")
    assert not exact("PyPI", "2.2.2", "resolved") and not exact("Go", "1.22.0", "go-directive")
    assert exact("NuGet", "13.0.1", "manifest-floor") and not exact(
        "NuGet", "2.1", "manifest-floor"
    )
    assert exact("RubyGems", "2.2.8", "locked") and not exact("RubyGems", "6.4.0", "manifest-floor")


def test_maven_sources_anchor_below_the_module_source_root(tmp_path):
    (tmp_path / "com" / "ex").mkdir(parents=True)
    (tmp_path / "com" / "ex" / "Parser.java").write_text("x")
    files = [FileChange("core/src/main/java/com/ex/Parser.java")]
    strip, found = anchor(files, tmp_path)
    assert strip == 4 and set(found) == {"core/src/main/java/com/ex/Parser.java"}


def test_redirects_are_configurable():
    f = Fetcher(
        transport=lambda u: (b"x", "https://mirror.example/blob"),
        redirects={"pypi.org": frozenset({"mirror.example"})},
    )
    assert f.get("https://pypi.org/x", f.registries) == b"x"
    with pytest.raises(FetchRefused):
        Fetcher(transport=lambda u: (b"x", "https://mirror.example/blob")).get(
            "https://pypi.org/x", f.registries
        )


@pytest.mark.parametrize(
    "subject",
    [
        "chore: bump version to 2.131.0 [skip ci]",
        "bump for 41.0.2 (#9215)",
        "chore(release): prepare release 1.18.0 (#11003)",
        "chore(release): v1.13.2 (#7207)",
        "Bumped v8.9.0 (#5589)",
        "chore(master): release 10.0.5 (#1864)",
        "[6.0.x] Bumped version for 6.0.6 release.",
        "Release Wasmtime 46.0.3 (#14170)",
        "Version Packages (#13362)",
    ],
)
def test_release_subjects_seen_in_real_fix_links(subject):
    assert release_like([Commit("1" * 40, subject, "", [])], [])


@pytest.mark.parametrize(
    "subject",
    [
        "Fixed CVE-2025-14550 -- Optimized repeated header parsing in ASGI requests.",
        "fix: normalize recursive JWT payload errors",
        "chore(deps): bump lodash from 4.17.20 to 4.17.21",
        "Bump golang.org/x/net dependency to v0.23.0",
        "[PR #8652/b0536ae6 backport][3.10] Do not follow symlinks for compressed file variants",
        "Merge commit from fork",
        "Release the lock before returning",
        "fix: version packages resolution in monorepo",
    ],
)
def test_fix_subjects_are_not_release_commits(subject):
    files = [FileChange("lib/x.py", [{"removed": ["a"], "added": ["b"]}])]
    assert not release_like([Commit("2" * 40, subject, "", [])], files)


def test_a_markdown_only_change_is_not_a_fix():
    assert release_like([], [FileChange("README.md", [{"removed": ["a"], "added": ["b"]}])])


# ----------------------------------------------------------------- dating


def _dated(subject, date):
    return Commit("9" * 40, subject, f"From: x\nDate: {date}\nSubject: {subject}\n", [])


def test_commit_date_is_read_from_the_patch_header():
    from traust_engine.applicability.dating import commit_date

    d = commit_date(_dated("fix", "Tue, 23 Apr 2024 18:33:49 +0300"))
    assert d.isoformat() == "2024-04-23T18:33:49+03:00"
    assert commit_date(Commit("1" * 40, "x", "no date here", [])) is None


def test_packets_carry_commit_and_fix_release_dates(tmp_path):
    from traust_engine.applicability.dating import latest

    commits = [
        _dated("a", "Mon, 15 Apr 2024 10:00:00 +0000"),
        _dated("b", "Tue, 16 Apr 2024 10:00:00 +0000"),
    ]
    assert latest(commits) == "2024-04-16T10:00:00+00:00"
    assert latest([Commit("1" * 40, "x", "no date", [])]) is None


def test_release_times_come_from_the_registries():
    pages = {
        "https://proxy.golang.org/example.com/lib/@v/v1.4.0.info": b'{"Version":"v1.4.0","Time":"2024-02-01T00:12:23Z"}',
        "https://pypi.org/pypi/pkg/1.0/json": b'{"urls":[{"upload_time_iso_8601":"2023-11-01T06:59:10Z"}]}',
        "https://registry.npmjs.org/lib": b'{"time":{"1.2.3":"2022-01-02T03:04:05.000Z"}}',
    }
    f = Fetcher(transport=lambda u: (pages[u], u))
    assert f.release_time("Go", "example.com/lib", "1.4.0") == "2024-02-01T00:12:23Z"
    assert f.release_time("PyPI", "pkg", "1.0") == "2023-11-01T06:59:10Z"
    assert f.release_time("npm", "lib", "1.2.3") == "2022-01-02T03:04:05.000Z"
    assert f.release_time("Maven", "g:a", "1.0") is None


def test_rubygems_release_time_skips_platform_builds():
    rows = (
        b'[{"number":"2.2.8","platform":"java","created_at":"2023-01-01T00:00:00Z"},'
        b'{"number":"2.2.8","platform":"ruby","created_at":"2023-07-31T01:02:03Z"}]'
    )
    url = "https://rubygems.org/api/v1/versions/rack.json"
    f = Fetcher(transport=lambda u: ({url: rows}[u], u))
    assert f.release_time("RubyGems", "rack", "2.2.8") == "2023-07-31T01:02:03Z"
    assert f.release_time("NuGet", "Newtonsoft.Json", "13.0.1") is None


# ----------------------------------------------------------------- dependency source


def test_go_requires_are_read_from_go_mod(tmp_path):
    from traust_engine.applicability.dependencies import go_requires

    (tmp_path / "go.mod").write_text(
        "module example.com/lib\n\nrequire example.com/one v1.2.0\n\nrequire (\n\texample.com/two v0.3.1 // indirect\n)\n"
    )
    assert sorted(go_requires(tmp_path)) == [
        ("example.com/one", "1.2.0"),
        ("example.com/two", "0.3.1"),
    ]


@pytest.mark.parametrize(
    "eco,dep,text,expect",
    [
        ("npm", "busboy", "var Busboy = require('busboy')", True),
        ("npm", "busboy", "import Busboy from 'busboy/lib/x'", True),
        ("npm", "busboy", "var b = require('busboyish')", False),
        ("PyPI", "Python-Jose", "from python_jose import jwt", True),
        ("Maven", "org.bouncycastle:bcutil-jdk18on", "import org.bouncycastle.util.Arrays;", True),
        ("crates.io", "rustls-pki-types", "use rustls_pki_types::CertificateDer;", True),
        ("Go", "golang.org/x/net", 'import "golang.org/x/net/http2"', True),
    ],
)
def test_imports(eco, dep, text, expect):
    from traust_engine.applicability.dependencies import imports

    assert imports(eco, dep, text) is expect


class _Resolution:
    def __init__(self, nodes, status="ok"):
        self.nodes, self.status, self.detail = nodes, status, ""

    @property
    def ok(self):
        return self.status == "ok"


class _Resolver:
    def __init__(self, nodes):
        self.nodes = nodes

    def dependencies(self, eco, name, version):
        return _Resolution(self.nodes)


def _tgz(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_an_imported_direct_dependency_joins_the_packet(tmp_path):
    from traust_engine.applicability.dependencies import gather

    root = tmp_path / "pkg"
    (root / "lib").mkdir(parents=True)
    (root / "lib" / "mw.js").write_text("var Busboy = require('busboy')\n")
    tarball = _tgz({"package/lib/types/multipart.js": b"// parser"})
    f = Fetcher(transport=lambda u: (tarball, u))
    resolver = _Resolver(
        [
            ("busboy", "0.2.14", "DIRECT"),
            ("dicer", "0.2.5", "INDIRECT"),
            ("xtend", "4.0.2", "DIRECT"),
        ]
    )
    sources, gaps = gather(
        "npm", "multer", "1.4.2", root, [root / "lib" / "mw.js"], resolver, f, tmp_path / "deps"
    )
    assert gaps == [] and [(s["package"], s["version"], s["imported_by"]) for s in sources] == [
        ("busboy", "0.2.14", ["lib/mw.js"])
    ]
    assert (
        tmp_path / "deps" / "busboy@0.2.14" / "package" / "lib" / "types" / "multipart.js"
    ).is_file()


def test_no_resolver_is_a_recorded_gap(tmp_path):
    from traust_engine.applicability.dependencies import gather

    (tmp_path / "a.py").write_text("import x\n")
    sources, gaps = gather(
        "PyPI", "p", "1.0", tmp_path, [tmp_path / "a.py"], None, Fetcher(), tmp_path / "d"
    )
    assert sources == [] and gaps == [{"reason": "no dependency resolver configured"}]


# ------------------------------------------------------------ RubyGems and NuGet


def _gem(files: dict[str, str]) -> bytes:
    inner = io.BytesIO()
    with tarfile.open(fileobj=inner, mode="w:gz") as tf:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    outer = io.BytesIO()
    with tarfile.open(fileobj=outer, mode="w") as tf:
        for name, data in (("metadata.gz", b"x"), ("data.tar.gz", inner.getvalue())):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return outer.getvalue()


def test_a_gem_extracts_its_data_archive(tmp_path):
    n = extract(
        _gem({"lib/rack/utils.rb": "module Rack; end\n", "../escape.rb": "x"}), "gem", tmp_path
    )
    assert n == 1 and (tmp_path / "lib/rack/utils.rb").is_file()
    assert Fetcher().source_url("RubyGems", "rack", "2.2.8") == (
        "https://rubygems.org/downloads/rack-2.2.8.gem",
        "gem",
    )


def test_nuget_versions_normalize_as_the_flat_container_names_them():
    assert nuget_version("1.23.0") == "1.23.0"
    assert nuget_version("1.0.0.0") == "1.0.0"
    assert nuget_version("1.01.2+build.5") == "1.1.2"
    assert nuget_version("2.0.0-Preview.1") == "2.0.0-preview.1"


def test_archive_urls_for_declared_repositories():
    c = "e" * 40
    assert archive_url("https://github.com/microsoft/kiota", c) == (
        f"https://github.com/microsoft/kiota/archive/{c}.tar.gz"
    )
    assert archive_url("https://github.com/dotnet/runtime.git", c) == (
        f"https://github.com/dotnet/runtime/archive/{c}.tar.gz"
    )
    assert archive_url("https://gitlab.com/grp/sub/proj", c) == (
        f"https://gitlab.com/grp/sub/proj/-/archive/{c}/proj-{c}.tar.gz"
    )
    for bad in (
        "https://dev.azure.com/org/proj",
        "https://github.com/a/../b",
        "https://github.com/a",
    ):
        with pytest.raises(FetchRefused):
            archive_url(bad, c)
    with pytest.raises(FetchRefused):
        archive_url("https://github.com/a/b", "not-a-commit")


NUSPEC = (
    '<?xml version="1.0"?><package><metadata><id>Microsoft.OpenApi.Kiota.Builder</id>'
    "<version>1.23.0</version>"
    '<repository type="git" url="https://github.com/microsoft/kiota" commit="' + "e" * 40 + '" />'
    "</metadata></package>"
)
NUSPEC_URL = (
    "https://api.nuget.org/v3-flatcontainer/microsoft.openapi.kiota.builder/1.23.0/"
    "microsoft.openapi.kiota.builder.nuspec"
)


def _tarball(top: str, files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(f"{top}/{name}")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_nuget_source_is_the_archive_at_the_declared_commit(tmp_path):
    archive = "https://github.com/microsoft/kiota/archive/" + "e" * 40 + ".tar.gz"
    final = "https://codeload.github.com/microsoft/kiota/tar.gz/" + "e" * 40
    bodies = {
        NUSPEC_URL: (NUSPEC.encode(), NUSPEC_URL),
        archive: (_tarball("kiota-" + "e" * 40, {"src/A.cs": "class A {}\n"}), final),
    }
    calls = []

    def transport(u):
        calls.append(u)
        return bodies[u]

    f = Fetcher(transport=transport)
    assert (
        f.nuget_id("microsoft.openapi.kiota.builder", "1.23.0") == "Microsoft.OpenApi.Kiota.Builder"
    )
    src = f.source("NuGet", "Microsoft.OpenApi.Kiota.Builder", "1.23.0", tmp_path / "s")
    assert src["files"] == 1 and src["url"] == archive
    assert src["declared_by"] == {
        "nuspec": NUSPEC_URL,
        "repository": "https://github.com/microsoft/kiota",
        "commit": "e" * 40,
    }
    assert calls.count(NUSPEC_URL) == 1  # fetched once, reused


def test_a_nuspec_without_a_commit_is_refused():
    text = NUSPEC.replace(' commit="' + "e" * 40 + '"', "")
    f = Fetcher(transport=lambda u: (text.encode(), u))
    with pytest.raises(FetchRefused):
        f.nuget_declared("Microsoft.OpenApi.Kiota.Builder", "1.23.0")


def test_nuget_ids_take_the_publishers_casing_or_become_a_gap(tmp_path):
    from traust_engine.applicability.packet import nuget_ids

    def transport(u):
        if u == NUSPEC_URL:
            return NUSPEC.encode(), u
        raise OSError("404")

    pkgs = [
        ("NuGet", "microsoft.openapi.kiota.builder", "1.23.0"),
        ("NuGet", "gone.package", "1.0.0"),
        ("npm", "lodash", "4.17.21"),
    ]
    out, gaps = nuget_ids(pkgs, Fetcher(transport=transport))
    assert out == [
        ("NuGet", "Microsoft.OpenApi.Kiota.Builder", "1.23.0"),
        ("npm", "lodash", "4.17.21"),
    ]
    assert [(g["reason"], g["package"]) for g in gaps] == [("nuget_id_unresolved", "gone.package")]


def test_ruby_version_files_mark_a_release_commit():
    bump = [
        FileChange("lib/kramdown/version.rb", []),
        FileChange("doc/news/release_2_3_1.page", []),
    ]
    assert release_like([], bump)
    dep_fix = [FileChange("Gemfile.lock", []), FileChange("src/App/App.csproj", [])]
    assert not release_like([], dep_fix)
