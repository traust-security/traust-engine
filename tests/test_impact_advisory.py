"""The impact analysis takes its range from the advisory's OSV record."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

from traust_engine.impact.advisory import AdvisoryUnavailable, resolve
from traust_engine.impact.analyzer import ImpactParams, _execute
from traust_engine.osv.client import BatchOutcome
from traust_engine.osv.ranges import covers
from traust_engine.portfolio.graph import db_connect


def _record(vid, name, events, *, eco="PyPI", aliases=()):
    return {
        "id": vid,
        "aliases": list(aliases),
        "affected": [
            {
                "package": {"name": name, "ecosystem": eco},
                "ranges": [{"type": "ECOSYSTEM", "events": events}],
            }
        ],
    }


GHSA = _record(
    "GHSA-aaaa-bbbb-cccc",
    "brotli",
    [{"introduced": "1.0.3"}, {"fixed": "1.2.1"}],
    aliases=["CVE-2026-0001"],
)
PYSEC = _record(
    "PYSEC-2026-1", "brotli", [{"introduced": "0"}, {"fixed": "1.2.1"}], aliases=["CVE-2026-0001"]
)


class FakeOsv:
    base_url = "https://osv.test/v1"

    def __init__(self, records, *, package_ids=None, answers=True):
        self.records = {r["id"]: r for r in records}
        self.package_ids = package_ids or sorted(self.records)
        self.answers = answers

    def get_vulns(self, ids):
        return {i: self.records[i] for i in ids if i in self.records}, Counter()

    def query_batch(self, queries):
        if not self.answers:
            return BatchOutcome(ids=[None], issues=Counter(unreachable=1))
        return BatchOutcome(ids=[self.package_ids])


def test_the_range_and_source_come_from_the_record():
    a = resolve("GHSA-aaaa-bbbb-cccc", "brotli", "pypi", client=FakeOsv([GHSA]))
    assert a.sources == ("https://osv.test/v1/vulns/GHSA-aaaa-bbbb-cccc",)
    assert (a.vulnerable_range, a.fixed_version) == (">=1.0.3 <1.2.1", "1.2.1")
    assert [a.in_range(v) for v in ("1.0.2", "1.1.0", "1.2.1", "garbage")] == [
        False,
        True,
        False,
        None,
    ]


def test_an_alias_is_found_through_the_module_and_every_record_is_kept():
    a = resolve("CVE-2026-0001", "Brotli", "pypi", client=FakeOsv([GHSA, PYSEC]))
    assert len(a.sources) == 2
    assert a.in_range("1.0.2") is True  # PYSEC's span starts at 0


def test_several_spans_keep_their_lower_bounds():
    rec = _record(
        "GO-2026-1",
        "example.com/mod",
        [{"introduced": "0"}, {"fixed": "1.5.0"}, {"introduced": "2.0.0"}, {"fixed": "2.3.0"}],
        eco="Go",
    )
    a = resolve("GO-2026-1", "example.com/mod", "go", client=FakeOsv([rec]))
    assert a.vulnerable_range == "<1.5.0 || >=2.0.0 <2.3.0"
    assert a.fixed_version == "2.3.0"
    assert [a.in_range(v) for v in ("v1.4.0", "v1.6.0", "v2.1.0")] == [True, False, True]


@pytest.mark.parametrize(
    ("client", "module", "eco", "why"),
    [
        (FakeOsv([GHSA]), "requests", "pypi", "names no affected version"),
        (FakeOsv([]), "brotli", "pypi", "no record"),
        (FakeOsv([], answers=False), "brotli", "pypi", "did not answer"),
        (FakeOsv([GHSA]), "alpine", "docker", "no docker advisories"),
    ],
)
def test_without_a_usable_record_the_advisory_is_not_assessed(client, module, eco, why):
    with pytest.raises(AdvisoryUnavailable, match=why):
        resolve("GHSA-aaaa-bbbb-cccc", module, eco, client=client)


def test_an_air_gapped_run_reads_the_supplied_record(tmp_path):
    path = tmp_path / "ghsa.json"
    path.write_text(json.dumps(GHSA))
    a = resolve("CVE-2026-0001", "brotli", "pypi", advisory_file=str(path))
    assert a.sources == (path.resolve().as_uri(),)
    with pytest.raises(AdvisoryUnavailable, match="not GHSA-zzzz"):
        resolve("GHSA-zzzz-zzzz-zzzz", "brotli", "pypi", advisory_file=str(path))


def test_covers_cannot_decide_an_unorderable_bound():
    rec = _record("X-1", "p", [{"introduced": "0"}, {"fixed": "not-a-version"}])
    assert covers(rec, "p", "PyPI", "1.0") is None


def test_the_artifact_records_the_fetched_range_and_sources(tmp_path):
    db = tmp_path / "graph.db"
    con = db_connect(db)
    for repo, ver in (("repo:github.com/o/old", "1.0.2"), ("repo:github.com/o/hit", "1.1.0")):
        con.execute(
            "INSERT INTO edges (src, dst, rel, attrs) VALUES (?, 'pkg:pypi/brotli', 'depends_on', ?)",
            (repo, json.dumps({"version": ver, "indirect": 0, "ecosystem": "pypi"})),
        )
    con.commit()
    con.close()
    out = tmp_path / "ghsa-aaaa-bbbb-cccc-impact-analysis.json"
    advisory = resolve("GHSA-aaaa-bbbb-cccc", "brotli", "pypi", client=FakeOsv([GHSA]))
    params = ImpactParams(
        cve="GHSA-aaaa-bbbb-cccc",
        module="brotli",
        ecosystem="pypi",
        advisory=advisory,
        out=str(out),
        skip_scan=True,
    )
    assert _execute(params, Path(db)) == 0
    doc = json.loads(out.read_text())
    meta = doc["metadata"]
    assert meta["advisory_sources"] == ["https://osv.test/v1/vulns/GHSA-aaaa-bbbb-cccc"]
    assert (meta["vulnerable_range"], meta["fixed_version"]) == (">=1.0.3 <1.2.1", "1.2.1")
    verdicts = {r["repo"]: r["classification"] for r in doc["repos"]}
    assert verdicts["repo:github.com/o/old"] == "version_not_in_range"
    assert verdicts["repo:github.com/o/hit"] != "version_not_in_range"
