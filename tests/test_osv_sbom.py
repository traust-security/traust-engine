"""Container-image language packages through OSV: what is sent, what is skipped, dedupe."""

import json
from collections import Counter

import pytest

from traust_engine.adapters import osv_sbom as m
from traust_engine.osv import BatchOutcome, Query


def art(aid, atype, purl, path, name="x", version="1"):
    return {
        "id": aid,
        "type": atype,
        "name": name,
        "version": version,
        "purl": purl,
        "locations": [{"path": path}],
    }


SYFT = {
    "source": {"name": "example/app", "metadata": {"userInput": "example/app:1"}},
    "artifacts": [
        art("r1", "rpm", "pkg:rpm/redhat/python3-urllib3@1.26.5-6.el9", "/var/lib/rpm"),
        art("p1", "python", "pkg:pypi/urllib3@1.26.5", "/usr/lib/python3.9/site-packages/urllib3"),
        art("p2", "python", "pkg:pypi/Requests@2.19.0", "/opt/app-root/lib/requests"),
        art("n1", "npm", "pkg:npm/%40scope/pkg@1.2.3", "/app/node_modules/@scope/pkg/package.json"),
        art("g1", "go-module", "pkg:golang/golang.org/x/net@v0.17.0", "/usr/bin/app"),
        art("g2", "go-module", "pkg:golang/stdlib@1.21.3", "/usr/bin/app"),
        art("g3", "go-module", "pkg:golang/example.com/app/cmd/app", "/usr/bin/app"),
        art(
            "j1",
            "java-archive",
            "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
            "/app/lib/log4j.jar",
        ),
        art("b1", "binary", "pkg:generic/node@18.12.0", "/usr/local/bin/node"),
    ],
    "artifactRelationships": [
        {"parent": "r1", "child": "p1", "type": "ownership-by-file-overlap"},
        {"parent": "g1", "child": "g2", "type": "dependency-of"},
    ],
}


@pytest.mark.parametrize(
    ("purl", "expected"),
    [
        ("pkg:npm/%40isaacs/cliui@8.0.2", ("npm", "@isaacs/cliui", "8.0.2")),
        ("pkg:pypi/Dbus_Python@1.2.18", ("PyPI", "dbus-python", "1.2.18")),
        ("pkg:golang/golang.org/x/net@v0.17.0", ("Go", "golang.org/x/net", "0.17.0")),
        ("pkg:golang/stdlib@go1.26.7", ("Go", "stdlib", "1.26.7")),
        ("pkg:maven/org.yaml/snakeyaml@1.33?type=jar", ("Maven", "org.yaml:snakeyaml", "1.33")),
        ("pkg:cargo/serde@1.0.0", ("crates.io", "serde", "1.0.0")),
        ("pkg:rpm/redhat/openssl@3.0.7", None),
        ("pkg:generic/node@18.12.0", None),
        ("", None),
    ],
)
def test_parse_purl(purl, expected):
    assert m.parse_purl(purl) == expected


def test_os_installed_language_packages_are_left_to_grype():
    packages, stats = m.collect_sbom_packages(SYFT)
    assert ("PyPI", "urllib3", "1.26.5") not in packages  # installed by python3-urllib3
    assert stats["skipped_os_installed"] == 1
    assert stats["skipped_os_installed_by_type"] == {"python": 1}
    assert stats["os_packages"] == 1


def test_what_is_sent():
    packages, stats = m.collect_sbom_packages(SYFT)
    assert set(packages) == {
        ("PyPI", "requests", "2.19.0"),
        ("npm", "@scope/pkg", "1.2.3"),
        ("Go", "golang.org/x/net", "0.17.0"),
        ("Go", "stdlib", "1.21.3"),
        ("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1"),
    }
    assert packages[("PyPI", "requests", "2.19.0")]["sources"] == ["/opt/app-root/lib/requests"]
    assert stats["skipped_unversioned"] == 1  # the Go main module
    assert stats["unsupported_types"] == {"binary": 1}  # grype's CPE matching covers it


def test_cyclonedx_is_refused(tmp_path):
    cdx = tmp_path / "x.cdx.json"
    cdx.write_text(json.dumps({"bomFormat": "CycloneDX", "components": []}))
    with pytest.raises(m.SbomFormatError, match="file-ownership"):
        m.load_syft(cdx)


class FakeClient:
    base_url = "https://osv.test/v1"
    probe_failure = None

    def __init__(self, ids, details):
        self._ids, self._details = ids, details

    def probe(self, query):
        return self.probe_failure

    def query_batch(self, queries):
        return BatchOutcome([self._ids.get(q, []) for q in queries], Counter())

    def get_vulns(self, ids):
        return {i: d for i, d in self._details.items() if i in set(ids)}, Counter()


REQ = {
    "id": "GHSA-x84v",
    "aliases": ["CVE-2018-18074"],
    "affected": [{"package": {"name": "requests", "ecosystem": "PyPI"}}],
}
NET = {"id": "GO-2023-2102", "aliases": ["CVE-2023-39325", "GHSA-4374"]}


def fake():
    return FakeClient(
        {
            Query("PyPI", "requests", "2.19.0"): ["GHSA-x84v"],
            Query("Go", "golang.org/x/net", "0.17.0"): ["GO-2023-2102"],
        },
        {"GHSA-x84v": REQ, "GO-2023-2102": NET},
    )


def test_scan_sbom_reports_skips_and_candidates():
    out = m.scan_sbom(SYFT, fake())
    prov = out["provenance"]
    assert prov["status"] == "complete"
    assert prov["input"] == "syft-json"
    assert prov["image"] == "example/app:1"
    assert prov["skipped_os_installed"] == 1
    assert {c["osv_id"] for c in out["candidates"]} == {"GHSA-x84v", "GO-2023-2102"}
    assert all(c["version_basis"] == "sbom" for c in out["candidates"])


def test_an_unreachable_api_fails_the_image_scan():
    down = fake()
    down.probe_failure = ("unreachable", "URLError")
    out = m.scan_sbom(SYFT, down)
    assert out["provenance"]["status"] == "failed"
    assert out["candidates"] == []
    assert out["provenance"]["skipped_os_installed"] == 1


def test_grype_duplicates_are_marked_by_purl_and_any_id():
    out = m.scan_sbom(SYFT, fake())
    grype = {
        "matches": [
            {  # same package, matched by the CVE alias
                "artifact": {"purl": "pkg:pypi/requests@2.19.0"},
                "vulnerability": {"id": "CVE-2018-18074"},
            },
            {  # same advisory, different package version: not a duplicate
                "artifact": {"purl": "pkg:golang/golang.org/x/net@v0.18.0"},
                "vulnerability": {"id": "GHSA-4374"},
            },
        ]
    }
    counts = m.mark_grype_duplicates(out["candidates"], grype)
    by_id = {c["osv_id"]: c["also_in_grype"] for c in out["candidates"]}
    assert by_id == {"GHSA-x84v": True, "GO-2023-2102": False}
    assert counts == {"also_in_grype": 1, "osv_only": 1}


def test_upstream_ids_count_for_dedupe():
    c = {"osv_id": "RHSA-2024:1", "aliases": [], "upstream": ["CVE-2024-1"]}
    assert m._ids(c) == {"RHSA-2024:1", "CVE-2024-1"}


def test_offline_round_trip(tmp_path):
    packages, _ = m.collect_sbom_packages(SYFT)
    cdx = m.write_cyclonedx(packages, tmp_path / "filtered.cdx.json")
    purls = {c["purl"] for c in json.loads(cdx.read_text())["components"]}
    assert "pkg:npm/%40scope/pkg@1.2.3" in purls
    assert "pkg:golang/stdlib@go1.21.3" in purls
    assert "pkg:golang/golang.org/x/net@v0.17.0" in purls
    assert "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" in purls
    assert {m.parse_purl(p) for p in purls} == set(packages)  # lossless both ways
    scanner = {
        "results": [
            {
                "packages": [
                    {
                        "package": {"name": "Requests", "ecosystem": "PyPI", "version": "2.19.0"},
                        "vulnerabilities": [REQ],
                        "groups": [{"ids": ["GHSA-x84v"], "max_severity": "6.1"}],
                    }
                ]
            }
        ]
    }
    (c,) = m.parse_offline(scanner, packages)
    assert c["sources"] == ["/opt/app-root/lib/requests"]
    assert c["max_severity"] == "6.1"


def test_write_cyclonedx_needs_the_cdx_name(tmp_path):
    with pytest.raises(ValueError, match=r"\.cdx\.json"):
        m.write_cyclonedx({}, tmp_path / "x.json")


def test_grype_matches_on_os_installed_packages_are_listed_with_their_owner():
    grype = {
        "matches": [
            {
                "artifact": {
                    "type": "python",
                    "purl": "pkg:pypi/urllib3@1.26.5",
                    "locations": [{"path": "/usr/lib/python3.9/site-packages/urllib3"}],
                },
                "vulnerability": {"id": "GHSA-38jv", "severity": "High"},
            },
            {  # not OS-installed: a real candidate
                "artifact": {"type": "python", "purl": "pkg:pypi/requests@2.19.0"},
                "vulnerability": {"id": "GHSA-x84v", "severity": "Medium"},
            },
            {  # an RPM itself is grype's own business
                "artifact": {"type": "rpm", "purl": "pkg:rpm/redhat/python3-urllib3@1.26.5"},
                "vulnerability": {"id": "CVE-2023-1", "severity": "Low"},
            },
        ]
    }
    (row,) = m.grype_os_installed_matches(grype, SYFT)
    assert row["package"] == "urllib3"
    assert row["installed_by"] == ["x"]  # the owning artifact's name
    assert row["paths"] == ["/usr/lib/python3.9/site-packages/urllib3"]
