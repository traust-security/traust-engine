"""OSV affected spans and the fix for one installed version."""

from traust_engine.osv.ranges import (
    Span,
    containing_span,
    fixed_for,
    range_evidence,
    spans,
    version_key,
)


def _vuln(*ranges, name="example-lib", ecosystem="Go", references=None):
    return {
        "id": "GHSA-test",
        "affected": [{"package": {"name": name, "ecosystem": ecosystem}, "ranges": list(ranges)}],
        "references": references or [],
    }


def _semver(*events):
    return {"type": "SEMVER", "events": list(events)}


TWO_SPANS = _vuln(
    _semver({"introduced": "0"}, {"fixed": "1.5.0"}, {"introduced": "2.0.0"}, {"fixed": "2.3.0"})
)


def test_spans_reads_every_introduced_fixed_pair():
    assert spans(TWO_SPANS, "example-lib", "Go") == [
        Span("0", fixed="1.5.0"),
        Span("2.0.0", fixed="2.3.0"),
    ]


def test_fix_is_the_one_for_the_installed_span():
    assert fixed_for(TWO_SPANS, "example-lib", "Go", "1.2.0") == "1.5.0"
    assert fixed_for(TWO_SPANS, "example-lib", "Go", "2.1.0") == "2.3.0"


def test_go_v_prefix_is_ignored():
    assert fixed_for(TWO_SPANS, "example-lib", "Go", "v2.1.0") == "2.3.0"


def test_trailing_zeros_compare_equal():
    vuln = _vuln(_semver({"introduced": "1.2"}, {"fixed": "1.5"}), ecosystem="PyPI")
    assert containing_span(vuln, "example-lib", "PyPI", "1.2.0") == Span("1.2", fixed="1.5")


def test_last_affected_only_has_no_fix():
    vuln = _vuln(_semver({"introduced": "1.0.0"}, {"last_affected": "1.4.0"}))
    assert fixed_for(vuln, "example-lib", "Go", "1.2.0") is None
    assert containing_span(vuln, "example-lib", "Go", "1.2.0") == Span(
        "1.0.0", last_affected="1.4.0"
    )


def test_last_affected_span_takes_a_later_fix():
    vuln = _vuln(
        _semver(
            {"introduced": "1.0.0"},
            {"last_affected": "1.4.0"},
            {"introduced": "2.0.0"},
            {"fixed": "2.3.0"},
        )
    )
    assert fixed_for(vuln, "example-lib", "Go", "1.2.0") == "2.3.0"


def test_a_fix_inside_another_span_is_skipped():
    # 1.5.0 fixes the first range but the second range marks it affected again.
    vuln = _vuln(
        _semver({"introduced": "0"}, {"fixed": "1.5.0"}),
        _semver({"introduced": "1.4.0"}, {"fixed": "1.6.0"}),
    )
    assert fixed_for(vuln, "example-lib", "Go", "1.4.5") == "1.6.0"


def test_overlapping_entries_take_the_covering_span_fix():
    # One entry is open-ended from 3.6.5; another fixes the 3.7 line in 3.7.14.
    vuln = {
        "affected": [
            {
                "package": {"name": "example-lib", "ecosystem": "Go"},
                "ranges": [_semver({"introduced": "3.6.5"})],
            },
            {
                "package": {"name": "example-lib", "ecosystem": "Go"},
                "ranges": [_semver({"introduced": "3.7.0"}, {"fixed": "3.7.14"})],
            },
        ]
    }
    assert fixed_for(vuln, "example-lib", "Go", "3.7.11") == "3.7.14"
    # 3.6.6 sits only in the open-ended span, and the record still marks 3.7.14
    # affected through that span, so the record names no fix for it.
    assert fixed_for(vuln, "example-lib", "Go", "3.6.6") is None


def test_open_ended_span_above_every_fix_has_no_fix():
    vuln = _vuln(_semver({"introduced": "0"}, {"fixed": "1.5.0"}, {"introduced": "3.0.0"}))
    assert fixed_for(vuln, "example-lib", "Go", "3.1.0") is None
    assert containing_span(vuln, "example-lib", "Go", "3.1.0") == Span("3.0.0")


def test_fixed_without_introduced_starts_at_zero():
    vuln = _vuln({"events": [{"fixed": "9.9.9"}]}, ecosystem="npm")
    assert spans(vuln, "example-lib", "npm") == [Span("0", fixed="9.9.9")]
    assert fixed_for(vuln, "example-lib", "npm", "1.0.0") == "9.9.9"


def test_unorderable_installed_version_keeps_the_first_fix():
    assert fixed_for(TWO_SPANS, "example-lib", "Go", "latest") == "1.5.0"
    assert fixed_for(TWO_SPANS, "example-lib", "Go", None) == "1.5.0"


def test_git_ranges_are_not_version_spans():
    vuln = _vuln(
        {
            "type": "GIT",
            "repo": "https://example.com/lib",
            "events": [{"introduced": "0"}, {"fixed": "abc123"}],
        },
        _semver({"introduced": "0"}, {"fixed": "1.5.0"}),
    )
    assert spans(vuln, "example-lib", "Go") == [Span("0", fixed="1.5.0")]


def test_other_package_and_ecosystem_are_ignored():
    assert spans(TWO_SPANS, "other-lib", "Go") == []
    assert spans(TWO_SPANS, "example-lib", "npm") == []


def test_ignore_case_matches_names_and_unnamed_entries():
    vuln = _vuln(_semver({"introduced": "0"}, {"fixed": "1.5.0"}), name="Example-Lib")
    assert fixed_for(vuln, "example-lib", None, "1.0.0", ignore_case=True) == "1.5.0"
    assert fixed_for(vuln, "example-lib", None, "1.0.0") is None
    unnamed = {"affected": [{"ranges": [_semver({"introduced": "0"}, {"fixed": "2.0.0"})]}]}
    assert fixed_for(unnamed, "example-lib", None, "1.0.0", ignore_case=True) == "2.0.0"


def test_pypi_ordering_uses_release_numbers():
    vuln = _vuln(
        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.20"}]},
        {"type": "ECOSYSTEM", "events": [{"introduced": "2.25.0"}, {"fixed": "2.32.0"}]},
        ecosystem="PyPI",
    )
    assert fixed_for(vuln, "example-lib", "PyPI", "2.19.1") == "2.20"
    assert fixed_for(vuln, "example-lib", "PyPI", "2.31.0") == "2.32.0"


def test_range_evidence_keeps_ranges_and_fix_references():
    vuln = _vuln(
        {"type": "GIT", "repo": "https://example.com/lib", "events": [{"fixed": "abc123"}]},
        _semver({"introduced": "0"}, {"fixed": "1.5.0"}),
        references=[
            {"type": "FIX", "url": "https://example.com/lib/commit/abc123"},
            {"type": "ADVISORY", "url": "https://example.com/advisory"},
        ],
    )
    assert range_evidence(vuln, "example-lib", "Go") == {
        "osv_ranges": [
            {"type": "GIT", "repo": "https://example.com/lib", "events": [{"fixed": "abc123"}]},
            {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.5.0"}]},
        ],
        "fix_references": ["https://example.com/lib/commit/abc123"],
    }


def test_version_key_orders_within_an_ecosystem():
    assert version_key("v1.10.0", "Go") > version_key("1.9.3", "Go")
    assert version_key("1.2.0", "PyPI") == version_key("1.2", "PyPI")
    assert version_key("latest", "Go") is None


def test_nuget_names_match_case_insensitively():
    from traust_engine.osv.ranges import spans

    rec = {
        "affected": [
            {
                "package": {"name": "Newtonsoft.Json", "ecosystem": "NuGet"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "13.0.1"}]}
                ],
            }
        ]
    }
    assert spans(rec, "newtonsoft.json", "NuGet") == spans(rec, "Newtonsoft.Json", "NuGet") != []
    assert spans(rec, "newtonsoft.json", "npm") == []
