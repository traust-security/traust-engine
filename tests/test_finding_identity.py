"""Tests for traust_engine._util.finding_identity — cross-scan finding identity."""

import json
from pathlib import Path

import pytest
from traust_contracts.v1.models.layer import LayerActor
from traust_ledger.client import LedgerClient

from traust_engine._util import finding_identity as fi
from traust_engine.ledger import LedgerService


class _Verifier:
    """Ledger >=0.8 verifies the actor before sign/patch_metadata; the session's
    alg=none token has no verifier, so these tests supply one."""

    def verify(self, token: str) -> LayerActor:
        return LayerActor(
            kind="human",
            identity="user:test",
            identity_verified=True,
            identity_provider="oidc",
        )


def _ledger(data_dir: Path) -> LedgerService:
    return LedgerService(LedgerClient(data_dir=str(data_dir), verifier=_Verifier()))


H1, H2 = "1" * 64, "2" * 64  # claim hashes are sha256 hex in the layer schema


def _layer(**metadata) -> str:
    """A layer with the initialized shell the ledger requires before it will sign."""
    shell = {
        "audit_report": "old.json",
        "repository": "https://github.com/org/repo",
        "created": "2026-08-19T00:00:00+00:00",
        "harness_version": "0.298.0",
    }
    return json.dumps({"metadata": shell | metadata, "events": [], "needs_review": []})


def _finding(fid, path, cwe, title, lines="10-20"):
    return {
        "id": fid,
        "title": title,
        "severity": "high",
        "cwes": [cwe],
        "locations": [{"path": path, "lines": lines}],
        "description": "x" * 60,
        "remediation": "fix it properly",
    }


def _report(repo, findings):
    return {"metadata": {"repository": repo}, "findings": findings}


def test_fingerprint_stable_across_scan_artifacts():
    a = _finding(
        "REPO-abc1234-001",
        "pkg/server/auth.go",
        "CWE-287",
        "Missing auth on sync endpoint",
        lines="10-20",
    )
    b = _finding(
        "REPO-def5678-003",
        "./pkg/server/auth.go",
        "CWE-287",
        "Sync endpoint lacks authentication",
        lines="14-25",
    )
    # different scan id, reworded title, shifted lines, ./ prefix — same identity
    assert fi.fingerprint(a, "https://github.com/org/repo") == fi.fingerprint(
        b, "git@github.com:org/repo.git"
    )


def test_fingerprint_distinguishes_cwe_and_location():
    base = _finding("R-abc1234-001", "a.go", "CWE-287", "t")
    other_cwe = _finding("R-abc1234-002", "a.go", "CWE-89", "t")
    other_path = _finding("R-abc1234-003", "b.go", "CWE-287", "t")
    r = "https://github.com/org/repo"
    assert fi.fingerprint(base, r) != fi.fingerprint(other_cwe, r)
    assert fi.fingerprint(base, r) != fi.fingerprint(other_path, r)


def test_annotate_report_sets_fingerprint_and_profile():
    rep = _report(
        "https://github.com/org/repo",
        [_finding("R-abc1234-001", "a.go", "CWE-287", "t")],
    )
    n = fi.annotate_report(rep)
    assert n == 2  # fingerprint + inferred audit_profile
    assert rep["metadata"]["audit_profile"] == "code"
    assert len(rep["findings"][0]["fingerprint"]) == 64
    assert fi.annotate_report(rep) == 0  # idempotent

    rpm = _report(
        "https://gitlab.example.com/dist/example/rpms/x",
        [
            dict(
                _finding("RPM_X-abc1234-001", "x.spec", "CWE-829", "unpinned source"),
                category="RPM03: Sources",
            )
        ],
    )
    fi.annotate_report(rpm)
    assert rpm["metadata"]["audit_profile"] == "rpm"


def test_match_ladder_tiers():
    old = _report(
        "https://github.com/org/repo",
        [
            _finding("R-aaa1111-001", "auth.go", "CWE-287", "No auth on sync"),
            _finding("R-aaa1111-002", "db.go", "CWE-89", "SQL injection in query"),
            _finding("R-aaa1111-003", "gone.go", "CWE-798", "Hardcoded key"),
        ],
    )
    new = _report(
        "https://github.com/org/repo",
        [
            # tier 1: same path+cwe -> same fingerprint
            _finding(
                "R-bbb2222-001", "auth.go", "CWE-287", "Sync endpoint unauthenticated"
            ),
            # tier 2 candidate: same path, same cwe would be tier 1 — so make a
            # re-classified CWE at same path with near-identical title -> tier 3
            _finding(
                "R-bbb2222-002", "db.go", "CWE-943", "SQL injection in query builder"
            ),
            # brand new finding
            _finding("R-bbb2222-004", "new.go", "CWE-352", "CSRF"),
        ],
    )
    fi.annotate_report(old)
    fi.annotate_report(new)
    r = fi.match_findings(old, new)
    assert r["mapped"]["R-aaa1111-001"]["matched_by"] == "fingerprint"
    assert r["mapped"]["R-aaa1111-002"]["matched_by"] == "path_set"
    assert r["unmatched_old"] == ["R-aaa1111-003"]
    assert r["unmatched_new"] == ["R-bbb2222-004"]


def test_rebaseline_writes_aliases_and_reviews(tmp_path):
    old = _report(
        "https://github.com/org/repo",
        [
            _finding("R-aaa1111-001", "auth.go", "CWE-287", "No auth"),
            _finding("R-aaa1111-002", "gone.go", "CWE-798", "Key"),
        ],
    )
    new = _report(
        "https://github.com/org/repo",
        [_finding("R-bbb2222-001", "auth.go", "CWE-287", "Unauth")],
    )
    for rep in (old, new):
        fi.annotate_report(rep)
    po, pn, pl = tmp_path / "old.json", tmp_path / "new.json", tmp_path / "layer.json"
    po.write_text(json.dumps(old))
    pn.write_text(json.dumps(new))
    pl.write_text(_layer())

    r = fi.rebaseline(po, pn, pl, ledger_service=_ledger(tmp_path))
    layer = json.loads(pl.read_text())
    al = layer["metadata"]["finding_aliases"]["R-aaa1111-001"]
    assert al["new_id"] == "R-bbb2222-001" and al["confirmed"] is True
    reasons = [i["queue_reason"] for i in layer["needs_review"]]
    assert reasons == ["rebaseline_unmatched"]
    assert r["unmatched_old"] == ["R-aaa1111-002"]


def test_rebaseline_migrates_superseded_claim_pins(tmp_path):
    # A rebaselined layer whose claim_hashes still pin old ids absent from
    # the new report would fail every future build_cumulative run. Covered
    # ids (mapped, or unmatched-with-queued-review) migrate; the new
    # report's own ids keep their pins untouched.
    old = _report(
        "https://github.com/org/repo",
        [
            _finding("FIND-001", "auth.go", "CWE-287", "No auth"),
            _finding("FIND-002", "gone.go", "CWE-798", "Key"),
        ],
    )
    new = _report(
        "https://github.com/org/repo",
        [_finding("R-bbb2222-001", "auth.go", "CWE-287", "Unauth")],
    )
    new["metadata"]["commit"] = "bbb2222" + "0" * 33
    for rep in (old, new):
        fi.annotate_report(rep)
    po = tmp_path / "repo-security-audit.json"
    pn = tmp_path / "new.json"
    pl = tmp_path / "layer.json"
    po.write_text(json.dumps(old))
    pn.write_text(json.dumps(new))
    pl.write_text(
        _layer(
            audit_commit="aaa1111" + "0" * 33,
            claim_hashes={"FIND-001": H1, "FIND-002": H2},
        )
    )

    r = fi.rebaseline(po, pn, pl, ledger_service=_ledger(tmp_path))
    layer = json.loads(pl.read_text())
    assert sorted(r["migrated_claims"]) == ["FIND-001", "FIND-002"]
    assert layer["metadata"]["claim_hashes"] == {}
    assert layer["metadata"]["audit_commit"] == "bbb2222" + "0" * 33


def test_rebaseline_batch_mode_keeps_unmatched_pins(tmp_path):
    # --no-review-queue leaves unmatched old ids with no queued decision;
    # their claim pins must stay (the tamper guard would otherwise lose
    # its record without any parked disposition trail).
    old = _report(
        "https://github.com/org/repo",
        [_finding("FIND-002", "gone.go", "CWE-798", "Key")],
    )
    new = _report(
        "https://github.com/org/repo",
        [_finding("R-bbb2222-001", "auth.go", "CWE-287", "Unauth")],
    )
    for rep in (old, new):
        fi.annotate_report(rep)
    po = tmp_path / "repo-security-audit.json"
    pn = tmp_path / "new.json"
    pl = tmp_path / "layer.json"
    po.write_text(json.dumps(old))
    pn.write_text(json.dumps(new))
    pl.write_text(_layer(claim_hashes={"FIND-002": H2}))

    r = fi.rebaseline(po, pn, pl, queue_reviews=False, ledger_service=_ledger(tmp_path))
    layer = json.loads(pl.read_text())
    assert r["migrated_claims"] == []
    assert layer["metadata"]["claim_hashes"] == {"FIND-002": H2}


# --- P9 / P9b: rebaseline owes a stamp, and must not write outside the tree ---


def _rebaseline_fixture(tmp_path):
    old = _report(
        "https://github.com/org/repo",
        [_finding("R-aaa1111-001", "auth.go", "CWE-287", "No auth")],
    )
    new = _report(
        "https://github.com/org/repo",
        [_finding("R-bbb2222-001", "auth.go", "CWE-287", "Unauth")],
    )
    for rep in (old, new):
        fi.annotate_report(rep)
    po, pn, pl = tmp_path / "old.json", tmp_path / "new.json", tmp_path / "layer.json"
    po.write_text(json.dumps(old))
    pn.write_text(json.dumps(new))
    pl.write_text(_layer())
    return po, pn, pl


def test_rebaseline_stamps_the_merkle_root_it_invalidates(tmp_path):
    """P9: it mutates the layer, so it owes the stamp every other writer does.

    Without it the declared root goes stale, which verify_merkle_integrity
    reports as an ERROR since traust-ledger 0.1.3.
    """
    from traust_engine.ledger import verify_merkle_integrity

    po, pn, pl = _rebaseline_fixture(tmp_path)

    fi.rebaseline(po, pn, pl, ledger_service=_ledger(tmp_path))

    layer = json.loads(pl.read_text())
    assert layer["metadata"].get("merkle_root"), "rebaseline must stamp before writing"
    errors = [f for f in verify_merkle_integrity(layer) if f.severity.name == "ERROR"]
    assert errors == [], [f.message for f in errors]


def test_rebaseline_refuses_a_layer_outside_the_tree(tmp_path):
    """P9b: a bare path let an operator typo or crafted argument write anywhere."""
    from traust_engine._util.layer_paths import LayerPathOutsideRoot

    po, pn, _ = _rebaseline_fixture(tmp_path)
    outside = tmp_path.parent / "escaped-layer.json"
    outside.write_text(_layer())

    try:
        fi.rebaseline(
            po, pn, outside, findings_root=tmp_path, ledger_service=_ledger(tmp_path)
        )
    except LayerPathOutsideRoot as e:
        assert "outside the allowed root" in str(e)
    else:
        raise AssertionError("rebaseline wrote a layer outside the findings root")


def test_rebaseline_allows_a_layer_inside_the_declared_root(tmp_path):
    po, pn, pl = _rebaseline_fixture(tmp_path)

    fi.rebaseline(po, pn, pl, findings_root=tmp_path, ledger_service=_ledger(tmp_path))

    assert json.loads(pl.read_text())["metadata"]["finding_aliases"]


def test_confine_layer_path_catches_a_symlink_out_of_the_tree(tmp_path):
    """Realpath containment on both sides — a symlink is caught, not followed."""
    from traust_engine._util.layer_paths import LayerPathOutsideRoot, confine_layer_path

    root = tmp_path / "findings"
    root.mkdir()
    outside = tmp_path / "elsewhere.json"
    outside.write_text("{}")
    link = root / "layer.json"
    link.symlink_to(outside)

    try:
        confine_layer_path(link, [root])
    except LayerPathOutsideRoot:
        pass
    else:
        raise AssertionError("a symlink escaping the root was accepted")

    real = root / "real-layer.json"
    real.write_text("{}")
    assert confine_layer_path(real, [root]) == real.resolve()


def test_annotate_report_stamps_the_algorithm_version():
    """A bare hash cannot say which recipe minted it.

    The ledger's event writer has always recorded fingerprint_algo; the
    report writer did not, so 25,515 corpus findings carry a hash and
    nothing else. Answering "v2 or v3?" then means brute-forcing every
    known recipe, which works only while there are two.
    """
    from traust_engine.ledger import ALGO_VERSION

    rep = {
        "metadata": {"repository": "https://example.test/repo"},
        "findings": [_finding("F-1", "a/b.go", "CWE-79", "one")],
    }
    fi.annotate_report(rep)
    finding = rep["findings"][0]
    assert finding["fingerprint_algo"] == ALGO_VERSION
    assert len(finding["fingerprint"]) == 64


def test_a_stale_algo_stamp_is_refreshed_even_when_the_hash_matches():
    """The hash and the version must not be able to disagree.

    Checking only the hash would leave a v2 marker sitting on a value the
    current recipe produced -- worse than no marker, because it reads as
    authoritative.
    """
    from traust_engine.ledger import ALGO_VERSION

    rep = {
        "metadata": {"repository": "https://example.test/repo"},
        "findings": [_finding("F-1", "a/b.go", "CWE-79", "one")],
    }
    fi.annotate_report(rep)
    rep["findings"][0]["fingerprint_algo"] = "v1"  # hash still correct
    assert fi.annotate_report(rep) == 1
    assert rep["findings"][0]["fingerprint_algo"] == ALGO_VERSION


def test_annotated_report_still_validates_against_the_contract():
    """additionalProperties is false on $defs/finding, so the writer and the
    schema have to move together."""
    import jsonschema
    from traust_contracts.paths import schema_dir

    schema = json.loads((schema_dir() / "report.schema.json").read_text())
    rep = {
        "metadata": {"repository": "https://example.test/repo"},
        "findings": [
            {
                "id": "REPO-abcdef0-001",
                "title": "A sufficiently descriptive finding title",
                "severity": "high",
                "description": "d" * 50,
                "cwes": ["CWE-79"],
                "locations": [{"path": "a/b.go"}],
                "remediation": "r" * 20,
            }
        ],
    }
    fi.annotate_report(rep)
    # Carry $defs so the finding's internal $refs resolve.
    jsonschema.Draft202012Validator(
        {"$ref": "#/$defs/finding", "$defs": schema["$defs"]}
    ).validate(rep["findings"][0])


def _stamped_report(fingerprint_value: str) -> dict:
    rep = {
        "metadata": {"repository": "https://example.test/repo"},
        "findings": [_finding("F-1", "a/b.go", "CWE-79", "one")],
    }
    rep["findings"][0]["fingerprint"] = fingerprint_value
    return rep


def test_identity_moves_reports_only_real_moves():
    """Stamping an UNSTAMPED finding is not a move -- nothing referenced it."""
    fresh = {
        "metadata": {"repository": "https://example.test/repo"},
        "findings": [_finding("F-1", "a/b.go", "CWE-79", "one")],
    }
    assert fi.identity_moves(fresh) == []

    fi.annotate_report(fresh)
    assert fi.identity_moves(fresh) == [], "idempotent re-stamp is not a move"

    moved = _stamped_report("f" * 64)
    assert [m[0] for m in fi.identity_moves(moved)] == ["F-1"]


def test_annotate_refuses_to_move_an_existing_identity_when_asked():
    """Ledger events are keyed on the fingerprint, so a move orphans them."""
    rep = _stamped_report("f" * 64)
    with pytest.raises(fi.IdentityMoved, match="orphans that history"):
        fi.annotate_report(rep, allow_identity_move=False)
    assert rep["findings"][0]["fingerprint"] == "f" * 64, (
        "must not mutate before refusing"
    )

    assert fi.annotate_report(rep, allow_identity_move=True) >= 1
    assert rep["findings"][0]["fingerprint"] != "f" * 64


def test_backfill_refuses_the_whole_run_and_writes_nothing(tmp_path, capsys):
    """Whole-run refusal: a half-stamped corpus is worse than an untouched one."""
    safe = tmp_path / "a-security-audit.json"
    risky = tmp_path / "b-security-audit.json"
    safe.write_text(
        json.dumps(
            {
                "metadata": {"repository": "https://example.test/repo"},
                "findings": [_finding("F-1", "a/b.go", "CWE-79", "one")],
            }
        )
    )
    risky.write_text(json.dumps(_stamped_report("f" * 64)))
    before = risky.read_text()

    safe_before = safe.read_text()
    assert fi.run_backfill(tmp_path) == 1
    err = capsys.readouterr().err
    assert "REFUSED" in err and "NOTHING" in err
    assert risky.read_text() == before, "the risky report must be untouched"
    # The one that matters: an earlier version skipped the risky file and
    # wrote every OTHER report, leaving the corpus half re-stamped. This
    # test passed anyway because it only checked the risky file.
    assert safe.read_text() == safe_before, "a refused run must write NOTHING"

    assert fi.run_backfill(tmp_path, allow_identity_move=True) == 0
    assert json.loads(risky.read_text())["findings"][0]["fingerprint"] != "f" * 64


def test_backfill_still_stamps_when_nothing_would_move(tmp_path):
    report = tmp_path / "a-security-audit.json"
    report.write_text(
        json.dumps(
            {
                "metadata": {"repository": "https://example.test/repo"},
                "findings": [_finding("F-1", "a/b.go", "CWE-79", "one")],
            }
        )
    )
    assert fi.run_backfill(tmp_path) == 0
    stamped = json.loads(report.read_text())["findings"][0]
    assert len(stamped["fingerprint"]) == 64 and stamped["fingerprint_algo"]


def test_run_fingerprint_only_guards_the_writing_path(tmp_path, capsys):
    """Read-only inspection must still show what WOULD change."""
    report = tmp_path / "x-security-audit.json"
    report.write_text(json.dumps(_stamped_report("f" * 64)))
    before = report.read_text()

    assert fi.run_fingerprint(report) == 0, "preview must not refuse"
    assert report.read_text() == before

    assert fi.run_fingerprint(report, write=True) == 1
    assert "orphans that history" in capsys.readouterr().err
    assert report.read_text() == before, "refused write must leave the file alone"


def _report_with_stamp(stamp: str, *, repo: str = "https://example.test/repo") -> dict:
    rep = {
        "metadata": {"repository": repo},
        "findings": [_finding("F-1", "a/b.go", "CWE-79", "one")],
    }
    rep["findings"][0]["fingerprint"] = stamp
    return rep


def test_repo_candidates_offers_both_the_raw_and_repaired_spelling():
    """72 corpus stamps were minted from '<https://...>' before
    normalize_repository stripped the brackets, so the raw value is the only
    thing that reproduces them."""
    wrapped = fi.repo_candidates({"metadata": {"repository": "<https://x/y>"}})
    assert wrapped == ["https://x/y", "<https://x/y>"]
    # No repair needed: one candidate, not a duplicate pair.
    assert fi.repo_candidates({"metadata": {"repository": "https://x/y"}}) == [
        "https://x/y"
    ]


def test_attribute_pass_is_read_only_by_default(tmp_path, capsys):
    from traust_engine.ledger import ALGO_VERSION, fingerprint

    rep = _report_with_stamp("placeholder")
    rep["findings"][0]["fingerprint"] = fingerprint(
        rep["findings"][0], rep["metadata"]["repository"]
    )
    report = tmp_path / "a-security-audit.json"
    report.write_text(json.dumps(rep))
    before = report.read_text()

    assert fi.run_attribute(tmp_path) == 0
    out = capsys.readouterr().out
    assert ALGO_VERSION in out and "dry run" in out
    assert report.read_text() == before, "a dry run must not write"

    assert fi.run_attribute(tmp_path, write=True) == 0
    assert (
        json.loads(report.read_text())["findings"][0]["fingerprint_algo"]
        == ALGO_VERSION
    )


def test_attribute_never_touches_the_hash(tmp_path):
    """It records what is already true; it must not change any identity."""
    from traust_engine.ledger import fingerprint

    rep = _report_with_stamp("placeholder")
    stamp = fingerprint(rep["findings"][0], rep["metadata"]["repository"])
    rep["findings"][0]["fingerprint"] = stamp
    report = tmp_path / "a-security-audit.json"
    report.write_text(json.dumps(rep))

    fi.run_attribute(tmp_path, write=True)
    assert json.loads(report.read_text())["findings"][0]["fingerprint"] == stamp


def test_unattributable_stamps_are_reported_and_left_unmarked(tmp_path, capsys):
    """A placeholder version would be a false certainty in the one field
    whose entire purpose is certainty."""
    report = tmp_path / "a-security-audit.json"
    report.write_text(json.dumps(_report_with_stamp("f" * 64)))

    assert fi.run_attribute(tmp_path, write=True) == 0
    captured = capsys.readouterr()
    assert "match no known recipe" in captured.err
    assert "F-1" in captured.err
    assert "fingerprint_algo" not in report.read_text()


def test_already_marked_stamps_are_not_recounted(tmp_path, capsys):
    from traust_engine.ledger import ALGO_VERSION, fingerprint

    rep = _report_with_stamp("placeholder")
    rep["findings"][0]["fingerprint"] = fingerprint(
        rep["findings"][0], rep["metadata"]["repository"]
    )
    rep["findings"][0]["fingerprint_algo"] = ALGO_VERSION
    (tmp_path / "a-security-audit.json").write_text(json.dumps(rep))

    fi.run_attribute(tmp_path)
    assert "1 already marked" in capsys.readouterr().out


def test_stamp_missing_fills_gaps_and_never_moves_an_existing_stamp():
    """annotate_report recomputes everything; this fills only the holes."""
    from traust_engine.ledger import ALGO_VERSION

    rep = {
        "metadata": {"repository": "https://example.test/repo"},
        "findings": [
            _finding("F-1", "a/b.go", "CWE-79", "one"),
            _finding("F-2", "c/d.go", "CWE-200", "two"),
        ],
    }
    rep["findings"][0]["fingerprint"] = "f" * 64  # a stale v-whatever stamp
    rep["findings"][0]["fingerprint_algo"] = "v1"

    assert fi.stamp_missing(rep) == 1, "only the unstamped one"
    assert rep["findings"][0]["fingerprint"] == "f" * 64, "existing stamp untouched"
    assert rep["findings"][0]["fingerprint_algo"] == "v1", "existing marker untouched"
    assert len(rep["findings"][1]["fingerprint"]) == 64
    assert rep["findings"][1]["fingerprint_algo"] == ALGO_VERSION
    assert fi.stamp_missing(rep) == 0, "idempotent"


def test_stamp_missing_pass_is_read_only_by_default(tmp_path, capsys):
    rep = {
        "metadata": {"repository": "https://example.test/repo"},
        "findings": [_finding("F-1", "a/b.go", "CWE-79", "one")],
    }
    report = tmp_path / "a-findings-current.json"
    report.write_text(json.dumps(rep))
    before = report.read_text()

    assert fi.run_stamp_missing(tmp_path) == 0
    assert "dry run" in capsys.readouterr().out
    assert report.read_text() == before

    assert fi.run_stamp_missing(tmp_path, write=True) == 0
    assert json.loads(report.read_text())["findings"][0]["fingerprint"]


def test_stamp_missing_leaves_a_fully_stamped_tree_alone(tmp_path):
    rep = {
        "metadata": {"repository": "https://example.test/repo"},
        "findings": [_finding("F-1", "a/b.go", "CWE-79", "one")],
    }
    rep["findings"][0]["fingerprint"] = "f" * 64
    path = tmp_path / "a-findings-current.json"
    path.write_text(json.dumps(rep))
    before = path.read_text()
    assert fi.run_stamp_missing(tmp_path, write=True) == 0
    assert path.read_text() == before
