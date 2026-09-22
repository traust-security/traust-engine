"""Tests for traust corpus findings-db -- storage/v1 on SQLite, plus the harness remainder.

findings.db is the contract's store: the artifacts are ingested through
traust_contracts.v1.storage and read through its views. These tests therefore
write CONTRACT-VALID fixtures -- a report the schema rejects is absent from
every contract table, which is exactly the behaviour the projection must
surface rather than hide.
"""

import json
import sqlite3

import pytest
import yaml
from traust_contracts.config import CorpusConfig
from traust_contracts.v1.storage.sql import REVISION as STORAGE_REVISION

from traust_engine.corpus import findings_db as bdb

# insert_decisions() reads the ADR index only from an injected progress_tracker;
# build() defaults it to None, so these projection tests need no external checkout.

CONFIG = """
version: 1
trees:
  findings: {label: example-platform, ownership: owned, business_unit: EXAMPLE_BU}
"""

REPO_URL = "https://github.com/org/repo-x"
FP_ONE = "1" * 64
FP_TWO = "2" * 64


def _report(findings: list[dict], *, disposition_aware: bool) -> dict:
    """A report.schema.json-valid document; the minimum the contract accepts."""
    document = {
        "title": "Security audit",
        "metadata": {"date": "2026-06-01", "scope": "repository", "repository": REPO_URL},
        "executive_summary": {
            "prose": "p" * 50,
            "severity_counts": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "informational": 0,
            },
        },
        "severity_criteria": [
            {"level": level, "definition": "d" * 20}
            for level in ("critical", "high", "medium", "low")
        ],
        "findings": findings,
        "findings_summary": [
            {"severity": level, "count": 0, "finding_ids": []}
            for level in ("critical", "high", "medium", "low")
        ],
        "remediation_roadmap": [{"priority": "1", "action": "a" * 10, "addresses": ["x"]}],
    }
    if disposition_aware:
        # What report_current prefers: the disposition-aware restatement.
        document["disposition_summary"] = {
            "layer_ref": "repo-x-findings-layer.json",
            "generated_at": "2026-07-01T00:00:00Z",
            "by_resolution": {
                "open": len(findings),
                "fix_in_progress": 0,
                "resolved": 0,
                "partially_resolved": 0,
                "risk_accepted": 0,
                "regression_introduced": 0,
            },
            "by_validity": {
                "confirmed": 0,
                "corrected": 0,
                "false_positive": 0,
                "not_verified": len(findings),
            },
        }
    return document


def _finding(fid: str, severity: str, fp: str, validity: str, cwe: str, path: str) -> dict:
    return {
        "id": fid,
        "title": f"Finding {fid}",
        "severity": severity,
        "cwes": [cwe],
        "locations": [{"path": path}],
        "description": "x" * 50,
        "remediation": "r" * 20,
        "fingerprint": fp,
        "disposition": {
            "validity": validity,
            "resolution": "open",
            "last_updated": "2026-07-01T00:00:00Z",
            "events": [],
        },
    }


def _mk_ws(tmp_path):
    """Minimal analysis-results with one repo: an audit, a findings-current
    restatement carrying 2 findings (one open critical, one hardening), a
    ledger with one event and an external ref, and a repo-graph."""
    results = tmp_path / "analysis-results"
    rdir = results / "findings" / "prod-a" / "repo-x"
    rdir.mkdir(parents=True)
    (rdir / "repo-x-security-audit.json").write_text(
        json.dumps(_report([], disposition_aware=False))
    )
    (rdir / "repo-x-security-audit.md").write_text("# audit\n")
    (rdir / "repo-x-findings-current.json").write_text(
        json.dumps(
            _report(
                [
                    _finding("FIND-001", "critical", FP_ONE, "confirmed", "CWE-78", "cmd/run.go"),
                    _finding("FIND-002", "medium", FP_TWO, "hardening", "CWE-250", "deploy/d.yaml"),
                ],
                disposition_aware=True,
            )
        )
    )
    (rdir / "repo-x-findings-layer.json").write_text(
        json.dumps(
            {
                "metadata": {
                    "audit_report": "repo-x-security-audit.json",
                    "repository": REPO_URL,
                    "created": "2026-07-01T00:00:00+00:00",
                    "harness_version": "0.1.0",
                    "external_refs": {
                        "FIND-001": [
                            {
                                "system": "cve",
                                "id": "CVE-2026-66792",
                                "confidence": "confirmed",
                                "matched_on": "title-similarity:0.78",
                                "stamped_at": "2026-08-20T00:00:00Z",
                            }
                        ]
                    },
                },
                "events": [
                    {
                        "event_id": "e" * 64,
                        "finding_ref": "FIND-001",
                        "recorded_at": "2026-07-01T00:00:00+00:00",
                        "occurred_at": "2026-06-01T00:00:00+00:00",
                        "source": {
                            "type": "triage_report",
                            "ref": "t.json",
                            "actor": {"kind": "machine", "identity": "triage/0.9"},
                        },
                        "disposition": {"validity": "confirmed"},
                        "rationale": "confirmed on the exploitability lens",
                        "fingerprint": FP_ONE,
                    }
                ],
                "needs_review": [],
            }
        )
    )
    (results / "graph").mkdir()
    (results / "graph" / "repo-graph.json").write_text(
        json.dumps(
            {
                "nodes": [{"id": "repo:github.com/org/repo-x", "type": "repo", "label": "x"}],
                "edges": [
                    {"rel": "ships", "from": "product:acm", "to": "repo:github.com/org/repo-x"}
                ],
            }
        )
    )
    cfg_path = tmp_path / "corpus-config.yaml"
    cfg_path.write_text(CONFIG)
    cfg = CorpusConfig.model_validate(yaml.safe_load(CONFIG))
    return results, cfg


@pytest.fixture()
def db(tmp_path):
    results, cfg = _mk_ws(tmp_path)
    out = tmp_path / "findings.db"
    counts = bdb.build(results, out, cfg=cfg)
    con = sqlite3.connect(out)
    yield con, counts
    con.close()


def test_counts(db):
    _, counts = db
    assert counts == {
        "repos": 1,
        "provenance": 1,
        "graph_edges": 1,
        "decisions": 0,
        # audit, findings-current, layer -- all contract-valid
        "artifacts_ingested": 3,
        "artifacts_rejected": 0,
    }


def test_repo_row_carries_corpus_identity(db):
    con, _ = db
    row = con.execute(
        "SELECT tree, ownership, business_unit, product, repo_dir, is_md_only FROM repos"
    ).fetchone()
    assert row == ("findings", "owned", "EXAMPLE_BU", "prod-a", "repo-x", 0)


def test_the_store_is_the_contract_at_the_installed_revision(db):
    """findings.db IS storage/v1 on SQLite -- not a second schema beside it."""
    con, _ = db
    row = con.execute("SELECT contract_version, revision FROM traust_storage_meta").fetchone()
    assert row == ("v1", STORAGE_REVISION)
    stamped = con.execute("SELECT value FROM meta WHERE key='storage_revision'").fetchone()[0]
    assert int(stamped) == STORAGE_REVISION


def test_the_legacy_tables_and_views_are_gone(db):
    """Two schemas over one corpus was the divergence; the contract's tables
    replace findings/events/validations/impact and v_open/v_hardening/
    v_distinct_owned outright rather than sitting beside them."""
    con, _ = db
    names = {r[0] for r in con.execute("SELECT name FROM sqlite_master")}
    for gone in ("findings", "events", "validations", "impact", "v_open", "v_hardening"):
        assert gone not in names, gone
    for kept in ("repos", "graph_edges", "provenance", "decisions", "meta"):
        assert kept in names, kept
    for contract in ("report_finding", "layer_event", "subject_ownership", "current_finding"):
        assert contract in names, contract


def test_findings_reach_the_contract_keyed_by_the_repo_key(db):
    """subject_id is repo_key: the join between the harness remainder and the
    contract is by identity, not by convention."""
    con, _ = db
    repo_key = con.execute("SELECT repo_key FROM repos").fetchone()[0]
    subjects = con.execute("SELECT DISTINCT subject_id FROM current_finding").fetchall()
    assert subjects == [(repo_key,)]
    owner = con.execute(
        "SELECT ownership, business_unit, report_kind FROM subject_ownership WHERE subject_id=?",
        (repo_key,),
    ).fetchone()
    assert owner == ("owned", "EXAMPLE_BU", "code-audit")
    assert con.execute("SELECT COUNT(*) FROM report_finding").fetchone()[0] == 2


def test_open_view_excludes_hardening(db):
    con, _ = db
    assert con.execute("SELECT COUNT(*) FROM open_findings").fetchone()[0] == 1
    assert con.execute("SELECT finding_id FROM hardening_findings").fetchone()[0] == "FIND-002"


def test_events_are_the_layer_and_carry_the_actor_and_the_subject(db):
    """The time dimension is layer_event; the layer binding carries the
    subject so an event reaches its repo without parsing the layer_id."""
    con, _ = db
    repo_key = con.execute("SELECT repo_key FROM repos").fetchone()[0]
    row = con.execute(
        "SELECT e.finding_ref, e.actor_identity, b.subject_id "
        "FROM layer_event e JOIN artifact_binding b ON b.binding_id = e.binding_id"
    ).fetchone()
    assert row == ("FIND-001", "triage/0.9", repo_key)


def test_meta_states_authority_and_the_ingest_outcome(db):
    con, _ = db
    meta = dict(con.execute("SELECT key, value FROM meta"))
    assert "census" in meta["authority"]
    assert meta["built_at"]
    assert meta["ingest_rejected"] == "0"
    assert json.loads(meta["ingest_by_family"]) == {"report": 2, "layer": 1}


def test_a_rejected_artifact_is_counted_not_hidden(tmp_path):
    """An artifact the contract refuses is in none of its tables. The build
    says so in meta rather than quietly projecting fewer findings."""
    results, cfg = _mk_ws(tmp_path)
    fc = results / "findings" / "prod-a" / "repo-x" / "repo-x-findings-current.json"
    doc = json.loads(fc.read_text())
    del doc["findings"][0]["description"]  # required by the contract
    fc.write_text(json.dumps(doc))
    out = tmp_path / "rejected.db"
    counts = bdb.build(results, out, cfg=cfg)
    assert counts["artifacts_rejected"] == 1
    con = sqlite3.connect(out)
    try:
        meta = dict(con.execute("SELECT key, value FROM meta"))
        assert meta["ingest_rejected"] == "1"
        assert "required" in json.dumps(json.loads(meta["ingest_reasons"]))
        # The plain audit (zero findings) is now the current report.
        assert con.execute("SELECT COUNT(*) FROM current_finding").fetchone()[0] == 0
        assert con.execute("SELECT COUNT(*) FROM repos").fetchone()[0] == 1
    finally:
        con.close()


def test_distinct_view_dedupes(tmp_path):
    """Two repos carrying the same fingerprint dedupe in distinct_exposure."""
    results, cfg = _mk_ws(tmp_path)
    src = results / "findings" / "prod-a" / "repo-x"
    dup = results / "findings" / "prod-b" / "repo-x"
    dup.mkdir(parents=True)
    for f in src.iterdir():
        (dup / f.name).write_text(f.read_text())
    out = tmp_path / "dup.db"
    bdb.build(results, out, cfg=cfg)
    con = sqlite3.connect(out)
    try:
        assert con.execute("SELECT COUNT(*) FROM open_findings").fetchone()[0] == 2
        row = con.execute("SELECT occurrences FROM distinct_exposure").fetchone()
    finally:
        con.close()
    assert row[0] == 2


def test_open_view_counts_fix_in_progress(db):
    """Open matches the census convention: anything not resolved/risk_accepted."""
    con, _ = db
    before = con.execute("SELECT COUNT(*) FROM open_findings").fetchone()[0]
    con.execute(
        "UPDATE report_finding SET resolution='fix_in_progress' WHERE finding_id='FIND-001'"
    )
    assert con.execute("SELECT COUNT(*) FROM open_findings").fetchone()[0] == before
    con.execute("UPDATE report_finding SET resolution='resolved' WHERE finding_id='FIND-001'")
    assert con.execute("SELECT COUNT(*) FROM open_findings").fetchone()[0] == before - 1


def test_corrected_is_open_exposure(db):
    """'corrected' is a claim about the write-up, not about whether the bug exists."""
    con, _ = db
    before = con.execute("SELECT COUNT(*) FROM open_findings").fetchone()[0]
    con.execute("UPDATE report_finding SET validity='corrected' WHERE finding_id='FIND-001'")
    assert con.execute("SELECT COUNT(*) FROM open_findings").fetchone()[0] == before
    con.execute("UPDATE report_finding SET validity='false_positive' WHERE finding_id='FIND-001'")
    assert con.execute("SELECT COUNT(*) FROM open_findings").fetchone()[0] == before - 1


def test_artifact_refs_keep_the_symlink_not_its_target(tmp_path):
    """The row must cite the artifact AT this repo, not wherever the link points."""
    results, cfg = _mk_ws(tmp_path)
    src = results / "findings" / "prod-a" / "repo-x"
    dst = results / "findings" / "prod-a" / "repo-y"
    dst.mkdir()
    (dst / "repo-y-security-audit.json").write_text(
        (src / "repo-x-security-audit.json").read_text()
    )
    (dst / "repo-y-triage.json").symlink_to(src / "repo-x-triage.json")
    (src / "repo-x-triage.json").write_text("{}")

    out = tmp_path / "linked.db"
    bdb.build(results, out, cfg=cfg)
    con = sqlite3.connect(out)
    try:
        (ref,) = con.execute(
            "SELECT triage_json FROM repos WHERE repo_key LIKE '%repo-y%'"
        ).fetchone()
    finally:
        con.close()
    assert ref == "findings/prod-a/repo-y/repo-y-triage.json", ref


def test_provenance_projects_external_refs(db):
    """metadata.external_refs must reach the DB, or the first-discovery
    metric has to re-walk every layer to answer a basic question."""
    con, _ = db
    row = con.execute(
        "SELECT cve, system, finding_id, confidence, matched_on FROM provenance"
    ).fetchone()
    assert row == ("CVE-2026-66792", "cve", "FIND-001", "confirmed", "title-similarity:0.78")


def test_provenance_is_keyed_for_idempotent_rebuilds(db):
    con, _ = db
    cols = {r[1] for r in con.execute("PRAGMA table_info(provenance)")}
    assert {"cve", "repo_key", "finding_id"} <= cols
    assert con.execute("SELECT COUNT(*) FROM provenance").fetchone()[0] == 1


def test_repo_key_separates_two_report_kinds_for_one_repo(tmp_path):
    """One repo, two kinds of report, two rows -- and the same identity in the
    contract's ownership table, which used to disagree with `repos` on which
    kinds get a suffix."""
    results, cfg = _mk_ws(tmp_path)
    d = results / "findings" / "prod-a" / "repo-x"
    (d / "repo-x-cloud-config-audit.json").write_text(
        json.dumps({"metadata": {"repository": REPO_URL}, "findings": []})
    )
    out = tmp_path / "kinds.db"
    bdb.build(results, out, cfg=cfg)
    con = sqlite3.connect(out)
    try:
        rows = con.execute(
            "SELECT repo_key, report_kind FROM repos WHERE repo_key LIKE '%repo-x%' ORDER BY 1"
        ).fetchall()
        subjects = {
            r[0]: r[1] for r in con.execute("SELECT subject_id, report_kind FROM subject_ownership")
        }
    finally:
        con.close()
    assert len(rows) == len({r[0] for r in rows}), rows
    assert {k for _, k in rows} == {"code-audit", "cloud-config"}, rows
    assert subjects == dict(rows), "repos and subject_ownership agree on identity and kind"


def test_build_is_atomic(tmp_path):
    """A reader mid-build sees the previous complete file, never a half store."""
    results, cfg = _mk_ws(tmp_path)
    out = tmp_path / "atomic.db"
    bdb.build(results, out, cfg=cfg)
    assert out.is_file()
    assert not out.with_name("atomic.db.building").exists()


def test_build_stamps_the_schema_revision(db):
    con, _ = db
    row = con.execute("SELECT value FROM meta WHERE key='schema_revision'").fetchone()
    assert row is not None, "a reader cannot check what the build does not stamp"
    assert int(row[0]) == bdb.SCHEMA_REVISION


def test_reader_refuses_a_database_from_another_revision(db):
    con, _ = db
    assert bdb.check_revision(con) == bdb.SCHEMA_REVISION
    con.execute("UPDATE meta SET value=? WHERE key='schema_revision'", (bdb.SCHEMA_REVISION + 1,))
    with pytest.raises(bdb.StaleFindingsDb, match="Rebuild it"):
        bdb.check_revision(con)


def test_a_database_predating_the_stamp_reads_as_revision_one(db):
    con, _ = db
    con.execute("DELETE FROM meta WHERE key='schema_revision'")
    with pytest.raises(bdb.StaleFindingsDb, match="is revision 1"):
        bdb.check_revision(con)


def test_connect_refuses_and_does_not_leak_the_handle(tmp_path, monkeypatch):
    stale = tmp_path / "stale.db"
    con = sqlite3.connect(stale)
    con.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
    con.execute("INSERT INTO meta VALUES ('schema_revision','1')")
    con.commit()
    con.close()

    opened = []
    real_connect = sqlite3.connect
    monkeypatch.setattr(
        sqlite3, "connect", lambda *a, **k: opened.append(real_connect(*a, **k)) or opened[-1]
    )
    with pytest.raises(bdb.StaleFindingsDb, match="is revision 1"):
        bdb.connect(stale)

    assert opened, "connect() never opened anything"
    with pytest.raises(sqlite3.ProgrammingError):
        opened[-1].execute("SELECT 1")  # closed: refusing must not leak a handle


def test_connect_rejects_a_file_that_is_not_a_findings_database(tmp_path):
    junk = tmp_path / "junk.db"
    junk.write_bytes(b"not a database at all")
    with pytest.raises(bdb.StaleFindingsDb, match="not a findings database"):
        bdb.connect(junk)
