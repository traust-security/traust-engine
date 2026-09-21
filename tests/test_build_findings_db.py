"""Tests for traust corpus findings-db — the C9 SQLite projection."""

import json
import sqlite3

import pytest
import yaml
from traust_contracts.config import CorpusConfig

from traust_engine.corpus import findings_db as bdb

# insert_decisions() reads the ADR index only from an injected progress_tracker;
# build() defaults it to None, so these projection tests need no external checkout.

CONFIG = """
version: 1
trees:
  findings: {label: example-platform, ownership: owned, business_unit: EXAMPLE_BU}
"""


def _mk_ws(tmp_path):
    """Minimal analysis-results with one repo: 2 findings (one open
    critical, one hardening), a ledger event, a validation report, and
    a repo-graph."""
    results = tmp_path / "analysis-results"
    rdir = results / "findings" / "prod-a" / "repo-x"
    rdir.mkdir(parents=True)
    (rdir / "repo-x-security-audit.json").write_text(
        json.dumps({"metadata": {"repository": "https://github.com/org/repo-x"}, "findings": []})
    )
    (rdir / "repo-x-security-audit.md").write_text("# audit\n")
    (rdir / "repo-x-findings-current.json").write_text(
        json.dumps(
            {
                "metadata": {"repository": "https://github.com/org/repo-x"},
                "findings": [
                    {
                        "id": "FIND-001",
                        "title": "cmd injection",
                        "severity": "critical",
                        "cwes": ["CWE-78"],
                        "cvss": {"score": 9.1, "vector": "AV:N/AC:L"},
                        "locations": [{"path": "cmd/run.go", "lines": "10"}],
                        "disposition": {"validity": "confirmed", "resolution": "open"},
                    },
                    {
                        "id": "FIND-002",
                        "title": "missing seccomp",
                        "severity": "medium",
                        "cwes": ["CWE-250"],
                        "locations": [{"path": "deploy/dep.yaml"}],
                        "disposition": {"validity": "hardening", "resolution": "open"},
                    },
                ],
            }
        )
    )
    (rdir / "repo-x-findings-layer.json").write_text(
        json.dumps(
            {
                "metadata": {
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
                    }
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
                    }
                ],
                "needs_review": [],
            }
        )
    )
    vdir = results / "validations" / "repo-x"
    vdir.mkdir(parents=True)
    (vdir / "repo-x-validation.json").write_text(
        json.dumps(
            {
                "source_reports": [
                    {
                        "kind": "audit",
                        "path": "/somewhere/else/analysis-results/findings/"
                        "prod-a/repo-x/repo-x-security-audit.json",
                    }
                ],
                "validated_findings": [
                    {"source_id": "FIND-001", "verdict": "confirmed", "technique": "exec"}
                ],
            }
        )
    )
    (results / "graph").mkdir()
    (results / "graph" / "repo-graph.json").write_text(
        json.dumps(
            {
                "nodes": [
                    {"id": "repo:github.com/org/repo-x", "type": "repo", "label": "org/repo-x"}
                ],
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
        "findings": 2,
        "events": 1,
        "provenance": 1,
        "validations": 1,
        "graph_edges": 1,
        "decisions": 0,
        "impact_rows": 0,
    }


def test_repo_row_carries_corpus_identity(db):
    con, _ = db
    row = con.execute(
        "SELECT tree, ownership, business_unit, product, repo_dir, is_md_only FROM repos"
    ).fetchone()
    assert row == ("findings", "owned", "EXAMPLE_BU", "prod-a", "repo-x", 0)


def test_fingerprint_computed_when_absent(db):
    con, _ = db
    fp = con.execute("SELECT fingerprint FROM findings WHERE finding_id='FIND-001'").fetchone()[0]
    assert fp and len(fp) == 64


def test_open_view_excludes_hardening(db):
    con, _ = db
    assert con.execute("SELECT COUNT(*) FROM v_open").fetchone()[0] == 1
    assert con.execute("SELECT finding_id FROM v_hardening").fetchone()[0] == "FIND-002"


def test_events_joined(db):
    con, _ = db
    row = con.execute("SELECT finding_id, actor_identity FROM events").fetchone()
    assert row == ("FIND-001", "triage/0.9")


def test_validation_resolves_foreign_workspace_path(db):
    """source_reports paths from another machine still join by the
    analysis-results/-relative suffix."""
    con, _ = db
    row = con.execute("SELECT repo_key, verdict FROM validations").fetchone()
    assert row[0] is not None and row[1] == "confirmed"


def test_meta_states_authority(db):
    con, _ = db
    authority = con.execute("SELECT value FROM meta WHERE key='authority'").fetchone()[0]
    assert "census" in authority
    assert con.execute("SELECT value FROM meta WHERE key='built_at'").fetchone()[0]


def test_distinct_view_dedupes(tmp_path):
    """Two repos with the same finding shape at the same path in the same
    repo URL share a fingerprint and dedupe in v_distinct_owned."""
    results, cfg = _mk_ws(tmp_path)
    src = results / "findings" / "prod-a" / "repo-x"
    dup = results / "findings" / "prod-b" / "repo-x"
    dup.mkdir(parents=True)
    for f in src.iterdir():
        (dup / f.name).write_text(f.read_text())
    out = tmp_path / "dup.db"
    bdb.build(results, out, cfg=cfg)
    con = sqlite3.connect(out)
    assert con.execute("SELECT COUNT(*) FROM v_open").fetchone()[0] == 2
    row = con.execute("SELECT occurrences FROM v_distinct_owned").fetchone()
    con.close()
    assert row[0] == 2


def test_control_refs_column(tmp_path):
    results, cfg = _mk_ws(tmp_path)
    fc = results / "findings" / "prod-a" / "repo-x" / "repo-x-findings-current.json"
    doc = json.loads(fc.read_text())
    doc["findings"][0]["control_refs"] = ["nist-800-53-rev5:sc-28", "soc2-tsc:CC6.1"]
    fc.write_text(json.dumps(doc))
    out = tmp_path / "cr.db"
    bdb.build(results, out, cfg=cfg)
    con = sqlite3.connect(out)
    row = con.execute("SELECT control_refs FROM findings WHERE finding_id='FIND-001'").fetchone()[0]
    none_row = con.execute(
        "SELECT control_refs FROM findings WHERE finding_id='FIND-002'"
    ).fetchone()[0]
    con.close()
    assert json.loads(row) == ["nist-800-53-rev5:sc-28", "soc2-tsc:CC6.1"]
    assert none_row is None


def test_open_view_counts_fix_in_progress(db):
    """P0-3 (docs-verification 2026-07-31): the old whitelist said
    'in_progress' — not a schema enum value — so every fix_in_progress
    finding silently dropped out of v_open. Open now matches the
    census convention: anything not resolved/risk_accepted."""
    con, _ = db
    before = con.execute("SELECT COUNT(*) FROM v_open").fetchone()[0]
    con.execute("UPDATE findings SET resolution='fix_in_progress' WHERE finding_id='FIND-001'")
    assert con.execute("SELECT COUNT(*) FROM v_open").fetchone()[0] == before
    con.execute("UPDATE findings SET resolution='resolved' WHERE finding_id='FIND-001'")
    assert con.execute("SELECT COUNT(*) FROM v_open").fetchone()[0] == before - 1


def test_artifact_refs_keep_the_symlink_not_its_target(tmp_path):
    """The row must cite the artifact AT this repo, not wherever the link points.

    findings_db carried its own copy of the ref helper, still using Path.resolve(),
    and it had written the result into the shipped database: the row for
    repo-x in one product tree cited its triage and threat model under repo-y in a
    sibling release tree — a different artifact identity. Same bytes today, and after the
    move to object storage there is no symlink to collapse into anyway.
    """
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
    """Rebuilds re-INSERT OR REPLACE; the key must not multiply rows."""
    con, _ = db
    cols = {r[1] for r in con.execute("PRAGMA table_info(provenance)")}
    assert {"cve", "repo_key", "finding_id"} <= cols
    n = con.execute("SELECT COUNT(*) FROM provenance").fetchone()[0]
    assert n == 1


def test_repo_key_separates_two_report_kinds_for_one_repo(tmp_path):
    """One repo, two kinds of report, two rows — not one silently overwriting the other.

    Measured on the corpus: three cloud-config repos carry both a -security-audit.json
    and a -cloud-config-audit.json, and the key omitted report_kind, so findings.db
    held fewer rows than the resolver had records, with no error and nothing in the row to
    show a merge happened.
    """
    results, cfg = _mk_ws(tmp_path)
    d = results / "findings" / "prod-a" / "repo-x"
    (d / "repo-x-cloud-config-audit.json").write_text(
        json.dumps({"metadata": {"repository": "https://github.com/org/repo-x"}, "findings": []})
    )
    out = tmp_path / "kinds.db"
    bdb.build(results, out, cfg=cfg)
    con = sqlite3.connect(out)
    try:
        rows = con.execute(
            "SELECT repo_key, report_kind FROM repos WHERE repo_key LIKE '%repo-x%' ORDER BY 1"
        ).fetchall()
    finally:
        con.close()
    kinds = {k for _, k in rows}
    assert len(rows) == len(set(r[0] for r in rows)), rows
    assert kinds == {"code-audit", "cloud-config"}, rows


def test_view_filters_are_derived_from_the_contract_enums():
    """The view SQL must not contain hand-typed disposition values.

    'in_progress' (see test_open_view_counts_fix_in_progress) was one dead
    value; 'withdrawn' and 'refuted' were two more, sitting in v_open's
    exclusion list while existing in no validity enum, so they filtered
    nothing. Rendering the lists from the enums is what stops the next one.
    """
    from traust_contracts.v1.enums import Validity

    # The SQL literal form, not the bare word: prose in the comments may
    # legitimately name a value the filter no longer carries.
    assert "'withdrawn'" not in bdb.SCHEMA
    assert "'refuted'" not in bdb.SCHEMA
    for member in (*bdb.NON_EXPOSURE_VALIDITY, *bdb.CLOSED_RESOLUTIONS):
        assert f"'{member.value}'" in bdb.SCHEMA, member

    # Every enum member is bucketed, and the two buckets do not overlap.
    assert set(bdb.OPEN_EXPOSURE_VALIDITY) | set(bdb.NON_EXPOSURE_VALIDITY) == set(Validity)
    assert not set(bdb.OPEN_EXPOSURE_VALIDITY) & set(bdb.NON_EXPOSURE_VALIDITY)


def test_corrected_is_open_exposure(db):
    """report.schema.json: 'corrected' = "finding revised after initial
    write-up" — a claim about the write-up's accuracy, not about whether the
    bug exists. Whether it is fixed is resolution's axis, so corrected stays
    open. Zero rows carry it today, which is exactly why it needs pinning."""
    con, _ = db
    before = con.execute("SELECT COUNT(*) FROM v_open").fetchone()[0]
    con.execute("UPDATE findings SET validity='corrected' WHERE finding_id='FIND-001'")
    assert con.execute("SELECT COUNT(*) FROM v_open").fetchone()[0] == before
    con.execute("UPDATE findings SET validity='false_positive' WHERE finding_id='FIND-001'")
    assert con.execute("SELECT COUNT(*) FROM v_open").fetchone()[0] == before - 1


# The exact column list v_open/v_hardening published when they were `SELECT f.*`.
# Order is part of the contract: a positional consumer must keep working.
# Append here when a column is added; never insert or reorder.
PUBLISHED_VIEW_COLUMNS = [
    "repo_key",
    "finding_id",
    "title",
    "severity",
    "primary_cwe",
    "cwes",
    "cvss_score",
    "cvss_vector",
    "fingerprint",
    "validity",
    "resolution",
    "assurance",
    "validation_status",
    "last_updated",
    "paths",
    "control_refs",
    "tree",
    "ownership",
    "business_unit",
    "label",
    "product",
    "is_branch_audit",
]


@pytest.mark.parametrize("view", ["v_open", "v_hardening"])
def test_views_publish_a_named_stable_column_list(db, view):
    """`SELECT f.*` made the view's shape a side effect of the findings DDL.

    Adding a column to `findings` silently changed every consumer's result
    shape. The list is now explicit, so this test is the thing that notices.
    """
    con, _ = db
    got = [row[1] for row in con.execute(f"PRAGMA table_info({view})")]
    assert got == PUBLISHED_VIEW_COLUMNS
    assert "SELECT f.*" not in bdb.SCHEMA


def test_view_column_list_covers_the_findings_table(db):
    """A column added to `findings` must be added to the view list too.

    Without this, a new column is simply absent from the views and nobody
    finds out until a dashboard query returns nothing for it.
    """
    con, _ = db
    table_columns = [row[1] for row in con.execute("PRAGMA table_info(findings)")]
    published = [c.removeprefix("f.") for c in bdb.FINDING_VIEW_COLUMNS if c.startswith("f.")]
    assert published == table_columns, (
        "findings table and FINDING_VIEW_COLUMNS disagree; append the new "
        "column to FINDING_VIEW_COLUMNS (at the end) and to "
        "PUBLISHED_VIEW_COLUMNS in this test"
    )


def test_build_stamps_the_schema_revision(db):
    con, _ = db
    row = con.execute("SELECT value FROM meta WHERE key='schema_revision'").fetchone()
    assert row is not None, "a reader cannot check what the build does not stamp"
    assert int(row[0]) == bdb.SCHEMA_REVISION


def test_reader_refuses_a_database_from_another_revision(db):
    """build() always writes a fresh file, so this guard is for READERS.

    A dashboard querying a findings.db left over from an older harness would
    otherwise get a plausible wrong answer -- the views it selects from may
    not have the columns or the filter semantics it assumes.
    """
    con, _ = db
    assert bdb.check_revision(con) == bdb.SCHEMA_REVISION

    con.execute("UPDATE meta SET value=? WHERE key='schema_revision'", (bdb.SCHEMA_REVISION + 1,))
    with pytest.raises(bdb.StaleFindingsDb, match="Rebuild it"):
        bdb.check_revision(con)


def test_a_database_predating_the_stamp_reads_as_revision_one(db):
    """The key arrived with revision 2, so its absence is not 'unknown'."""
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
