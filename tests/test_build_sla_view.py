"""Tests for traust metrics sla + the shipped SLA policy (C10)."""

import datetime as dt
import json
import sqlite3
from pathlib import Path

import pytest
from traust_contracts.paths import schema_dir as _schema_dir

SCHEMA_DIR = _schema_dir()
from traust_engine.metrics import sla as sla

SHIPPED_POLICY = Path(__file__).parent / "fixtures" / "config" / "sla-policy.yaml"

POLICY = {
    "policy_name": "test-policy",
    "source": {"name": "t", "retrieved": "2026-07-18"},
    "severity_mapping": {
        "critical": "critical",
        "important": "high",
        "moderate": "medium",
        "low": "low",
    },
    "clock_start": "first_routed_or_filed",
    "profiles": {
        "main": {
            "default": True,
            "slas": {
                "critical": {"resolve_days": 30},
                "high": {"resolve_days": 60},
                "low": {"resolve_days": None},
            },
        },
        "floor": {
            "cvss_floor_days": {"threshold": 4.0, "resolve_days": 30},
            "slas": {"medium": {"resolve_days": 90}},
        },
    },
}


# ---------------- policy plumbing ----------------


def test_shipped_policy_validates():
    jsonschema = pytest.importorskip("jsonschema")
    yaml = pytest.importorskip("yaml")
    policy = yaml.safe_load(SHIPPED_POLICY.read_text())
    schema = json.loads((SCHEMA_DIR / "sla-policy.schema.json").read_text())
    jsonschema.validate(policy, schema)
    assert policy["severity_mapping"]["important"] == "high"
    assert policy["severity_mapping"]["moderate"] == "medium"
    assert policy["severity_mapping"]["low"] == "low"
    internal = policy["profiles"]["internal-cve"]
    assert internal["default"] is True
    assert internal["slas"]["critical"]["resolve_days"] == 30
    assert internal["slas"]["high"]["resolve_days"] == 60
    assert internal["slas"]["medium"]["resolve_days"] == 90
    assert internal["slas"]["low"]["resolve_days"] is None
    example = policy["profiles"]["example-profile"]
    assert example["cvss_floor_days"] == {"threshold": 4.0, "resolve_days": 30}


def test_pick_profile_default_and_named():
    name, _prof = sla.pick_profile(POLICY, None)
    assert name == "main"
    name, _ = sla.pick_profile(POLICY, "floor")
    assert name == "floor"
    with pytest.raises(SystemExit):
        sla.pick_profile(POLICY, "nope")


def test_resolve_days_ladder():
    main = POLICY["profiles"]["main"]
    assert sla.resolve_days_for(main, "critical", None) == 30
    assert sla.resolve_days_for(main, "low", None) is None
    assert sla.resolve_days_for(main, "medium", None) == "unclocked"
    floor = POLICY["profiles"]["floor"]
    # CVSS floor overrides regardless of severity presence
    assert sla.resolve_days_for(floor, "critical", 9.8) == 30
    assert sla.resolve_days_for(floor, "medium", 3.0) == 90
    assert sla.resolve_days_for(floor, "critical", 3.9) == "unclocked"


def test_clock_start_ladder():
    filed = [
        ("2026-06-05", "2026-06-06", "jira_filing"),
        ("2026-06-01", "2026-06-02", "triage_report"),
    ]
    d, basis = sla.clock_start(filed, "2026-05-01", "first_routed_or_filed")
    assert (d, basis) == (dt.date(2026, 6, 5), "filed")
    events = [("2026-06-01", "2026-06-02", "triage_report")]
    d, basis = sla.clock_start(events, "2026-05-01", "first_routed_or_filed")
    assert (d, basis) == (dt.date(2026, 6, 1), "first_event")
    d, basis = sla.clock_start([], "2026-05-01", "first_routed_or_filed")
    assert (d, basis) == (dt.date(2026, 5, 1), "audit_date")
    d, basis = sla.clock_start([], None, "first_routed_or_filed")
    assert (d, basis) == (None, "unclocked")


# ---------------- view over a fixture DB ----------------


def _mk_db(tmp_path):
    db = tmp_path / "findings.db"
    con = sqlite3.connect(db)
    con.executescript("""
    CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
    CREATE TABLE repos (repo_key TEXT PRIMARY KEY, tree TEXT,
      ownership TEXT, business_unit TEXT, label TEXT, product TEXT,
      repo_dir TEXT, base_slug TEXT, ref TEXT, repo_url TEXT,
      is_branch_audit INTEGER, is_md_only INTEGER, preferred TEXT,
      report_path TEXT, audit_date TEXT);
    CREATE TABLE findings (repo_key TEXT, finding_id TEXT, title TEXT,
      severity TEXT, primary_cwe TEXT, cwes TEXT, cvss_score REAL,
      cvss_vector TEXT, fingerprint TEXT, validity TEXT,
      resolution TEXT, assurance TEXT, validation_status TEXT,
      last_updated TEXT, paths TEXT);
    CREATE TABLE events (event_id TEXT, repo_key TEXT, finding_id TEXT,
      recorded_at TEXT, occurred_at TEXT, source_type TEXT,
      source_ref TEXT, actor_kind TEXT, actor_identity TEXT,
      validity TEXT, resolution TEXT);
    CREATE TABLE graph_edges (from_id TEXT, to_id TEXT, rel TEXT);
    INSERT INTO meta VALUES ('built_at', '2026-07-18T00:00:00Z');
    """)
    con.execute(
        "INSERT INTO repos VALUES ('findings/p/r/r','findings',"
        "'owned','EXAMPLE_BU','example-platform','p','r','r',NULL,"
        "'https://github.com/org/r',0,0,'findings_current',"
        "'x.json','2026-05-01')"
    )
    rows = [
        # overdue critical: audit 2026-05-01 + 30d = due 05-31 < as-of
        ("F-1", "critical", 9.0, "confirmed", "open"),
        # in-SLA high: due 2026-06-30... also < as-of 07-18 => overdue.
        # use a recent event to keep it in SLA instead (below)
        ("F-2", "high", 7.0, "confirmed", "open"),
        # low: no SLA
        ("F-3", "low", 2.0, "confirmed", "open"),
        # hardening: excluded entirely
        ("F-4", "critical", 9.0, "hardening", "open"),
        # resolved critical within SLA (event below)
        ("F-5", "critical", 9.0, "confirmed", "resolved"),
    ]
    for fid_, sev, score, validity, resolution in rows:
        con.execute(
            "INSERT INTO findings VALUES ('findings/p/r/r',?,?,?,"
            "'CWE-1','[]',?,NULL,'fp',?,?,NULL,NULL,NULL,'[]')",
            (fid_, "t-" + fid_, sev, score, validity, resolution),
        )
    # F-2 clock starts at a recent event -> still in SLA
    con.execute(
        "INSERT INTO events VALUES ('e2','findings/p/r/r','F-2',"
        "'2026-07-10','2026-07-01','triage_report','t.json',"
        "'machine','triage/1',NULL,NULL)"
    )
    # F-5 resolved 20 days after clock start (audit date) -> met 30d SLA
    con.execute(
        "INSERT INTO events VALUES ('e5','findings/p/r/r','F-5',"
        "'2026-05-22','2026-05-21','verification_report',"
        "'v.json','machine','verify/1',NULL,'resolved')"
    )
    con.execute(
        "INSERT INTO graph_edges VALUES ('owner-team:example-team','repo:github.com/org/r','owned-by')"
    )
    con.commit()
    con.close()
    return db


def test_build_view_end_to_end(tmp_path):
    db = _mk_db(tmp_path)
    view = sla.build_view(db, POLICY, "main", POLICY["profiles"]["main"], dt.date(2026, 7, 18))
    s = view["summary"]
    assert s["open_overdue"] == 1  # F-1
    assert s["open_in_sla"] == 1  # F-2 (event-started clock)
    assert s["open_no_sla"] == 1  # F-3
    assert s["out_of_profile_scope"] == 0
    assert s["resolved_met"] == 1  # F-5
    assert s["resolved_breached"] == 0
    assert s["resolved_sla_compliance_pct"] == 100.0
    esc = view["escalation_digest"]
    assert len(esc) == 1 and esc[0]["finding_id"] == "F-1"
    assert esc[0]["owner_team"] == "example-team"
    assert view["overdue_by_team"]["example-team"]["critical"] == 1
    # hardening never entered any counter or list
    assert "F-4" not in json.dumps(view)


def test_cvss_floor_profile(tmp_path):
    db = _mk_db(tmp_path)
    view = sla.build_view(db, POLICY, "floor", POLICY["profiles"]["floor"], dt.date(2026, 7, 18))
    s = view["summary"]
    # F-1 (9.0) and F-2 (7.0) get the 30d floor; F-3 (2.0, low) is out
    # of scope for this profile; F-5 resolved under floor clock
    assert s["open_overdue"] == 1  # F-1: due 05-31
    assert s["open_in_sla"] == 1  # F-2: event clock 07-01 + 30
    assert s["out_of_profile_scope"] == 1  # F-3
    assert s["resolved_met"] == 1


def test_markdown_renders(tmp_path):
    db = _mk_db(tmp_path)
    view = sla.build_view(db, POLICY, "main", POLICY["profiles"]["main"], dt.date(2026, 7, 18))
    md = sla.render_md(view)
    assert "escalation digest (generated — human review" in md.lower()
    assert "example-team" in md
    assert "policy data" in md


# ---------------- accountable-contact join (product registry) ----------


def _mk_pd_cache(tmp_path):
    """Fixture registry cache — no meta file, so status reads 'stale'."""
    cache = tmp_path / "feeds"
    cache.mkdir(exist_ok=True)
    doc = {
        "ps_products": {
            "widgetprod": {"name": "Example Widget", "ps_modules": ["widget-1"]},
            "gizmoprod": {"name": "Example Gizmo", "ps_modules": ["gizmo-1"]},
        },
        "ps_modules": {
            "widget-1": {
                "ps_update_streams": ["widget-1-default"],
                "private_tracker_cc": ["alice"],
                "default_cc": ["bob"],
                "lifecycle": {"supported_from": "2020-01-01", "supported_until": None},
            },
            "gizmo-1": {
                "default_cc": ["bob"],
                "lifecycle": {"supported_from": "2020-01-01", "supported_until": None},
            },
        },
        "ps_update_streams": {
            "widget-1-default": {
                "managed_service_components": [
                    {"name": "managed-comp", "git_repo_url": "https://github.com/org/managed"}
                ]
            },
        },
    }
    (cache / "product_definitions.json").write_text(json.dumps(doc))
    # YAML is a JSON superset, so the map file can be plain JSON text
    map_path = tmp_path / "map.yaml"
    map_path.write_text(
        json.dumps({"mappings": {"packages": {"widget": "widgetprod", "gizmo": "gizmoprod"}}})
    )
    return cache, map_path


def _mk_pd_db(tmp_path):
    """Four repos, each one overdue critical finding (30d SLA, audit
    2026-05-01, as-of 2026-07-18)."""
    db = tmp_path / "findings-pd.db"
    con = sqlite3.connect(db)
    con.executescript("""
    CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
    CREATE TABLE repos (repo_key TEXT PRIMARY KEY, tree TEXT,
      ownership TEXT, business_unit TEXT, label TEXT, product TEXT,
      repo_dir TEXT, base_slug TEXT, ref TEXT, repo_url TEXT,
      is_branch_audit INTEGER, is_md_only INTEGER, preferred TEXT,
      report_path TEXT, audit_date TEXT);
    CREATE TABLE findings (repo_key TEXT, finding_id TEXT, title TEXT,
      severity TEXT, primary_cwe TEXT, cwes TEXT, cvss_score REAL,
      cvss_vector TEXT, fingerprint TEXT, validity TEXT,
      resolution TEXT, assurance TEXT, validation_status TEXT,
      last_updated TEXT, paths TEXT);
    CREATE TABLE events (event_id TEXT, repo_key TEXT, finding_id TEXT,
      recorded_at TEXT, occurred_at TEXT, source_type TEXT,
      source_ref TEXT, actor_kind TEXT, actor_identity TEXT,
      validity TEXT, resolution TEXT);
    CREATE TABLE graph_edges (from_id TEXT, to_id TEXT, rel TEXT);
    INSERT INTO meta VALUES ('built_at', '2026-07-18T00:00:00Z');
    """)
    repos = [
        # (key, product, repo_url) — mapped t1, mapped t3, slug-only,
        # repo-url tier
        ("findings/widget/r/r", "widget", "https://github.com/org/w"),
        ("findings/gizmo/r/r", "gizmo", "https://github.com/org/g"),
        ("findings/slugonly/r/r", "examplewidget", "https://github.com/org/s"),
        ("findings/managed/r/r", None, "https://github.com/org/managed"),
    ]
    for key, product, url in repos:
        con.execute(
            "INSERT INTO repos VALUES (?,?,'owned','EXAMPLE_BU','example-platform',?,"
            "'r','r',NULL,?,0,0,'findings_current','x.json',"
            "'2026-05-01')",
            (key, "findings", product, url),
        )
        con.execute(
            "INSERT INTO findings VALUES (?,?,?,'critical','CWE-1',"
            "'[]',9.0,NULL,'fp','confirmed','open',NULL,NULL,NULL,'[]')",
            (key, "F-1", "t"),
        )
    con.commit()
    con.close()
    return db


def _digest_by_repo(view):
    return {e["repo_key"]: e for e in view["escalation_digest"]}


def test_escalation_rows_carry_accountable_contact(tmp_path):
    cache, map_path = _mk_pd_cache(tmp_path)
    ctx = sla.load_product_context(cache, map_path)
    view = sla.build_view(
        _mk_pd_db(tmp_path), POLICY, "main", POLICY["profiles"]["main"], dt.date(2026, 7, 18), ctx
    )
    esc = _digest_by_repo(view)
    ac = esc["findings/widget/r/r"]["accountable_contact"]
    # best-tier contact wins: alice (t1) over bob (t3)
    assert ac == {
        "kerberos_id": "alice",
        "tier": 1,
        "field": "private_tracker_cc",
        "embargo_cleared": True,
        "ps_product": "widgetprod",
        "match_tier": "mapped",
    }
    # repo-url tier is trustworthy and resolves through the stream join
    ac = esc["findings/managed/r/r"]["accountable_contact"]
    assert ac["kerberos_id"] == "alice"
    assert ac["match_tier"] == "repo-url"
    assert view["metadata"]["product_definitions"]["source_status"] in ("ok", "stale")


def test_tier3_contact_never_embargo_cleared(tmp_path):
    cache, map_path = _mk_pd_cache(tmp_path)
    ctx = sla.load_product_context(cache, map_path)
    view = sla.build_view(
        _mk_pd_db(tmp_path), POLICY, "main", POLICY["profiles"]["main"], dt.date(2026, 7, 18), ctx
    )
    ac = _digest_by_repo(view)["findings/gizmo/r/r"]["accountable_contact"]
    assert ac["tier"] == 3 and ac["field"] == "default_cc"
    assert ac["embargo_cleared"] is False


def test_slug_match_excluded_from_digest(tmp_path):
    cache, map_path = _mk_pd_cache(tmp_path)
    ctx = sla.load_product_context(cache, map_path)
    view = sla.build_view(
        _mk_pd_db(tmp_path), POLICY, "main", POLICY["profiles"]["main"], dt.date(2026, 7, 18), ctx
    )
    # 'examplewidget' slug-matches the registry but has no map entry:
    # advisory only, never lands in an unattended artifact
    assert _digest_by_repo(view)["findings/slugonly/r/r"]["accountable_contact"] is None


def test_unavailable_cache_degrades_not_fails(tmp_path):
    empty = tmp_path / "empty-feeds"
    empty.mkdir()
    ctx = sla.load_product_context(empty)
    assert ctx["status"] == "unavailable" and ctx["idx"] is None
    db = _mk_pd_db(tmp_path)
    view = sla.build_view(db, POLICY, "main", POLICY["profiles"]["main"], dt.date(2026, 7, 18), ctx)
    assert all(e["accountable_contact"] is None for e in view["escalation_digest"])
    assert view["metadata"]["product_definitions"]["source_status"] == "unavailable"
    # every counter identical to a run without the join
    base = sla.build_view(db, POLICY, "main", POLICY["profiles"]["main"], dt.date(2026, 7, 18))
    assert view["summary"] == base["summary"]


def test_load_product_context_none_cache_returns_unavailable_stub():
    ctx = sla.load_product_context(None)
    assert ctx == {
        "status": "unavailable",
        "source": {"detail": "feeds cache not configured"},
        "idx": None,
        "mappings": {},
    }


def test_metrics_build_sla_view_without_feeds_cache(tmp_path):
    import shutil

    import yaml

    from traust_engine import HarnessEngine

    home = tmp_path / "cfg"
    shutil.copytree(Path(__file__).parent / "fixtures" / "config", home)
    pt = tmp_path / "pt"
    ar = tmp_path / "ar"
    pt.mkdir()
    (pt / "configs").mkdir(parents=True)
    ar.mkdir()
    (home / "locations.yaml").write_text(
        yaml.safe_dump({"progress_tracker": str(pt), "analysis_results": str(ar)}),
        encoding="utf-8",
    )
    policy_path = pt / "configs" / "sla-policy.yaml"
    policy_path.write_text(yaml.safe_dump(POLICY), encoding="utf-8")
    db = _mk_db(tmp_path)

    h = HarnessEngine.load(config_home=home)
    view, _out = h.metrics.build_sla_view(
        db_path=db,
        policy_path=policy_path,
        as_of=dt.date(2026, 7, 18),
        out_dir=tmp_path / "sla-out",
    )
    assert view["metadata"]["product_definitions"]["source_status"] == "unavailable"


def test_markdown_renders_accountable_column(tmp_path):
    cache, map_path = _mk_pd_cache(tmp_path)
    ctx = sla.load_product_context(cache, map_path)
    view = sla.build_view(
        _mk_pd_db(tmp_path), POLICY, "main", POLICY["profiles"]["main"], dt.date(2026, 7, 18), ctx
    )
    md = sla.render_md(view)
    assert "| Accountable |" in md
    assert "`alice` (pd t1)" in md
    assert "escalation paths, not owners" in md
    # slug-only row renders the em-dash placeholder
    assert "| — |" in md
