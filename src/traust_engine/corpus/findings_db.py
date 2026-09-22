"""Build the queryable findings database -- the SQLite backend of storage/v1.

``<analysis-results>/graph/findings.db`` IS ``traust-contracts`` storage/v1
on SQLite. ONE schema, TWO backends: an adopter who keeps artifacts in git
gets this file, rebuilt from the tree; an adopter on PostgreSQL gets the same
tables and views populated at submit time. The dashboards read the views and
never learn which backend they are on.

What this module does:

1. ``Store(conn).init()`` -- the contract's tables and views, at the storage
   ``REVISION`` the installed contracts package declares. Nothing here
   defines a finding, an event, a validation or an impact row; the contract
   does, and ``store_ingest`` populates it from the SAME corpus resolution
   ``/census`` counts.
2. The five tables that have no contract home yet (dashboard plan, C1):
   ``repos`` (the corpus resolver's per-record identity, which
   ``report_store`` rehydrates a ReportRecord from field-for-field),
   ``graph_edges`` (repo-graph), ``provenance`` (a layer's external_refs --
   which CVE a finding became) and ``decisions`` (the ADR index), plus
   ``meta`` -- build bookkeeping: when, from what, and the authority rule.

Until 2026-09-21 this file defined its own nine tables and three views over
the same corpus the contract projects -- two SCHEMAS over one corpus, not two
backends -- and every dashboard number had two places to be wrong. The legacy
``findings`` / ``events`` / ``validations`` / ``impact`` tables and the
``v_open`` / ``v_hardening`` / ``v_distinct_owned`` views are gone; their
contract homes are ``report_finding`` / ``layer_event`` /
``validation_finding`` / ``impact_repo`` and ``open_findings`` /
``hardening_findings`` / ``distinct_exposure``, all read through
``current_finding`` (the spine) with ``subject_id`` as the repo key.

AUTHORITY RULE: `/census` remains the denominator authority. This DB is a
projection of the same corpus resolution, stamped with its build time and
corpus config -- when a DB number and a census number disagree, the census
(rebuilt) wins, and the first debugging question is "is the DB stale?".
The `meta` table carries this statement so no query consumer can miss it.

Rejections are NOT hidden: an artifact that fails contract validation is
absent from every contract table, and ``meta`` records how many and why
(``ingest_rejected``, ``ingest_reasons``). That is a data-quality queue for
the producers, never something this projection papers over.

Location: <analysis-results>/graph/findings.db -- local rebuildable
artifact, gitignored (portfolio-graph.db precedent). Built to a sibling
temp file and renamed into place, so a reader never sees a half-built store.

Usage:
    traust corpus findings-db \\
        [--results-root ../analysis-results] [--out <file>]
        [--trees findings oss-findings ...]
"""

from __future__ import annotations

import datetime
import json
import sqlite3
from pathlib import Path

from traust_contracts.config import CorpusConfig
from traust_contracts.v1.storage import Store
from traust_contracts.v1.storage.sql import REVISION as STORAGE_REVISION

from traust_engine.assets import harness_version
from traust_engine.corpus import resolver as corpus
from traust_engine.corpus import store_ingest
from traust_engine.corpus.report_store import to_ref
from traust_engine.locations import (
    REPO_GRAPH_REL,
)

# One definition of a subject's identity, shared with the ingest walker: the
# two used to differ on which report kinds get a suffix, so a container-audit
# subject had one key in `repos` and another in `subject_ownership`.
DEFAULT_REPORT_KIND = store_ingest.DEFAULT_REPORT_KIND
repo_key = store_ingest.repo_key


# Bumped whenever the shape this module writes changes in a way a reader can
# see: a table or view column added/removed/reordered, or a view's meaning
# changed. build() always writes a fresh file, so this exists for READERS --
# a dashboard querying a findings.db left over from an older harness gets a
# clear refusal instead of a plausible wrong answer.
#
# 1 -> 2: v_open/v_hardening stopped being SELECT f.* and publish an explicit
#         column list, and their disposition filters are derived from the
#         contract enums (the dead 'withdrawn'/'refuted' values are gone).
# 2 -> 3: repos gains priv_profile, the seventh per-record artifact ref.
# 3 -> 4: findings.db IS storage/v1 on SQLite. The legacy findings, events,
#         validations and impact tables and the v_open, v_hardening and
#         v_distinct_owned views are gone; the contract's tables and views
#         (storage REVISION recorded in meta.storage_revision and in
#         traust_storage_meta) take their place. Only repos, graph_edges,
#         provenance, decisions and meta remain harness-defined. A reader on
#         revision 3 selects from tables that do not exist.
SCHEMA_REVISION = 4


class StaleFindingsDb(RuntimeError):
    """The database on disk was written by a different schema revision."""


def check_revision(con: sqlite3.Connection, *, path: Path | None = None) -> int:
    """Refuse a findings.db this code did not write the shape of.

    Absent means pre-revision: the key was introduced with revision 2, so a
    database without it predates the column-list and enum-derivation changes.
    """
    where = f" at {path}" if path else ""
    try:
        row = con.execute("SELECT value FROM meta WHERE key='schema_revision'").fetchone()
    except sqlite3.DatabaseError as error:
        raise StaleFindingsDb(f"not a findings database{where}: {error}") from None
    found = int(row[0]) if row else 1
    if found != SCHEMA_REVISION:
        raise StaleFindingsDb(
            f"findings database{where} is revision {found}, this harness writes "
            f"{SCHEMA_REVISION}. Rebuild it: traust corpus findings-db"
        )
    return found


def connect(db_path: Path) -> sqlite3.Connection:
    """Open a findings.db for reading, refusing a stale one."""
    con = sqlite3.connect(str(db_path))
    try:
        check_revision(con, path=db_path)
    except Exception:
        con.close()
        raise
    return con


# The harness-defined remainder: the tables with no storage/v1 home (C1).
# Nothing about a FINDING lives here -- that is the contract's -- only the
# corpus resolver's record identity, the repo-graph edges, the ledger's
# external references and the ADR index, plus build bookkeeping.
SCHEMA = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);

CREATE TABLE repos (
  repo_key      TEXT PRIMARY KEY,  -- tree/[product/]repo_dir/base[#kind];
                                   -- == artifact_binding.subject_id and
                                   -- subject_ownership.subject_id
  tree          TEXT NOT NULL,
  ownership     TEXT NOT NULL,     -- owned | upstream | external-bu
  business_unit TEXT NOT NULL,
  label         TEXT NOT NULL,     -- engagement/tree label
  product       TEXT,
  repo_dir      TEXT NOT NULL,
  base_slug     TEXT NOT NULL,
  base          TEXT NOT NULL,     -- report filename base (base_slug + any ref suffix)
  ref           TEXT,              -- branch ref for branch re-audits
  ref_kind      TEXT,              -- branch | tag | default (declared only)
  ref_source    TEXT,              -- metadata | slug | NULL (HEAD legacy)
  repo_url      TEXT,
  is_branch_audit INTEGER NOT NULL,
  is_md_only    INTEGER NOT NULL,
  preferred     TEXT NOT NULL,
  report_kind   TEXT NOT NULL,      -- code-audit | cloud-config |
                                    -- container-audit (filter before
                                    -- blending: the units differ)
  report_path   TEXT,
  audit_date    TEXT,              -- report metadata.date (SLA clock
                                   -- fallback when a finding has no
                                   -- ledger events)
  -- The seven per-record artifact refs, root-relative rather than absolute.
  -- These are what corpus-manifest.json carried and this table did not, and
  -- they are the reason it can be retired (2026-08-20). Root-relative on
  -- purpose: an absolute path is meaningless once reports move out of the
  -- checkout (ledger plan §4.4.0), and a ref resolves through report_store
  -- against a local tree or a bucket alike.
  audit_json      TEXT,
  audit_md        TEXT,
  findings_current TEXT,
  findings_layer  TEXT,
  triage_json     TEXT,
  threat_model    TEXT,
  priv_profile    TEXT
);

CREATE TABLE graph_edges (
  from_id TEXT NOT NULL,
  to_id   TEXT NOT NULL,
  rel     TEXT NOT NULL
);
CREATE INDEX idx_edges_to ON graph_edges(to_id, rel);

-- Which external identifier a finding became (layer metadata.external_refs).
-- Provenance, not a disposition; layer_metadata does not carry it.
CREATE TABLE provenance (
  cve           TEXT NOT NULL,     -- external identifier the finding became
  system        TEXT NOT NULL,     -- cve | bugzilla | ghsa | jira
  repo_key      TEXT NOT NULL REFERENCES repos(repo_key),
  finding_id    TEXT NOT NULL,     -- finding this was stamped against
  confidence    TEXT,              -- confirmed | probable
  matched_on    TEXT,              -- how the link was derived
  stamped_at    TEXT,
  PRIMARY KEY (cve, repo_key, finding_id)
);
CREATE INDEX idx_prov_cve  ON provenance (cve);
CREATE INDEX idx_prov_conf ON provenance (confidence);

-- ADR index projection (compliance Phase 2c): decisions with status,
-- for decision_refs joins. Source of truth = the pinned adr-index;
-- superseded/deprecated/archived decisions are non-citable for
-- satisfied compliance verdicts.
CREATE TABLE decisions (
  register    TEXT NOT NULL,
  decision_id TEXT NOT NULL,
  title       TEXT,
  status      TEXT,
  repo        TEXT,
  pin         TEXT,
  path        TEXT,
  PRIMARY KEY (register, decision_id)
);
"""


def _read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def insert_record(cur, rec, results: Path, counts: dict):
    """One `repos` row per corpus record, plus the layer's external refs.

    Findings, events and validations are NOT written here any more: the
    contract projects them (report_finding, layer_event, validation_finding)
    from the same artifacts, keyed by the same subject_id this row's
    repo_key is.
    """
    key = repo_key(rec)
    report_rel = {
        "findings_current": rec.findings_current,
        "audit_json": rec.audit_json,
        "audit_md_only": rec.audit_md,
    }.get(rec.preferred)
    report = (
        _read_json(results / report_rel)
        if report_rel and rec.preferred != "audit_md_only"
        else None
    )
    audit_date = ((report or {}).get("metadata") or {}).get("date")

    def _ref(value):
        # Shared with build_index — see report_store.to_ref. This was a second copy
        # that still followed symlinks, and it had written that into the shipped db.
        return to_ref(value, results)

    cur.execute(
        "INSERT OR REPLACE INTO repos VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            key,
            rec.tree,
            rec.ownership,
            rec.business_unit,
            rec.label,
            rec.product,
            rec.repo_dir,
            rec.base_slug,
            rec.base,
            rec.ref,
            rec.ref_kind,
            rec.ref_source,
            rec.repo_url,
            int(rec.is_branch_audit),
            int(rec.is_md_only),
            rec.preferred,
            rec.report_kind,
            report_rel,
            audit_date,
            _ref(rec.audit_json),
            _ref(rec.audit_md),
            _ref(rec.findings_current),
            _ref(rec.findings_layer),
            _ref(rec.triage_json),
            _ref(rec.threat_model),
            _ref(rec.priv_profile),
        ),
    )
    counts["repos"] += 1

    if rec.findings_layer:
        layer = _read_json(results / rec.findings_layer) or {}
        # metadata.external_refs (contracts >= 0.5.4): which external
        # identifier a finding became. Provenance, not a disposition —
        # projected so metrics can answer "how many CVEs did we file
        # first" without re-walking every layer.
        for stamped_finding, refs in (
            (layer.get("metadata") or {}).get("external_refs") or {}
        ).items():
            for ref in refs or []:
                if not ref.get("id"):
                    continue
                cur.execute(
                    "INSERT OR REPLACE INTO provenance VALUES (?,?,?,?,?,?,?)",
                    (
                        ref["id"],
                        ref.get("system") or "cve",
                        key,
                        stamped_finding,
                        ref.get("confidence"),
                        ref.get("matched_on"),
                        ref.get("stamped_at"),
                    ),
                )
                counts["provenance"] += 1


def insert_graph(cur, results: Path, counts: dict):
    g = _read_json(results / REPO_GRAPH_REL)
    for e in (g or {}).get("edges") or []:
        cur.execute(
            "INSERT INTO graph_edges VALUES (?,?,?)", (e.get("from"), e.get("to"), e.get("rel"))
        )
        counts["graph_edges"] += 1


def insert_decisions(
    cur,
    results: Path,
    counts: dict,
    *,
    progress_tracker: Path | None = None,
):
    """ADR index (progress-tracker/metrics/adr/adr-index.json) →
    decisions table + governs edges. Absent index = zero rows, no
    error (the index lands with compliance Phase 2c consumers)."""
    pt = progress_tracker
    idx = _read_json(pt / "metrics" / "adr" / "adr-index.json") if pt else None
    for reg in (idx or {}).get("registers") or []:
        for d in reg.get("decisions") or []:
            cur.execute(
                "INSERT OR REPLACE INTO decisions VALUES (?,?,?,?,?,?,?)",
                (
                    reg["name"],
                    d.get("id"),
                    d.get("title"),
                    d.get("status"),
                    reg.get("repo"),
                    reg.get("pin"),
                    d.get("path"),
                ),
            )
            counts["decisions"] += 1
        for target in reg.get("governs") or []:
            cur.execute(
                "INSERT INTO graph_edges VALUES (?,?,?)",
                (f"decision-register:{reg['name']}", target, "governs"),
            )
            counts["graph_edges"] += 1


def build(
    results: Path,
    out: Path,
    trees: list[str] | None = None,
    *,
    cfg: CorpusConfig,
    progress_tracker: Path | None = None,
) -> dict:
    """Build findings.db: the contract's store, plus the harness remainder.

    Written to ``<out>.building`` and renamed into place at the end -- a full
    corpus takes minutes now that the store retains evidence, and a reader
    that opens the file mid-build must see the previous complete one, never
    a half-populated store.
    """
    res = corpus.resolve(results, cfg, trees=trees, with_repo_urls=True)

    out.parent.mkdir(parents=True, exist_ok=True)
    building = out.with_name(out.name + ".building")
    building.unlink(missing_ok=True)
    con = sqlite3.connect(building)
    # A from-scratch rebuild of a regenerable file: durability buys nothing
    # here and the journal roughly doubles the build time. The rename below
    # is what makes the result appear atomically.
    con.execute("PRAGMA journal_mode = OFF")
    con.execute("PRAGMA synchronous = OFF")

    # 1. The contract. Tables and views at the installed storage REVISION,
    #    populated from the same resolution the harness tables use.
    store = Store(con)
    store.init()
    ingest = store_ingest.ingest_tree(store, results, cfg, trees=trees, resolution=res)

    # 2. The harness remainder (C1).
    cur = con.cursor()
    cur.executescript(SCHEMA)
    counts = {
        "repos": 0,
        "provenance": 0,
        "graph_edges": 0,
        "decisions": 0,
        "artifacts_ingested": ingest.ingested + ingest.already,
        "artifacts_rejected": ingest.rejected,
    }
    for rec in res.records:
        insert_record(cur, rec, results, counts)
    insert_graph(cur, results, counts)
    insert_decisions(cur, results, counts, progress_tracker=progress_tracker)

    meta = {
        "schema_revision": str(SCHEMA_REVISION),
        "storage_revision": str(STORAGE_REVISION),
        "built_at": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "harness_version": harness_version() or "",
        "results_root": str(results),
        "trees": json.dumps(sorted(res.trees)),
        "authority": (
            "projection — /census is the denominator "
            "authority; on disagreement rebuild this DB and "
            "trust the census"
        ),
        "corpus_warnings": json.dumps(res.warnings[:50]),
        # The data-quality queue. An artifact that fails contract validation
        # is in none of the contract tables; saying how many and why is the
        # difference between a projection and a place numbers quietly go
        # missing.
        "ingest_accepted": str(ingest.ingested + ingest.already),
        "ingest_rejected": str(ingest.rejected),
        "ingest_reasons": json.dumps(
            dict(sorted(ingest.reasons.items(), key=lambda kv: -kv[1])[:20])
        ),
        "ingest_unregistered_trees": json.dumps(ingest.unregistered),
        "ingest_by_family": json.dumps(ingest.by_family),
    }
    for k, v in meta.items():
        cur.execute("INSERT INTO meta VALUES (?,?)", (k, v))
    con.commit()
    con.close()
    building.replace(out)
    return counts
