"""Build the queryable findings database (C9) — a SQLite PROJECTION.

Loads the corpus resolution (traust_engine.corpus.resolver — never a hand-rolled
walker), every preferred findings report, disposition-ledger events,
validation reports, and repo-graph edges into one stdlib-SQLite file so
ad-hoc questions ("open criticals by business unit?", "which KEV-adjacent
repos ship in the most products?") become a query instead of an
8k-file JSON walk.

AUTHORITY RULE: `/census` remains the denominator authority. This DB is a
projection of the same corpus resolution, stamped with its build time and
corpus config — when a DB number and a census number disagree, the census
(rebuilt) wins, and the first debugging question is "is the DB stale?".
The `meta` table carries this statement so no query consumer can miss it.

Location: <analysis-results>/graph/findings.db — local rebuildable
artifact, gitignored (portfolio-graph.db precedent).

Usage:
    traust corpus findings-db \
        [--results-root ../analysis-results] [--out <file>]
        [--trees findings oss-findings ...]
"""

from __future__ import annotations

import datetime
import json
import sqlite3
from pathlib import Path

from traust_contracts.config import CorpusConfig
from traust_contracts.v1.enums import DispositionResolution, Validity

from traust_engine._util import finding_identity as fid
from traust_engine.assets import harness_version
from traust_engine.corpus import resolver as corpus
from traust_engine.corpus.report_store import to_ref
from traust_engine.locations import (
    REPO_GRAPH_REL,
)

try:
    from traust_contracts.models import Finding, Location

    HAS_CONTRACTS = True
except ImportError:
    HAS_CONTRACTS = False

# ---------------------------------------------------------------------------
# Disposition buckets for the views, derived from the contract enums rather
# than typed into the SQL.
#
# Hand-typed values are how v_open once excluded 'in_progress' — a value the
# enum does not contain ('fix_in_progress' does) — so every in-progress
# finding silently dropped out of open exposure (docs-verification
# 2026-07-31 P0-3). Two more dead values, 'withdrawn' and 'refuted', were
# still in the list when this was written; neither exists in any validity
# enum, so both filtered nothing.
#
# Deriving them means a value renamed upstream raises at import instead of
# going quietly inert, and the completeness assertion below means a value
# ADDED upstream stops the build until someone buckets it deliberately.
CLOSED_RESOLUTIONS = (
    DispositionResolution.RESOLVED,
    DispositionResolution.RISK_ACCEPTED,
)
# Real and risk-bearing but not open exposure: false positives are not real,
# and hardening is posture debt tracked separately (v_hardening).
NON_EXPOSURE_VALIDITY = (
    Validity.FALSE_POSITIVE,
    Validity.HARDENING,
)
# 'corrected' belongs here: report.schema.json defines it as "finding revised
# after initial write-up" — a statement about the accuracy of the write-up,
# not about whether the bug exists. Whether it is fixed is resolution's axis.
OPEN_EXPOSURE_VALIDITY = (
    Validity.CONFIRMED,
    Validity.NOT_VERIFIED,
    Validity.CORRECTED,
)

_unbucketed = set(Validity) - set(NON_EXPOSURE_VALIDITY) - set(OPEN_EXPOSURE_VALIDITY)
if _unbucketed:  # pragma: no cover - fires only when the contract enum grows
    raise RuntimeError(
        "findings_db: validity value(s) "
        f"{sorted(v.value for v in _unbucketed)} are in the contract enum but "
        "not bucketed as open exposure or non-exposure. Classify them in "
        "OPEN_EXPOSURE_VALIDITY or NON_EXPOSURE_VALIDITY — leaving them "
        "unlisted silently counts them as open in v_open."
    )


# Bumped whenever the shape this module writes changes in a way a reader can
# see: a table or view column added/removed/reordered, or a view's meaning
# changed. build() always writes a fresh file (it unlinks first), so this
# exists for READERS -- a dashboard querying a findings.db left over from an
# older harness gets a clear refusal instead of a plausible wrong answer.
#
# 1 -> 2: v_open/v_hardening stopped being SELECT f.* and publish an explicit
#         column list, and their disposition filters are derived from the
#         contract enums (the dead 'withdrawn'/'refuted' values are gone).
# 2 -> 3: repos gains priv_profile, the seventh per-record artifact ref.
#         operator-priv-profile became a projectable contract artifact
#         (contracts v0.17.0), and report_store rebuilds a ReportRecord from
#         this table field-for-field -- so a reader on revision 2 cannot
#         reconstruct the record at all.
SCHEMA_REVISION = 3


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


def _sql_values(values) -> str:
    """Render enum members as a SQL IN-list. Enum values only, never input."""
    return ", ".join(f"'{member.value}'" for member in values)


# ---------------------------------------------------------------------------
# The published column list for v_open and v_hardening.
#
# These were `SELECT f.*`, which made the view's shape a side effect of the
# findings table's DDL: add a column there and every consumer's result shape
# changed silently. Naming them makes the view a contract — and declaring it
# once means the two views cannot drift apart.
#
# ORDER IS PART OF THE CONTRACT. This is exactly what `f.*` expanded to, so
# any consumer reading positionally keeps working. Append new columns at the
# end; never insert or reorder.
FINDING_VIEW_COLUMNS = (
    "f.repo_key",
    "f.finding_id",
    "f.title",
    "f.severity",
    "f.primary_cwe",
    "f.cwes",
    "f.cvss_score",
    "f.cvss_vector",
    "f.fingerprint",
    "f.validity",
    "f.resolution",
    "f.assurance",
    "f.validation_status",
    "f.last_updated",
    "f.paths",
    "f.control_refs",
    "r.tree",
    "r.ownership",
    "r.business_unit",
    "r.label",
    "r.product",
    "r.is_branch_audit",
)
_VIEW_SELECT = ",\n         ".join(FINDING_VIEW_COLUMNS)


SCHEMA = f"""
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);

CREATE TABLE repos (
  repo_key      TEXT PRIMARY KEY,  -- tree/[product/]repo_dir/base
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

CREATE TABLE findings (
  repo_key      TEXT NOT NULL REFERENCES repos(repo_key),
  finding_id    TEXT NOT NULL,
  title         TEXT,
  severity      TEXT,
  primary_cwe   TEXT,
  cwes          TEXT,              -- JSON array
  cvss_score    REAL,
  cvss_vector   TEXT,
  fingerprint   TEXT,
  validity      TEXT,              -- disposition.validity
  resolution    TEXT,              -- disposition.resolution
  assurance     TEXT,
  validation_status TEXT,
  last_updated  TEXT,
  paths         TEXT,              -- JSON array of file paths
  control_refs  TEXT,              -- JSON array of framework:control_id
                                   -- tags on findings cross-filed from
                                   -- not_satisfied compliance controls
                                   -- (the attack_refs precedent)
  PRIMARY KEY (repo_key, finding_id)
);
CREATE INDEX idx_findings_fp   ON findings(fingerprint);
CREATE INDEX idx_findings_sev  ON findings(severity);
CREATE INDEX idx_findings_cwe  ON findings(primary_cwe);

CREATE TABLE events (
  event_id      TEXT NOT NULL,
  repo_key      TEXT NOT NULL,
  finding_id    TEXT,
  recorded_at   TEXT,
  occurred_at   TEXT,
  source_type   TEXT,
  source_ref    TEXT,
  actor_kind    TEXT,
  actor_identity TEXT,
  validity      TEXT,
  resolution    TEXT,
  PRIMARY KEY (event_id, repo_key)
);
CREATE INDEX idx_events_finding ON events(repo_key, finding_id);

CREATE TABLE validations (
  repo_key      TEXT,              -- NULL when the source repo could not
                                   -- be resolved from source_reports
  finding_id    TEXT,
  verdict       TEXT,
  technique     TEXT,
  report_path   TEXT
);
CREATE INDEX idx_validations ON validations(repo_key, finding_id);

CREATE TABLE graph_edges (
  from_id TEXT NOT NULL,
  to_id   TEXT NOT NULL,
  rel     TEXT NOT NULL
);
CREATE INDEX idx_edges_to ON graph_edges(to_id, rel);

-- ADR index projection (compliance Phase 2c): decisions with status,
-- for decision_refs joins. Source of truth = the pinned adr-index;
-- superseded/deprecated/archived decisions are non-citable for
-- satisfied compliance verdicts.
CREATE TABLE impact (
  cve            TEXT NOT NULL,     -- CVE the artifact analyzes
  module         TEXT NOT NULL,
  repo_id        TEXT NOT NULL,     -- 'repo:github.com/org/name' graph id
  classification TEXT NOT NULL,     -- affected | likely_affected | ...
  evidence_level TEXT,              -- symbol | symbol-usage | binary | manifest | none
  needs_manual_trace INTEGER,
  artifact       TEXT NOT NULL,     -- path of the *-impact-analysis.json
  PRIMARY KEY (cve, repo_id)
);
CREATE INDEX idx_impact_cve ON impact (cve);
CREATE INDEX idx_impact_class ON impact (classification);

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

-- open exposure, census-aligned approximation: not affirmatively closed,
-- not a false positive, and NOT hardening (posture debt is tracked
-- separately, per the census/trends convention). The census remains the
-- authority for headline denominators (see meta.authority).
CREATE VIEW v_open AS
  SELECT {_VIEW_SELECT}
  FROM findings f JOIN repos r USING (repo_key)
  -- Both lists are rendered from the traust-contracts enums (see
  -- CLOSED_RESOLUTIONS / NON_EXPOSURE_VALIDITY above), never typed here.
  -- The census's exact convention (build_census.py): open = anything not
  -- affirmatively closed, so partial fixes and regressed findings still
  -- count as shipped exposure.
  WHERE COALESCE(f.resolution, '{DispositionResolution.OPEN.value}')
        NOT IN ({_sql_values(CLOSED_RESOLUTIONS)})
    AND COALESCE(f.validity, '{Validity.CONFIRMED.value}')
        NOT IN ({_sql_values(NON_EXPOSURE_VALIDITY)});

-- posture debt (hardening class), separated like the dashboards do
CREATE VIEW v_hardening AS
  SELECT {_VIEW_SELECT}
  FROM findings f JOIN repos r USING (repo_key)
  WHERE f.validity = '{Validity.HARDENING.value}';

-- Lens-2 style distinct exposure over owned HEAD audits
CREATE VIEW v_distinct_owned AS
  SELECT fingerprint, COUNT(*) AS occurrences,
         MAX(severity) AS severity_example,
         MIN(repo_key) AS first_repo
  FROM v_open
  WHERE ownership = 'owned' AND is_branch_audit = 0
    AND fingerprint IS NOT NULL
  GROUP BY fingerprint;
"""


def _read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


DEFAULT_REPORT_KIND = "code-audit"


def repo_key(rec) -> str:
    """`tree[/product]/repo_dir/base`, plus the report kind when it is not the default.

    The kind used to be omitted entirely, which made the key collide whenever one
    repo carried two kinds of report. Three do — example-acm, automation-iac and
    acs-fleet-manager-config each have both a `-security-audit.json` and a
    `-cloud-config-audit.json` — so `INSERT OR REPLACE` dropped one of each pair and
    findings.db held fewer rows than records, with nothing to show a row had
    been overwritten. Same defect shape as the projection's (layer_id, finding_ref):
    a key missing a dimension, merging silently.

    Only non-default kinds are suffixed. repo_key is a published identifier that
    dashboards and saved queries reference, and changing every code-audit key to
    disambiguate a handful of collisions would be a worse trade than suffixing only
    the few kinds that actually need it (cloud-config and container-audit).
    """
    parts = [rec.tree]
    if rec.product:
        parts.append(rec.product)
    parts += [rec.repo_dir, rec.base]
    key = "/".join(parts)
    kind = getattr(rec, "report_kind", DEFAULT_REPORT_KIND) or DEFAULT_REPORT_KIND
    return key if kind == DEFAULT_REPORT_KIND else f"{key}#{kind}"


def insert_record(cur, rec, results: Path, counts: dict):
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
    repo_url = rec.repo_url or ((report or {}).get("metadata") or {}).get("repository")
    for f in (report or {}).get("findings") or []:
        disp = f.get("disposition") or {}
        cvss = f.get("cvss") or {}
        cwes = f.get("cwes") or []
        paths = [(loc.get("path") or "") for loc in f.get("locations") or [] if loc.get("path")]
        fp = f.get("fingerprint") or fid.fingerprint(f, repo_url)
        cur.execute(
            "INSERT OR REPLACE INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                key,
                f.get("id"),
                f.get("title"),
                f.get("severity"),
                fid.primary_cwe(f),
                json.dumps(cwes),
                cvss.get("score"),
                cvss.get("vector"),
                fp,
                disp.get("validity"),
                disp.get("resolution"),
                disp.get("assurance"),
                f.get("validation_status"),
                disp.get("last_updated"),
                json.dumps(paths),
                json.dumps(f["control_refs"]) if f.get("control_refs") else None,
            ),
        )
        counts["findings"] += 1

    if rec.findings_layer:
        layer = _read_json(results / rec.findings_layer) or {}
        for e in layer.get("events") or []:
            src = e.get("source") or {}
            actor = src.get("actor") or {}
            disp = e.get("disposition") or {}
            cur.execute(
                "INSERT OR REPLACE INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    e.get("event_id"),
                    key,
                    e.get("finding_ref"),
                    e.get("recorded_at"),
                    e.get("occurred_at"),
                    src.get("type"),
                    src.get("ref"),
                    actor.get("kind"),
                    actor.get("identity"),
                    disp.get("validity"),
                    disp.get("resolution"),
                ),
            )
            counts["events"] += 1

        # metadata.external_refs (contracts >= 0.5.4): which external
        # identifier a finding became. Provenance, not a disposition —
        # projected so metrics can answer "how many CVEs did we file
        # first" without re-walking every layer.
        # NB: not `fid` — that name is the finding_identity module here.
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


def insert_validations(cur, results: Path, counts: dict):
    """Walk <results>/validations/**/*-validation.json. The repo is
    resolved best-effort from source_reports paths (findings/... prefix
    match against repos.report_path); unresolved rows keep repo_key NULL
    rather than being dropped."""
    vroot = results / "validations"
    if not vroot.is_dir():
        return
    # non-branch (HEAD) records overwrite branch records sharing the dir
    cur.execute(
        "SELECT report_path, repo_key FROM repos "
        "WHERE report_path IS NOT NULL "
        "ORDER BY is_branch_audit DESC"
    )
    by_dir = {}
    for p, k in cur.fetchall():
        try:
            rel = Path(p).resolve().relative_to(results.resolve())
        except ValueError:
            rel = Path(p)
        by_dir[str(rel.parent)] = k

    def _tree_rel(sp: str) -> str | None:
        # source_reports paths are absolute on the AUTHORING machine;
        # everything after its analysis-results/ is workspace-portable
        marker = sp.rfind("analysis-results/")
        if marker >= 0:
            return sp[marker + len("analysis-results/") :]
        marker = sp.find("findings/")
        return sp[marker:] if marker >= 0 else None

    for vpath in sorted(vroot.rglob("*-validation.json")):
        vdoc = _read_json(vpath) or {}
        key = None
        for sr in vdoc.get("source_reports") or []:
            sp = sr.get("path") if isinstance(sr, dict) else str(sr)
            rel = _tree_rel(sp) if sp else None
            if rel:
                key = by_dir.get(str(Path(rel).parent))
                if key:
                    break
        for vf in vdoc.get("validated_findings") or []:
            cur.execute(
                "INSERT INTO validations VALUES (?,?,?,?,?)",
                (
                    key,
                    vf.get("source_id"),
                    vf.get("verdict"),
                    vf.get("technique"),
                    str(vpath.relative_to(results)),
                ),
            )
            counts["validations"] += 1


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


def insert_impact(cur, results: Path, counts: dict) -> None:
    """Project /impact-analysis artifacts (analysis-results/impact/) so
    'which repos are affected by CVE-X' is a SQL query. Projection only —
    the artifacts remain the source of truth."""
    counts.setdefault("impact_rows", 0)
    impact_dir = results / "impact"
    if not impact_dir.is_dir():
        return
    for art in sorted(impact_dir.glob("*-impact-analysis.json")):
        try:
            data = json.loads(art.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        meta = data.get("metadata") or {}
        cve = meta.get("cve") or ""
        module = meta.get("module") or ""
        if not cve:
            continue
        for r in data.get("repos") or []:
            ev = r.get("evidence") or {}
            cur.execute(
                "INSERT OR REPLACE INTO impact VALUES (?,?,?,?,?,?,?)",
                (
                    cve,
                    module,
                    r.get("repo") or "",
                    r.get("classification") or "",
                    ev.get("evidence_level"),
                    1 if ev.get("needs_manual_trace") else 0,
                    str(art.relative_to(results)),
                ),
            )
            counts["impact_rows"] += 1


def build(
    results: Path,
    out: Path,
    trees: list[str] | None = None,
    *,
    cfg: CorpusConfig,
    progress_tracker: Path | None = None,
) -> dict:
    res = corpus.resolve(results, cfg, trees=trees, with_repo_urls=True)

    out.parent.mkdir(parents=True, exist_ok=True)
    out.unlink(missing_ok=True)
    con = sqlite3.connect(out)
    cur = con.cursor()
    cur.executescript(SCHEMA)

    counts = {
        "repos": 0,
        "findings": 0,
        "events": 0,
        "provenance": 0,
        "validations": 0,
        "graph_edges": 0,
        "decisions": 0,
    }
    for rec in res.records:
        insert_record(cur, rec, results, counts)
    insert_validations(cur, results, counts)
    insert_graph(cur, results, counts)
    insert_decisions(cur, results, counts, progress_tracker=progress_tracker)
    insert_impact(cur, results, counts)

    meta = {
        "schema_revision": str(SCHEMA_REVISION),
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
    }
    for k, v in meta.items():
        cur.execute("INSERT INTO meta VALUES (?,?)", (k, v))
    con.commit()
    con.close()
    return counts


def query_findings_typed(db_path: Path, where: str = "", params: tuple = ()) -> list[Finding]:
    """Query findings DB and return typed Finding objects."""
    if not HAS_CONTRACTS:
        raise ImportError("traust_contracts required for typed findings")
    conn = connect(db_path)
    sql = "SELECT * FROM findings"
    if where:
        sql += f" WHERE {where}"
    cur = conn.execute(sql, params)
    rows = cur.fetchall()
    cols = [d[0] for d in cur.description] if cur.description else []
    conn.close()
    results: list[Finding] = []
    for row in rows:
        row_dict = dict(zip(cols, row, strict=False))
        paths_raw = row_dict.get("paths")
        paths = json.loads(paths_raw) if paths_raw else []
        results.append(
            Finding(
                id=row_dict.get("finding_id", ""),
                title=row_dict.get("title", ""),
                severity=row_dict.get("severity", ""),
                cwes=json.loads(row_dict.get("cwes", "[]")) if row_dict.get("cwes") else [],
                locations=[Location(path=p) for p in paths] if paths else [],
                description="",
                remediation="",
                fingerprint=row_dict.get("fingerprint", ""),
                validation_status=row_dict.get("validation_status", ""),
            )
        )
    return results
