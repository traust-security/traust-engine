"""Deterministic linter for THREAT_MODEL.md artifacts.

Enforces the contract in skills/threat-model/schema.md the same way
validate_report.py gates audit/triage JSON: the /threat-model skill is not
done until this exits 0. Checks structure (sections, tables, enums), the
coverage invariant (every entry point is threatened or explicitly parked),
ID stability, provenance completeness, and evidence-cell hygiene (evidence
holds vuln references, never file:line citations — the litmus-test guard).

Deterministic-tooling invariant: this script routes/gates/validates; it
never concludes. A lint failure means "fix the artifact", not "the threat
is wrong".

Usage:
    python3 -m traust_engine.reporting.lint <path> [<path> ...] [--strict]

Paths may be THREAT_MODEL.md files or directories (searched recursively for
THREAT_MODEL.md and *-threat-model.md). --strict promotes recommended-but-
optional gaps (missing harness_version, missing section 8) to warnings shown
in the summary; they never fail the run, matching validate_report.py --strict.
"""

import json
import re
from pathlib import Path

from traust_engine.reporting import threat_rating

REQUIRED_SECTIONS = [
    "1. System context",
    "2. Assets",
    "3. Entry points & trust boundaries",
    "4. Threats",
    "5. Deprioritized",
    "6. Open questions",
    "7. Provenance",
]
OPTIONAL_SECTIONS = [
    "8. Recommended mitigations",
    "9. Attack scenarios",
    "10. Tenant boundaries",
    "11. Risk ratings",
]

ACTOR_ENUM = {
    "remote_unauth",
    "remote_auth",
    "adjacent_network",
    "local_user",
    "local_admin",
    "supply_chain",
    "insider",
}
IMPACT_ENUM = {"low", "medium", "high", "critical", "existential"}
LIKELIHOOD_ENUM = {"very_rare", "rare", "possible", "likely", "almost_certain"}
STATUS_ENUM = {"unmitigated", "partially_mitigated", "mitigated", "risk_accepted"}
SENSITIVITY_ENUM = {"low", "medium", "high", "critical"}
CLOSES_CLASS_ENUM = {"yes", "partial", "no"}
EFFORT_ENUM = {"XS", "S", "M", "L"}
MODE_ENUM = {"interview", "bootstrap", "bootstrap-then-interview"}

IMPACT_ORDER = ["existential", "critical", "high", "medium", "low"]
LIKELIHOOD_ORDER = ["almost_certain", "likely", "possible", "rare", "very_rare"]

THREATS_COLUMNS = [
    "id",
    "threat",
    "actor",
    "surface",
    "asset",
    "impact",
    "likelihood",
    "status",
    "controls",
    "evidence",
]
# Trailing column: MITRE ATT&CK technique IDs, validated against the
# pinned table in skills/attack-coverage/. DEFAULT for new emissions
# since ATTACK_REFS_SINCE (enforced via section-7 provenance
# harness_version); ten-column legacy models stay valid.
THREATS_COLUMNS_ATTACK = [*THREATS_COLUMNS, "attack_refs"]
ATTACK_REFS_SINCE = (0, 82, 0)
# Trailing OPTIONAL column after attack_refs (PEACH isolation lens Phase 1,
# comma-separated subset of the five isolation-hardening
# dimension keys (shared vocabulary with contracts/schemas/isolation-review.schema.json)
# tagging which dimension a threat stresses. Multi-tenant services only;
# never required — 10- and 11-column tables stay valid.
THREATS_COLUMNS_ISOLATION = [*THREATS_COLUMNS_ATTACK, "isolation_dimensions"]
# OWASP Risk Rating Methodology variant: `severity | likelihood | impact`
# replace the legacy `impact | likelihood` pair (cell forms and the rating
# arithmetic: reporting/threat_rating.py). Always carries attack_refs, since
# only new emissions are rated; isolation_dimensions stays optional.
THREATS_COLUMNS_OWASP = [
    "id",
    "threat",
    "actor",
    "surface",
    "asset",
    "severity",
    "likelihood",
    "impact",
    "status",
    "controls",
    "evidence",
    "attack_refs",
]
THREATS_COLUMNS_OWASP_ISOLATION = [*THREATS_COLUMNS_OWASP, "isolation_dimensions"]
_THREATS_BASE_VARIANTS = (
    THREATS_COLUMNS,
    THREATS_COLUMNS_ATTACK,
    THREATS_COLUMNS_ISOLATION,
    THREATS_COLUMNS_OWASP,
    THREATS_COLUMNS_OWASP_ISOLATION,
)
# Trailing OPTIONAL column, last: the review surfaces a threat sits on
# (threat-model schema `review_surfaces`, traust-contracts 0.57.0), written
# only when some threat carries them.
THREATS_COLUMN_VARIANTS = (
    *_THREATS_BASE_VARIANTS,
    *([*v, "review_surfaces"] for v in _THREATS_BASE_VARIANTS),
)

# Section 10 "Tenant boundaries" (optional; multi-tenant services only).
# Vocabulary is shared with the isolation-review skill: interface kind,
# exposure, complexity, and the five dimension results reuse the enums of
# contracts/schemas/isolation-review.schema.json so boundary rows and full isolation
# reviews line up. PEACH is cited by name/URL only — never adapted text.
BOUNDARY_COLUMNS = [
    "boundary_id",
    "interface",
    "kind",
    "exposure",
    "complexity",
    "privilege",
    "encryption",
    "authentication",
    "connectivity",
    "hygiene",
    "threat_ids",
    "isolation_review_ref",
]
ISOLATION_DIMENSIONS = ["privilege", "encryption", "authentication", "connectivity", "hygiene"]
BOUNDARY_KIND_ENUM = {"api", "data-store", "queue", "ingress", "webhook", "cli", "other"}
BOUNDARY_EXPOSURE_ENUM = {"public", "tenant", "partner", "internal"}
BOUNDARY_COMPLEXITY_ENUM = {"low", "medium", "high"}
DIMENSION_RESULT_ENUM = {"yes", "partial", "no", "na"}
BOUNDARY_ID = re.compile(r"^IF-\d+$")
# empty cell valid; otherwise the isolation review's artifact row id — the store owns
# artifacts, and a file path is not an id
ISOLATION_REVIEW_REF = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
ASSETS_COLUMNS = ["asset", "description", "sensitivity"]
ASSETS_OPTIONAL_COLUMNS = ["regulatory_scope", "example_records"]
ENTRY_COLUMNS = ["entry_point", "description", "trust_boundary", "reachable_assets"]
#: section 3 with the optional trailing review_surfaces column
ENTRY_COLUMNS_SURFACES = [*ENTRY_COLUMNS, "review_surfaces"]


def _review_surfaces() -> list[str]:
    from traust_contracts.paths import enum_dir

    return json.loads((enum_dir() / "review-surface.json").read_text(encoding="utf-8"))["values"]


def _surface_errors(where: str, cell: str) -> list[str]:
    """Each comma-separated value must be a review_surface id (empty is fine)."""
    known = _review_surfaces()
    return [
        f"{where}: review_surfaces '{s}' not in {known}"
        for s in (x.strip() for x in re.split(r"[,;]\s*", cell or "") if x.strip())
        if s not in known
    ]


DEPRI_COLUMNS = ["threat", "reason"]
DEPRI_COLUMNS_SURFACES = [*DEPRI_COLUMNS, "review_surfaces"]
MITIG_COLUMNS = ["mitigation", "threat_ids", "closes_class", "effort"]
UPDATE_HISTORY_COLUMNS = ["date", "changes", "reason"]

# Evidence cells hold references that *instantiate* a threat: CVEs, GHSAs,
# commit hashes, audit finding IDs (FIND-NNN or canonical
# {REPO_SLUG}-{SHORTSHA}-{NNN} as used by the disposition ledger), issue
# URLs, or pentest finding IDs (uppercase code + number).
EVIDENCE_OK = [
    re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE),
    re.compile(r"^GHSA(-[a-z0-9]{4}){3}$", re.IGNORECASE),
    re.compile(r"^[0-9a-f]{7,40}$"),  # commit hash
    re.compile(r"^FIND-\d{3,}$"),  # audit finding id
    re.compile(r"^[A-Z0-9_.]+-[0-9a-f]{7,12}-\d{3}$"),  # canonical ledger id
    re.compile(r"^-\d{3}$"),  # continuation shorthand after a canonical id
    re.compile(r"^https?://\S+$"),  # issue link
    re.compile(r"^[A-Z]{2,}[A-Z0-9]*-\d+$"),  # tracker/pentest id
]


_ATTACK_ID = re.compile(r"^T\d{4}(\.\d{3})?$")


def _validate_attack_refs(ids):
    """Validate technique IDs against the pinned ATT&CK table (shared
    attack-coverage module). Falls back to shape-only validation with a
    warning-style message if the table is unavailable (e.g. the linter is
    copied out of the harness tree)."""
    try:
        import attack_refs as _ar

        return _ar.validate_ids(ids)
    except Exception:
        return [
            f"'{t}' is not a well-formed technique ID (pinned table unavailable; shape check only)"
            for t in ids
            if not _ATTACK_ID.match(t)
        ]


def evidence_token_ok(token):
    """True if a single evidence token is a recognized vuln reference.

    Tolerates the prose forms real artifacts use: a "commit "/"commits "
    prefix and a trailing parenthetical annotation ("(exploited in the
    wild)").
    """
    token = re.sub(r"\s*\([^)]*\)\s*$", "", token.strip())
    token = re.sub(r"^commits?\s+", "", token, flags=re.IGNORECASE)
    return any(p.match(token) for p in EVIDENCE_OK)


# file:line citations do not belong in evidence (litmus-test guard).
FILE_LINE = re.compile(r"[\w./-]+\.[A-Za-z]{1,5}:\d+")

THREAT_ID = re.compile(r"^T\d+$")
SCENARIO_HEADING = re.compile(r"^### (T\d+)\b")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def parse_sections(text):
    """Return ordered list of (heading_text, body_lines)."""
    sections = []
    current = None
    for line in text.splitlines():
        m = re.match(r"^## (.+?)\s*$", line)
        if m:
            current = (m.group(1), [])
            sections.append(current)
        elif current is not None:
            current[1].append(line)
    return sections


def split_row(stripped):
    """Split a table row on unescaped pipes only (GFM: `\\|` is a literal)."""
    cells = re.split(r"(?<!\\)\|", stripped)
    if cells and cells[0].strip() == "":
        cells = cells[1:]
    if cells and cells[-1].strip() == "":
        cells = cells[:-1]
    return [c.strip() for c in cells]


def parse_table(body_lines):
    """Parse the first markdown table in a section body.

    Returns (columns, rows) where each row is a list of cell strings, or
    (None, []) if no table found.
    """
    columns, rows = None, []
    for line in body_lines:
        stripped = line.strip()
        if not stripped.startswith("|"):
            if columns is not None and stripped == "":
                break
            continue
        cells = split_row(stripped)
        if columns is None:
            columns = cells
        elif set(stripped) <= {"|", "-", " ", ":"}:
            continue  # separator row
        else:
            rows.append(cells)
    return columns, rows


def parse_provenance(body_lines):
    """Parse `- key: value` bullets from the provenance section."""
    fields = {}
    for line in body_lines:
        m = re.match(r"^\s*-\s*([a-z_ ]+?)\s*:\s*(.*)$", line)
        if m:
            fields[m.group(1).strip()] = m.group(2).strip()
    return fields


def lint_file(path, strict=False):
    errors, warnings = [], []
    text = path.read_text(encoding="utf-8")

    if not re.match(r"^# Threat Model:\s*\S", text.splitlines()[0] if text else ""):
        errors.append("first line must be '# Threat Model: <system name>'")

    sections = parse_sections(text)
    headings = [h for h, _ in sections]

    # -- Section presence and order -------------------------------------
    numbered = [h for h in headings if re.match(r"^\d+\.", h)]
    for i, want in enumerate(REQUIRED_SECTIONS):
        if want not in headings:
            errors.append(f"missing required section '## {want}'")
        elif numbered and want in numbered and numbered.index(want) != i:
            errors.append(f"section '## {want}' out of order")
    for h in numbered:
        if h not in REQUIRED_SECTIONS and h not in OPTIONAL_SECTIONS:
            warnings.append(f"unrecognized numbered section '## {h}'")

    def body(name):
        for h, b in sections:
            if h == name:
                return b
        return None

    # -- Section 2: Assets ----------------------------------------------
    asset_names = []
    b = body("2. Assets")
    if b is not None:
        cols, rows = parse_table(b)
        if cols is None:
            errors.append("section 2 has no assets table")
        else:
            if cols[:3] != ASSETS_COLUMNS:
                errors.append(f"section 2 columns must start with {ASSETS_COLUMNS}, got {cols[:3]}")
            for extra in cols[3:]:
                if extra not in ASSETS_OPTIONAL_COLUMNS:
                    warnings.append(f"section 2 unexpected column '{extra}'")
            for r in rows:
                if len(r) < 3:
                    errors.append(f"section 2 row too short: {r}")
                    continue
                asset_names.append(r[0])
                if r[2] not in SENSITIVITY_ENUM:
                    errors.append(
                        f"section 2 asset '{r[0]}': sensitivity '{r[2]}' not in {sorted(SENSITIVITY_ENUM)}"
                    )

    # -- Section 3: Entry points -----------------------------------------
    entry_points = []
    b = body("3. Entry points & trust boundaries")
    if b is not None:
        cols, rows = parse_table(b)
        if cols is None:
            errors.append("section 3 has no entry-points table")
        elif cols not in (ENTRY_COLUMNS, ENTRY_COLUMNS_SURFACES):
            errors.append(
                f"section 3 columns must be {ENTRY_COLUMNS} "
                f"(optionally + ['review_surfaces']), got {cols}"
            )
        for r in rows:
            if r and r[0]:
                entry_points.append(r[0])
                if cols == ENTRY_COLUMNS_SURFACES and len(r) == len(cols):
                    errors += _surface_errors(f"section 3 '{r[0]}'", r[-1])

    # -- Section 4: Threats -----------------------------------------------
    threat_ids, surface_cells, threat_rows = [], [], []
    rated_rows = {}  # id -> section 4 row, OWASP variant only
    threat_cols_seen = None
    b = body("4. Threats")
    if b is not None:
        cols, rows = parse_table(b)
        if cols is None:
            errors.append("section 4 has no threats table")
        elif cols not in THREATS_COLUMN_VARIANTS:
            errors.append(
                f"section 4 columns must be {THREATS_COLUMNS} "
                f"(optionally + ['attack_refs'], optionally then "
                f"+ ['isolation_dimensions']), or the OWASP-rated "
                f"{THREATS_COLUMNS_OWASP} (optionally + "
                f"['isolation_dimensions']), either optionally ending in "
                f"'review_surfaces', got {cols}"
            )
        else:
            threat_cols = threat_cols_seen = cols
            for r in rows:
                if len(r) != len(threat_cols):
                    errors.append(
                        f"section 4 row has {len(r)} cells, expected {len(threat_cols)}: {r[:2]}"
                    )
                    continue
                row = dict(zip(threat_cols, r, strict=False))
                threat_rows.append(row)
                tid = row["id"]
                if not THREAT_ID.match(tid):
                    errors.append(f"section 4 id '{tid}' must match T<number>")
                elif tid in threat_ids:
                    errors.append(f"section 4 duplicate id '{tid}'")
                threat_ids.append(tid)
                surface_cells.append(row["surface"])
                # actor may be a comma-separated list of enum values
                for a in re.split(r",\s*", row["actor"]):
                    if a not in ACTOR_ENUM:
                        errors.append(f"section 4 {tid}: actor '{a}' not in {sorted(ACTOR_ENUM)}")
                if "severity" in row:
                    for msg in threat_rating.cell_problems(
                        row["severity"], row["likelihood"], row["impact"]
                    ):
                        errors.append(f"section 4 {tid}: {msg}")
                    rated_rows[tid] = row
                    rating_enums = (("status", STATUS_ENUM),)
                else:
                    rating_enums = (
                        ("impact", IMPACT_ENUM),
                        ("likelihood", LIKELIHOOD_ENUM),
                        ("status", STATUS_ENUM),
                    )
                for field, enum in rating_enums:
                    if row[field] not in enum:
                        errors.append(
                            f"section 4 {tid}: {field} '{row[field]}' not in {sorted(enum)}"
                        )
                # evidence hygiene
                ev = row["evidence"].strip()
                if ev:
                    if FILE_LINE.search(ev):
                        errors.append(
                            f"section 4 {tid}: evidence contains a file:line citation "
                            f"('{ev}') — evidence holds vuln references (CVE/GHSA/commit/"
                            f"finding ID), never code locations; siblings go in the hand-back"
                        )
                    else:
                        for token in re.split(r"[,;]\s*", ev):
                            token = token.strip()
                            if token and not evidence_token_ok(token):
                                warnings.append(
                                    f"section 4 {tid}: evidence token '{token}' is not a recognized vuln reference"
                                )
                # attack_refs: bounded selection from the pinned ATT&CK table
                ar = (row.get("attack_refs") or "").strip()
                if ar:
                    ids = [t.strip() for t in re.split(r"[,;]\s*", ar) if t.strip()]
                    for msg in _validate_attack_refs(ids):
                        errors.append(f"section 4 {tid}: attack_refs {msg}")
                    if len(ids) > 4:
                        warnings.append(
                            f"section 4 {tid}: {len(ids)} attack_refs — a row needing >4 techniques is usually too broad; consider splitting"
                        )
                # isolation_dimensions: optional subset of the five
                # isolation-hardening dimension keys (empty cell valid)
                iso = (row.get("isolation_dimensions") or "").strip()
                if iso:
                    for d in [t.strip() for t in re.split(r"[,;]\s*", iso) if t.strip()]:
                        if d not in ISOLATION_DIMENSIONS:
                            errors.append(
                                f"section 4 {tid}: isolation_dimensions "
                                f"'{d}' not in {ISOLATION_DIMENSIONS}"
                            )
                errors += _surface_errors(f"section 4 {tid}", row.get("review_surfaces") or "")
            # sort order (warning: legacy models predate strict ordering)
            if "severity" in threat_cols:
                keys = [threat_rating.order_key(threat_rating.parse_row(r)) for r in threat_rows]
                if keys != sorted(keys):
                    warnings.append(
                        "section 4 rows are not sorted by (severity desc, impact score "
                        "desc, likelihood score desc), unrated rows after rated ones"
                    )
            else:
                keys = [
                    (IMPACT_ORDER.index(r["impact"]), LIKELIHOOD_ORDER.index(r["likelihood"]))
                    for r in threat_rows
                    if r["impact"] in IMPACT_ENUM and r["likelihood"] in LIKELIHOOD_ENUM
                ]
                if keys != sorted(keys):
                    warnings.append(
                        "section 4 rows are not sorted by (impact desc, likelihood desc)"
                    )

    # -- Section 5: Deprioritized ------------------------------------------
    depri_text = ""
    b = body("5. Deprioritized")
    if b is not None:
        depri_text = "\n".join(b)
        cols, rows = parse_table(b)
        if cols is not None and cols not in (DEPRI_COLUMNS, DEPRI_COLUMNS_SURFACES):
            errors.append(
                f"section 5 columns must be {DEPRI_COLUMNS} "
                f"(optionally + ['review_surfaces']), got {cols}"
            )
        if cols == DEPRI_COLUMNS_SURFACES:
            for r in rows:
                if r and r[0] and len(r) == len(cols):
                    errors += _surface_errors(f"section 5 '{r[0]}'", r[-1])

    # -- Coverage invariant --------------------------------------------------
    surfaces_joined = " ".join(surface_cells).lower()
    for ep in entry_points:
        if ep.lower() in surfaces_joined:
            continue
        if ep.lower() in depri_text.lower():
            continue
        errors.append(
            f"coverage: entry point '{ep}' has no section 4 threat naming it in "
            f"'surface' and no section 5 row parking it"
        )

    # -- Section 7: Provenance -----------------------------------------------
    b = body("7. Provenance")
    if b is not None:
        prov = parse_provenance(b)
        for key in ("mode", "date", "target", "inputs", "owner"):
            if key not in prov:
                errors.append(f"section 7 missing '{key}'")
        mode = prov.get("mode", "")
        if mode and mode not in MODE_ENUM:
            errors.append(f"section 7 mode '{mode}' not in {sorted(MODE_ENUM)}")
        if prov.get("date") and not DATE_RE.match(prov["date"]):
            errors.append(f"section 7 date '{prov['date']}' must be YYYY-MM-DD")
        if "harness_version" not in prov:
            warnings.append(
                "section 7 missing 'harness_version' (required for new emissions; "
                "legacy artifacts predate it)"
            )
        # attack_refs column is default schema for emissions >= 0.82.0
        m = re.match(r"(\d+)\.(\d+)\.(\d+)", prov.get("harness_version") or "")
        if (
            m
            and tuple(int(g) for g in m.groups()) >= ATTACK_REFS_SINCE
            and threat_cols_seen == THREATS_COLUMNS
        ):
            errors.append(
                "section 4 is missing the attack_refs column — default schema "
                f"for emissions at harness >= "
                f"{'.'.join(map(str, ATTACK_REFS_SINCE))} (this model's "
                f"provenance says {prov['harness_version']}); legacy models "
                "are exempt, new emissions are not"
            )
        # optional update history
        cols, rows = parse_table(b)
        if cols is not None:
            if cols != UPDATE_HISTORY_COLUMNS:
                errors.append(
                    f"section 7 update-history columns must be {UPDATE_HISTORY_COLUMNS}, got {cols}"
                )
            for r in rows:
                if r and r[0] and not DATE_RE.match(r[0]):
                    errors.append(f"section 7 update-history date '{r[0]}' must be YYYY-MM-DD")

    # -- Section 8: Recommended mitigations (optional) -------------------------
    b = body("8. Recommended mitigations")
    if b is None:
        if strict:
            warnings.append(
                "section 8 (Recommended mitigations) absent — recommended for new emissions"
            )
    else:
        cols, rows = parse_table(b)
        if cols is not None:
            if cols != MITIG_COLUMNS:
                errors.append(f"section 8 columns must be {MITIG_COLUMNS}, got {cols}")
            else:
                for r in rows:
                    if len(r) != 4:
                        errors.append(f"section 8 row too short: {r}")
                        continue
                    for tid in re.split(r"[,;]\s*", r[1]):
                        tid = tid.strip()
                        if tid and tid not in threat_ids:
                            errors.append(
                                f"section 8 mitigation '{r[0]}' references unknown threat id '{tid}'"
                            )
                    if r[2] not in CLOSES_CLASS_ENUM:
                        errors.append(
                            f"section 8 '{r[0]}': closes_class '{r[2]}' not in {sorted(CLOSES_CLASS_ENUM)}"
                        )
                    if r[3] not in EFFORT_ENUM:
                        errors.append(
                            f"section 8 '{r[0]}': effort '{r[3]}' not in {sorted(EFFORT_ENUM)}"
                        )

    # -- Section 9: Attack scenarios (optional) ---------------------------------
    b = body("9. Attack scenarios")
    if b is not None:
        scenario_ids = []
        for line in b:
            m = SCENARIO_HEADING.match(line)
            if m:
                scenario_ids.append(m.group(1))
            elif line.startswith("### "):
                errors.append(f"section 9 heading '{line.strip()}' must start '### T<n>'")
        if not scenario_ids:
            errors.append("section 9 present but has no '### T<n>' scenario subsections")
        for sid in scenario_ids:
            if sid not in threat_ids:
                errors.append(f"section 9 scenario '{sid}' references unknown threat id")
        if len(scenario_ids) > 8:
            warnings.append(
                f"section 9 has {len(scenario_ids)} scenarios — keep to the top 3-5 threats"
            )

    # -- Section 10: Tenant boundaries (optional; multi-tenant only) ------------
    b = body("10. Tenant boundaries")
    if b is not None:
        cols, rows = parse_table(b)
        if cols is None:
            errors.append("section 10 present but has no tenant-boundaries table")
        elif cols != BOUNDARY_COLUMNS:
            errors.append(f"section 10 columns must be {BOUNDARY_COLUMNS}, got {cols}")
        else:
            boundary_ids = []
            for r in rows:
                if len(r) != len(BOUNDARY_COLUMNS):
                    errors.append(
                        f"section 10 row has {len(r)} cells, "
                        f"expected {len(BOUNDARY_COLUMNS)}: {r[:2]}"
                    )
                    continue
                row = dict(zip(BOUNDARY_COLUMNS, r, strict=False))
                bid = row["boundary_id"]
                if not BOUNDARY_ID.match(bid):
                    errors.append(f"section 10 boundary_id '{bid}' must match IF-<number>")
                elif bid in boundary_ids:
                    errors.append(f"section 10 duplicate boundary_id '{bid}'")
                boundary_ids.append(bid)
                for field, enum in (
                    ("kind", BOUNDARY_KIND_ENUM),
                    ("exposure", BOUNDARY_EXPOSURE_ENUM),
                    ("complexity", BOUNDARY_COMPLEXITY_ENUM),
                ):
                    if row[field] not in enum:
                        errors.append(
                            f"section 10 {bid}: {field} '{row[field]}' not in {sorted(enum)}"
                        )
                for dim in ISOLATION_DIMENSIONS:
                    if row[dim] not in DIMENSION_RESULT_ENUM:
                        errors.append(
                            f"section 10 {bid}: {dim} '{row[dim]}' "
                            f"not in {sorted(DIMENSION_RESULT_ENUM)}"
                        )
                for tid in re.split(r"[,;]\s*", row["threat_ids"]):
                    tid = tid.strip()
                    if tid and tid not in threat_ids:
                        errors.append(f"section 10 {bid}: references unknown threat id '{tid}'")
                ref = row["isolation_review_ref"].strip()
                if ref and not ISOLATION_REVIEW_REF.match(ref):
                    errors.append(
                        f"section 10 {bid}: isolation_review_ref '{ref}' must "
                        f"be empty or an isolation-review artifact id"
                    )

    # -- Section 11: Risk ratings (required when section 4 is OWASP-rated) -----
    b = body("11. Risk ratings")
    rated = {
        tid: row for tid, row in rated_rows.items() if row["severity"] != threat_rating.UNRATED
    }
    if b is None:
        if rated:
            errors.append(
                f"section 11 (Risk ratings) is missing; it must list the factor "
                f"scores for rated threats {sorted(rated)}"
            )
    else:
        errors += _lint_risk_ratings(b, rated, threat_ids)

    return errors, warnings


def _rating_subsections(body_lines):
    """Split section 11 into (threat id, heading line, body lines)."""
    out, current = [], None
    for line in body_lines:
        if line.startswith("### "):
            m = threat_rating.RATING_HEADING.match(line)
            current = (m.group(1) if m else None, line.strip(), [])
            out.append(current)
        elif current is not None:
            current[2].append(line)
    return out


def _lint_risk_ratings(body_lines, rated, threat_ids):
    """Section 11: every rated threat has a factor table that reproduces the
    severity, levels and scores its section 4 row states."""
    errors = []
    seen = []
    for tid, heading, sub in _rating_subsections(body_lines):
        if tid is None:
            errors.append(f"section 11 heading '{heading}' must start '### T<n>'")
            continue
        where = f"section 11 {tid}"
        if tid in seen:
            errors.append(f"{where}: duplicate subsection")
            continue
        seen.append(tid)
        if tid not in threat_ids:
            errors.append(f"{where}: references unknown threat id")
            continue
        if tid not in rated:
            errors.append(f"{where}: section 4 does not rate this threat")
            continue
        cols, rows = parse_table(sub)
        if cols != threat_rating.FACTOR_COLUMNS:
            errors.append(f"{where}: columns must be {threat_rating.FACTOR_COLUMNS}, got {cols}")
            continue
        scores = {}
        for r in rows:
            if len(r) != len(cols):
                errors.append(f"{where}: row has {len(r)} cells, expected {len(cols)}: {r[:1]}")
                continue
            name, value = r[0], r[1]
            if name not in threat_rating.ALL_FACTORS:
                errors.append(f"{where}: unknown factor '{name}'")
            elif name in scores:
                errors.append(f"{where}: factor '{name}' listed twice")
            elif not re.fullmatch(r"\d", value):
                errors.append(f"{where}: factor '{name}' score '{value}' must be 0-9")
            else:
                scores[name] = int(value)
        stated = threat_rating.parse_row(rated[tid])
        if stated["severity_source"] != "owasp":
            continue  # the section 4 cell errors already say why
        rating, problems = threat_rating.rating_from_factors(scores, stated["impact_basis"])
        errors += [f"{where}: {p}" for p in problems]
        if rating is None:
            continue
        computed = threat_rating.parse_row(
            {
                "severity": rating["severity"],
                "likelihood": threat_rating.likelihood_cell(rating),
                "impact": threat_rating.impact_cell(rating),
            }
        )
        for key in ("severity", "likelihood", "impact", "likelihood_score", "impact_score"):
            if computed[key] != stated[key]:
                errors.append(
                    f"{where}: factors give {key} {computed[key]!r}, section 4 says {stated[key]!r}"
                )
        heading_severity = heading.split("—")[-1].strip() if "—" in heading else None
        if heading_severity and heading_severity != rating["severity"]:
            errors.append(
                f"{where}: heading says '{heading_severity}', factors give '{rating['severity']}'"
            )
    for tid in sorted(set(rated) - set(seen)):
        errors.append(f"section 11 has no factor table for rated threat {tid}")
    return errors


def collect(paths):
    files = []
    for p in paths:
        p = Path(p)
        if p.is_dir():
            # Directory sweeps skip pipeline scratch under any artifacts/
            # component (per-worker THREAT_MODEL.md drafts are working
            # files, not portfolio artifacts). Explicit file paths are
            # always linted.
            found = sorted(
                set(list(p.rglob("THREAT_MODEL.md")) + list(p.rglob("*-threat-model.md")))
            )
            files.extend(f for f in found if "artifacts" not in f.relative_to(p).parts)
        else:
            files.append(p)
    return [f for f in files if not f.is_symlink()]
