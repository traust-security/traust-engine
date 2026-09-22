"""Owner-response SLA views (C10) — clocks over the findings projection.

SLAs are POLICY DATA, never code: this script ships with a default
SLA policy file (`configs/sla-policy.yaml`, schema-validated against
contracts/schemas/sla-policy.schema.json) and takes ANY other policy — customer
contract SLAs, per-BU policies, FedRAMP profiles — via `--policy <file>`.
To change an SLA, swap the file, never edit this script. The
severity_mapping inside the policy is likewise data: policy-specific
Critical/Important/Moderate/Low labels and the harness severity enum are
different vocabularies and their join must stay auditable.

Reads the C9 findings database (a projection — build it first with
traust corpus findings-db; the census is the denominator authority).
Per open finding, the SLA clock starts at (`clock_start` ladder,
first_routed_or_filed):
    1. earliest routing/filing ledger event (none exist in today's
       corpus — the rung is implemented for when Jira-filing events land)
    2. earliest ledger event (occurred_at)
    3. the report's audit date
Findings with none of these are counted `unclocked`, never guessed.
`resolve_days: null` severities are tracked but can never be overdue.
Resolved findings score compliance: resolved_at (latest resolving event)
vs the due date.

The escalation digest in the .md output is GENERATED, NEVER AUTO-SENT —
routing it to individuals requires human review.

Each digest row also carries the product registry's accountable
contact when the row's product/repo resolves at a trustworthy tier
(`mapped` or `repo-url` — `slug` is advisory and this artifact is
unattended, so no slug guess ever lands here). Accountable contacts are
escalation paths, not owners, and only tier 1 is embargo-cleared — the
flag is copied from traust_engine.registry.products, never synthesised.
The registry is an optional corroborating source: an absent or off-VPN
cache degrades to `accountable_contact: null` per row and a
`source_status: unavailable` in the metadata, never a failed run.

Usage:
    traust metrics sla [--db <findings.db>]
        [--policy <yaml>] [--profile <name>] [--as-of YYYY-MM-DD]
        [--out-dir <dir>] [--pd-cache-dir <dir>]
"""

from __future__ import annotations

import datetime as dt
import json
import sqlite3
import sys
from pathlib import Path

from traust_contracts.paths import schema_dir as _schema_dir

from traust_engine.assets import harness_version
from traust_engine.escaping import md_cell
from traust_engine.registry import products as pd

SCHEMA_DIR = _schema_dir()

try:
    import yaml
except ImportError:
    yaml = None


SCHEMA_PATH = SCHEMA_DIR / "sla-policy.schema.json"

# ledger source types that count as "routed or filed" (ladder rung 1).
# None are emitted by today's flows; the rung activates when Jira-filing
# events reach the ledger.
FILING_SOURCE_TYPES = ("jira_filing", "filing", "routing", "owner_assignment")

RESOLVING = ("resolved", "fix_verified")

# accountable-contact match tiers that may feed the digest. slug is
# advisory-only by product_definitions.py doctrine and stays out.
TRUSTED_TIERS = ("mapped", "repo-url")


def load_product_context(cache_dir: Path | None, map_path: Path | None = None) -> dict:
    """Registry indexes for the accountable-contact join, or a stub.

    Never raises and never exits: the registry is an optional
    corroborating source, and a missing cache (off VPN) must degrade to
    null contacts, not a failed run.
    """
    if cache_dir is None:
        return {
            "status": "unavailable",
            "source": {"detail": "feeds cache not configured"},
            "idx": None,
            "mappings": {},
        }
    status, source, doc = pd._source_block(cache_dir)
    ctx = {"status": status, "source": source, "idx": None, "mappings": {}}
    if doc is not None:
        ctx["idx"] = pd.build_indexes(doc)
        ctx["mappings"], _ = pd.load_mappings(map_path)
    return ctx


def accountable_contact(
    ctx: dict | None, product: str | None, repo_url: str | None, memo: dict
) -> dict | None:
    """Best-tier registry contact for one digest row, or None.

    embargo_cleared is copied from the resolver (tier 1 only, by
    construction) — never computed here.
    """
    if not ctx or not ctx["idx"]:
        return None
    key = (product or "", repo_url or "")
    if key in memo:
        return memo[key]
    res = None
    if product:
        got = pd.resolve_package(ctx["idx"], product, ctx["mappings"])
        if got["match_tier"] == "mapped":
            res = got
    if res is None and repo_url:
        mapped = (ctx["mappings"].get("repos") or {}).get(repo_url) or (
            ctx["mappings"].get("repos") or {}
        ).get(pd.norm_repo_url(repo_url))
        res = (
            pd.resolve_product(ctx["idx"], mapped, "mapped") if mapped else None
        ) or pd.resolve_repo_url(ctx["idx"], repo_url)
    contact = None
    if res and res["match_tier"] in TRUSTED_TIERS and res["contacts"]:
        best = res["contacts"][0]  # ladder-sorted: best tier first
        contact = {
            "kerberos_id": best["kerberos_id"],
            "tier": best["tier"],
            "field": best["field"],
            "embargo_cleared": best["embargo_cleared"],
            "ps_product": (res["ps_products"][0] if res["ps_products"] else None),
            "match_tier": res["match_tier"],
        }
    memo[key] = contact
    return contact


def load_policy(path: Path) -> dict:
    if yaml is None:
        sys.exit("PyYAML is required to load the SLA policy")
    policy = yaml.safe_load(path.read_text(encoding="utf-8"))
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    try:
        import jsonschema

        jsonschema.validate(policy, schema)
    except ImportError:
        # minimal structural gate when jsonschema is unavailable
        for k in ("policy_name", "source", "severity_mapping", "profiles"):
            if k not in policy:
                sys.exit(f"policy missing required key: {k}")
        if not policy["profiles"]:
            sys.exit("policy has no profiles")
    except jsonschema.ValidationError as e:
        sys.exit(f"policy fails contracts/schemas/sla-policy.schema.json: {e.message}")
    return policy


def pick_profile(policy: dict, name: str | None) -> tuple[str, dict]:
    profiles = policy["profiles"]
    if name:
        if name not in profiles:
            sys.exit(f"profile '{name}' not in policy (has: {', '.join(sorted(profiles))})")
        return name, profiles[name]
    for n, p in profiles.items():
        if p.get("default"):
            return n, p
    n = sorted(profiles)[0]
    return n, profiles[n]


def _date(s: str | None) -> dt.date | None:
    if not s:
        return None
    try:
        return dt.date.fromisoformat(s[:10])
    except ValueError:
        return None


def resolve_days_for(profile: dict, severity: str, cvss: float | None) -> int | str | None:
    """SLA days, None (no SLA), or 'unclocked' (severity not in profile)."""
    floor = profile.get("cvss_floor_days")
    if floor and cvss is not None and cvss >= floor["threshold"]:
        return floor["resolve_days"]
    slas = profile["slas"]
    if severity not in slas:
        return "unclocked"
    return slas[severity]["resolve_days"]


def clock_start(
    events: list[tuple], audit_date: str | None, mode: str
) -> tuple[dt.date | None, str]:
    """(start_date, basis) per the policy's clock_start ladder."""
    dates = sorted(d for d in (_date(occ) or _date(rec) for occ, rec, _ in events) if d)
    if mode == "first_routed_or_filed":
        filed = sorted(
            d
            for occ, rec, st in events
            if st in FILING_SOURCE_TYPES
            for d in (_date(occ) or _date(rec),)
            if d
        )
        if filed:
            return filed[0], "filed"
    if mode in ("first_routed_or_filed", "first_event") and dates:
        return dates[0], "first_event"
    ad = _date(audit_date)
    if ad:
        return ad, "audit_date"
    return None, "unclocked"


def build_view(
    db_path: Path,
    policy: dict,
    profile_name: str,
    profile: dict,
    as_of: dt.date,
    pd_ctx: dict | None = None,
) -> dict:
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    built_at = con.execute("SELECT value FROM meta WHERE key='built_at'").fetchone()
    mode = policy.get("clock_start", "first_routed_or_filed")

    events_by_finding: dict[tuple, list] = {}
    resolved_at: dict[tuple, dt.date] = {}
    for r in con.execute(
        "SELECT repo_key, finding_id, occurred_at, recorded_at, source_type, resolution FROM events"
    ):
        k = (r["repo_key"], r["finding_id"])
        events_by_finding.setdefault(k, []).append(
            (r["occurred_at"], r["recorded_at"], r["source_type"])
        )
        if r["resolution"] in RESOLVING:
            d = _date(r["occurred_at"]) or _date(r["recorded_at"])
            if d and (k not in resolved_at or d > resolved_at[k]):
                resolved_at[k] = d

    # owner team per repo (repo-graph owned-by: owner-team -> repo),
    # best-effort; tolerate either edge direction
    owners = {}
    for r in con.execute(
        "SELECT r.repo_key, ge.from_id AS owner FROM repos r "
        "JOIN graph_edges ge ON ge.rel='owned-by' "
        "AND ge.to_id = 'repo:' || "
        "REPLACE(REPLACE(COALESCE(r.repo_url,''),'https://',''),"
        "'.git','') "
        "UNION "
        "SELECT r.repo_key, ge.to_id AS owner FROM repos r "
        "JOIN graph_edges ge ON ge.rel='owned-by' "
        "AND ge.from_id = 'repo:' || "
        "REPLACE(REPLACE(COALESCE(r.repo_url,''),'https://',''),"
        "'.git','')"
    ):
        owners[r["repo_key"]] = r["owner"].split(":", 1)[-1]

    rows = con.execute(
        "SELECT f.repo_key, f.finding_id, f.severity, f.cvss_score, "
        "f.resolution, f.validity, f.title, r.ownership, "
        "r.business_unit, r.label, r.is_branch_audit, r.audit_date, "
        "r.product, r.repo_url "
        "FROM findings f JOIN repos r USING (repo_key) "
        "WHERE COALESCE(f.validity,'confirmed') NOT IN "
        "('false_positive','withdrawn','refuted','hardening') "
        "AND r.is_branch_audit = 0"
    ).fetchall()
    con.close()

    counters = {
        "open_in_sla": 0,
        "open_overdue": 0,
        "open_no_sla": 0,
        "unclocked": 0,
        "resolved_met": 0,
        "resolved_breached": 0,
        "resolved_unclocked": 0,
        "out_of_profile_scope": 0,
    }
    overdue_by_sev: dict[str, int] = {}
    overdue_by_team: dict[str, dict] = {}
    days_to_resolve: dict[str, list] = {}
    escalations = []
    contact_memo: dict = {}

    for r in rows:
        sev = (r["severity"] or "informational").lower()
        days = resolve_days_for(profile, sev, r["cvss_score"])
        if days == "unclocked":
            # severity outside this profile's scope (e.g. informational
            # under the default SLA policy; critical/high/low under
            # the profile's severity map — the CVSS floor may still
            # have caught them)
            counters["out_of_profile_scope"] += 1
            continue
        k = (r["repo_key"], r["finding_id"])
        start, basis = clock_start(events_by_finding.get(k, []), r["audit_date"], mode)
        is_resolved = (r["resolution"] or "open") == "resolved" or k in resolved_at

        if start is None:
            counters["resolved_unclocked" if is_resolved else "unclocked"] += 1
            continue
        if days is None:
            if not is_resolved:
                counters["open_no_sla"] += 1
            continue
        due = start + dt.timedelta(days=days)

        if is_resolved:
            rd = resolved_at.get(k)
            if rd is None:
                counters["resolved_unclocked"] += 1
                continue
            met = rd <= due
            counters["resolved_met" if met else "resolved_breached"] += 1
            days_to_resolve.setdefault(sev, []).append((rd - start).days)
        elif due < as_of:
            counters["open_overdue"] += 1
            overdue_by_sev[sev] = overdue_by_sev.get(sev, 0) + 1
            team = owners.get(r["repo_key"]) or "(unassigned)"
            t = overdue_by_team.setdefault(team, {"total": 0, "critical": 0, "worst_days": 0})
            t["total"] += 1
            if sev == "critical":
                t["critical"] += 1
            t["worst_days"] = max(t["worst_days"], (as_of - due).days)
            escalations.append(
                {
                    "repo_key": r["repo_key"],
                    "finding_id": r["finding_id"],
                    "severity": sev,
                    "title": (r["title"] or "")[:120],
                    "owner_team": team,
                    "due": due.isoformat(),
                    "days_overdue": (as_of - due).days,
                    "clock_basis": basis,
                    "accountable_contact": accountable_contact(
                        pd_ctx, r["product"], r["repo_url"], contact_memo
                    ),
                }
            )
        else:
            counters["open_in_sla"] += 1

    med = {sev: sorted(v)[len(v) // 2] for sev, v in days_to_resolve.items() if v}
    escalations.sort(
        key=lambda e: (
            -{"critical": 3, "high": 2, "medium": 1}.get(e["severity"], 0),
            -e["days_overdue"],
        )
    )
    total_scored = counters["resolved_met"] + counters["resolved_breached"]
    return {
        "metadata": {
            "artifact": "sla-view",
            "role": (
                "owner-response SLA clocks over the findings "
                "projection; policy is data (--policy), the census "
                "remains the denominator authority, and the "
                "escalation digest is generated, never auto-sent."
            ),
            "harness_version": harness_version(),
            "db": str(db_path),
            "db_built_at": built_at[0] if built_at else None,
            "policy_name": policy["policy_name"],
            "policy_source": policy["source"],
            "profile": profile_name,
            "clock_start": mode,
            "as_of": as_of.isoformat(),
            "product_definitions": {
                "source_status": (pd_ctx["status"] if pd_ctx else "unavailable"),
                "retrieved_at": ((pd_ctx or {}).get("source") or {}).get("retrieved_at"),
                "age_hours": ((pd_ctx or {}).get("source") or {}).get("age_hours"),
            },
        },
        "summary": {
            **counters,
            "resolved_sla_compliance_pct": (
                round(100 * counters["resolved_met"] / total_scored, 1) if total_scored else None
            ),
            "median_days_to_resolve_by_severity": med,
            "overdue_by_severity": dict(sorted(overdue_by_sev.items())),
        },
        "overdue_by_team": dict(sorted(overdue_by_team.items(), key=lambda kv: -kv[1]["total"])),
        "escalation_digest": escalations[:100],
    }


def render_md(view: dict) -> str:
    m, s = view["metadata"], view["summary"]
    L = []
    A = L.append
    A(f"# SLA View — {m['policy_name']} / {m['profile']}")
    A("")
    A(
        f"_As of {m['as_of']} · policy source: {m['policy_source']['name']} "
        f"(retrieved {m['policy_source']['retrieved']}) · findings DB "
        f"built {m['db_built_at']} · clock start: {m['clock_start']}._"
    )
    A(
        "_The census remains the denominator authority; SLAs are policy "
        "data — swap the file via `--policy`, never the code._"
    )
    A("")
    A("| Metric | Count |")
    A("|---|---:|")
    A(f"| Open, within SLA | {s['open_in_sla']:,} |")
    A(f"| **Open, overdue** | **{s['open_overdue']:,}** |")
    A(f"| Open, no SLA (policy: tracked, never overdue) | {s['open_no_sla']:,} |")
    A(f"| Unclocked (no event and no audit date) | {s['unclocked']:,} |")
    A(f"| Outside this profile's severity scope | {s['out_of_profile_scope']:,} |")
    A(f"| Resolved within SLA | {s['resolved_met']:,} |")
    A(f"| Resolved past SLA | {s['resolved_breached']:,} |")
    if s["resolved_sla_compliance_pct"] is not None:
        A(f"| Resolved-SLA compliance | {s['resolved_sla_compliance_pct']}% |")
    A("")
    if s["overdue_by_severity"]:
        A(
            "**Overdue by severity:** "
            + ", ".join(f"{k}: {v:,}" for k, v in s["overdue_by_severity"].items())
        )
        A("")
    if s["median_days_to_resolve_by_severity"]:
        A(
            "**Median days-to-resolve (resolved findings):** "
            + ", ".join(
                f"{k}: {v}d" for k, v in sorted(s["median_days_to_resolve_by_severity"].items())
            )
        )
        A("")
    teams = view["overdue_by_team"]
    if teams:
        A("## Overdue by owner team")
        A("")
        A("| Team | Overdue | Critical | Worst (days over) |")
        A("|---|---:|---:|---:|")
        for team, t in list(teams.items())[:25]:
            A(f"| {md_cell(team)} | {t['total']:,} | {t['critical']:,} | {t['worst_days']:,} |")
        A("")
    esc = view["escalation_digest"]
    if esc:
        A("## Escalation digest (generated — human review before any routing)")
        A("")
        A(
            "_Accountable contacts are escalation paths, not owners; only "
            "tier 1 is embargo-cleared. Verify accountable contacts via your "
            "employee verification tool before acting on one._"
        )
        A("")
        A("| Finding | Severity | Team | Accountable | Days overdue | Clock basis |")
        A("|---|---|---|---|---:|---|")
        for e in esc[:25]:
            ac = e.get("accountable_contact")
            acc = f"`{ac['kerberos_id']}` (pd t{ac['tier']})" if ac else "—"
            A(
                f"| {md_cell(e['repo_key'])}#{md_cell(e['finding_id'])} | {e['severity']} | "
                f"{md_cell(e['owner_team'])} | {md_cell(acc)} | {e['days_overdue']:,} | "
                f"{e['clock_basis']} |"
            )
        A("")
    return "\n".join(L) + "\n"


def write_sla_artifacts(view: dict, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "sla-view.json").write_text(json.dumps(view, indent=2) + "\n", encoding="utf-8")
    (out_dir / "sla-view.md").write_text(render_md(view), encoding="utf-8")
