"""
Validate security report JSON files against contracts/schemas/report.schema.json.

Usage:
  traust reporting validate findings/report.json
  traust reporting validate findings/
  traust reporting validate --strict findings/report.json
"""

import json
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from datetime import date as date_type
from pathlib import Path
from urllib.parse import urlparse

import jsonschema
from referencing import Registry, Resource
from traust_contracts.paths import schema_dir as _schema_dir

from traust_engine._util.actor import is_actor_verified as _actor_is_verified

SCHEMA_DIR = _schema_dir()
SCHEMA_PATH = SCHEMA_DIR / "report.schema.json"

MANDATORY_SEVERITY_LEVELS = {"critical", "high", "medium", "low"}

# Canonical globally-unique finding ID: {REPO_SLUG}-{SHORTSHA}-{NNN}
CANONICAL_FINDING_ID = re.compile(r"^[A-Z][A-Z0-9_]{0,23}-[a-f0-9]{7}-\d{3}$")

# The one runnable form of the identity tool. `traust_engine._util.finding_identity`
# has not existed since the code moved into this package, and the "Fix:"
# lines below get copy-pasted by whoever hit the error.
_IDENTITY_CMD = "python3 -m traust_engine._util.finding_identity"
# Harness version at which canonical IDs become mandatory.
CANONICAL_ID_MIN_VERSION = (0, 12, 0)
# Harness version at which the 0.15.0 consistency conventions become
# mandatory: peach_isolation_review present, validation_status set on every
# finding, category drawn from RECOMMENDED_CATEGORIES, loc_breakdown present.
# Derived from a portfolio drift audit of 5,488 reports (2026-07-08): these
# fields oscillated per batch prompt whenever the validator did not pin them.
CONSISTENCY_MIN_VERSION = (0, 15, 0)

# Recommended finding-category vocabulary (kebab-case). Free text remains
# schema-valid, but strict mode warns on values outside this set for reports
# from harness >= CONSISTENCY_MIN_VERSION so cross-report aggregation stays
# lossless. Compare via _normalize_category().
RECOMMENDED_CATEGORIES = {
    "injection",
    "authentication",
    "authorization",
    "secrets-management",
    "supply-chain",
    "insecure-workload-config",
    "network-exposure",
    "cryptography",
    "input-validation",
    "path-traversal",
    "cross-site-scripting",
    "ssrf",
    "resource-management",
    "logging-monitoring",
    "data-exposure",
    "tenant-isolation",
}


def _normalize_category(value: str) -> str:
    """Lowercase and kebab-case a category value for vocabulary comparison."""
    return re.sub(r"[\s_]+", "-", value.strip().lower())


def _parse_harness_version(meta: dict) -> tuple[int, int, int] | None:
    """Extract (major, minor, patch) from metadata.additional.harness_version
    (format 'X.Y.Z' or 'X.Y.Z-<sha>'). Returns None if absent/unparseable."""
    hv = (meta.get("additional") or {}).get("harness_version")
    if not hv:
        return None
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)", str(hv))
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


@dataclass
class ValidationResult:
    file_path: str
    errors: list = field(default_factory=list)
    warnings: list = field(default_factory=list)

    def error(self, msg: str):
        self.errors.append(msg)

    def warn(self, msg: str):
        self.warnings.append(msg)

    @property
    def passed(self) -> bool:
        return len(self.errors) == 0

    def print_report(self):
        name = Path(self.file_path).name
        if self.passed and not self.warnings:
            print(f"  PASS  {name}")
            return
        tag = "PASS" if self.passed else "FAIL"
        parts = []
        if self.errors:
            parts.append(f"{len(self.errors)} error(s)")
        if self.warnings:
            parts.append(f"{len(self.warnings)} warning(s)")
        print(f"  {tag}  {name} ({', '.join(parts)})")
        for e in self.errors:
            print(f"        ERROR: {e}")
        for w in self.warnings:
            print(f"        WARN:  {w}")


def _format_path(path) -> str:
    """Turn a jsonschema path deque into a readable dotted path."""
    parts = []
    for p in path:
        if isinstance(p, int):
            parts.append(f"[{p}]")
        else:
            parts.append(f".{p}" if parts else str(p))
    return "".join(parts) or "(root)"


def load_schema(path: Path = SCHEMA_PATH) -> dict:
    with Path(path).open(encoding="utf-8") as f:
        return json.load(f)


def build_registry() -> Registry:
    """Resolve cross-file $ref (e.g. validation.schema.json -> report.schema.json)."""
    reg = Registry()
    schema_files = sorted(SCHEMA_DIR.glob("*.schema.json"))
    if not schema_files:
        raise FileNotFoundError(
            f"no schemas under {SCHEMA_DIR} — contracts/ submodule not "
            "initialized? run `git submodule update --init`"
        )
    for sf in schema_files:
        doc = json.loads(sf.read_text(encoding="utf-8"))
        res = Resource.from_contents(doc)
        reg = reg.with_resource(uri=doc.get("$id", sf.name), resource=res)
    return reg


def cross_validate(report: dict, result: ValidationResult):
    finding_ids = [f["id"] for f in report.get("findings", [])]
    finding_id_set = set(finding_ids)

    # 1. Finding ID uniqueness
    dupes = [fid for fid, cnt in Counter(finding_ids).items() if cnt > 1]
    for fid in dupes:
        result.error(f"Duplicate finding ID: {fid}")

    # 2. Severity criteria completeness
    defined_levels = {c["level"] for c in report.get("severity_criteria", [])}
    for level in sorted(MANDATORY_SEVERITY_LEVELS - defined_levels):
        result.error(f"Severity criteria missing mandatory level: {level}")

    # 3. Severity count consistency
    actual_counts = Counter(f["severity"] for f in report.get("findings", []))
    for entry in report.get("findings_summary", []):
        sev = entry["severity"]
        expected = actual_counts.get(sev, 0)
        declared = entry["count"]
        if declared != expected:
            result.error(
                f"findings_summary[{sev}]: count is {declared}, "
                f"but {expected} finding(s) have severity '{sev}'"
            )
        if len(entry["finding_ids"]) != declared:
            result.error(
                f"findings_summary[{sev}]: count is {declared}, "
                f"but finding_ids has {len(entry['finding_ids'])} entries"
            )

    # 4. Summary IDs reference valid findings (and all findings are covered)
    all_summary_ids = set()
    for entry in report.get("findings_summary", []):
        for fid in entry["finding_ids"]:
            if fid not in finding_id_set:
                result.error(f"findings_summary references unknown finding ID: {fid}")
            all_summary_ids.add(fid)
    missing = finding_id_set - all_summary_ids
    if missing:
        result.error(f"Findings not listed in any findings_summary entry: {sorted(missing)}")

    # 5. Roadmap addresses reference valid findings
    for item in report.get("remediation_roadmap", []):
        for fid in item.get("addresses", []):
            if fid not in finding_id_set:
                result.error(f"remediation_roadmap references unknown finding ID: {fid}")

    # 6. Executive summary severity_counts match actual findings
    es_counts = report.get("executive_summary", {}).get("severity_counts", {})
    for sev, declared in es_counts.items():
        expected = actual_counts.get(sev, 0)
        if declared != expected:
            result.error(
                f"executive_summary.severity_counts[{sev}]: declared {declared}, "
                f"but {expected} finding(s) have severity '{sev}'"
            )

    # 7. PEACH isolation review: finding_ids reference valid findings; if
    #    applicable == false, no interfaces and no per-finding peach_references
    peach = report.get("peach_isolation_review")
    if peach is not None:
        if not peach.get("applicable"):
            if peach.get("interfaces"):
                result.error(
                    "peach_isolation_review.applicable is false but interfaces[] is non-empty"
                )
            for i, f in enumerate(report.get("findings", [])):
                if f.get("peach_references"):
                    result.error(
                        f"findings[{i}] ({f.get('id')}): peach_references set but "
                        f"peach_isolation_review.applicable is false"
                    )
        for iface in peach.get("interfaces") or []:
            for fid in iface.get("finding_ids") or []:
                if fid not in finding_id_set:
                    result.error(
                        f"peach_isolation_review.interfaces[{iface.get('name')}] "
                        f"references unknown finding ID: {fid}"
                    )

    # 8. metadata.loc_breakdown internal consistency
    lb = report.get("metadata", {}).get("loc_breakdown")
    if lb and lb.get("by_language"):
        lang_sum = sum(lb["by_language"].values())
        if lang_sum != lb.get("total"):
            result.warn(
                f"metadata.loc_breakdown: by_language sums to {lang_sum} "
                f"but total is {lb.get('total')}"
            )

    # 8b. metadata.repository must be a single clean URL. Legacy converter
    #     output carried markdown-autolink angle brackets, multi-URL prose,
    #     and bare names — 26 of the PQC triage's 109 "unreachable" repos
    #     (2026-07-18) were exactly this defect breaking ls-remote
    #     inventories. Warn (not error) so historical reports keep
    #     validating; new reports get flagged at authoring time.
    _repo_raw = str((report.get("metadata") or {}).get("repository") or "")
    if _repo_raw:
        if _repo_raw.startswith("<") or _repo_raw.rstrip().endswith(">"):
            result.warn(
                "metadata.repository is wrapped in angle brackets "
                f"({_repo_raw!r}) — strip the markdown autolink wrapper"
            )
        elif re.search(r"[;\s]", _repo_raw.strip()):
            result.warn(
                "metadata.repository contains whitespace/multiple URLs "
                f"({_repo_raw[:80]!r}) — use exactly one repository URL"
            )
        elif not re.match(r"^(https?://|git@)", _repo_raw.strip()):
            result.warn(
                f"metadata.repository ({_repo_raw[:80]!r}) is not a URL — "
                "use the full https:// (or git@) repository URL"
            )

    # 9. Canonical globally-unique finding IDs. Hard-enforced when the report
    #    was produced by harness >= CANONICAL_ID_MIN_VERSION; otherwise a
    #    warning so pre-0.12.0 reports keep validating.
    meta = report.get("metadata", {})
    hv = _parse_harness_version(meta)
    enforce = hv is not None and hv >= CANONICAL_ID_MIN_VERSION
    commit = meta.get("commit", "")
    shortsha = re.match(r"^[a-f0-9]{7}", str(commit).lower())
    for i, f in enumerate(report.get("findings", [])):
        fid = f.get("id", "")
        if CANONICAL_FINDING_ID.match(fid):
            if shortsha and f"-{shortsha.group(0)}-" not in fid:
                result.warn(
                    f"findings[{i}] ({fid}): SHORTSHA segment does not match "
                    f"metadata.commit ({shortsha.group(0)})"
                )
            continue
        msg = (
            f"findings[{i}] ({fid}): non-canonical finding ID — expected "
            f"{{REPO_SLUG}}-{{SHORTSHA}}-{{NNN}} "
            f"(e.g. EXAMPLE_PROXY-abc1234-001)"
        )
        if enforce:
            result.error(msg + f" [harness_version {'.'.join(map(str, hv))} >= 0.12.0]")
        else:
            result.warn(msg + " [legacy report — re-audit to migrate]")
    if enforce and not commit:
        result.error(
            "metadata.commit is required for harness >= 0.12.0 "
            "(SHORTSHA component of canonical finding IDs)"
        )

    # 10. 0.15.0 consistency conventions. Hard-enforced when the report was
    #     produced by harness >= CONSISTENCY_MIN_VERSION; earlier reports keep
    #     validating (strict mode surfaces the equivalent warnings).
    if hv is not None and hv >= CONSISTENCY_MIN_VERSION:
        if "peach_isolation_review" not in report:
            result.error(
                "peach_isolation_review is required for harness >= 0.15.0 — "
                "record {applicable: false, rationale: <why>} for "
                "single-tenant components"
            )
        for i, f in enumerate(report.get("findings", [])):
            if "validation_status" not in f:
                result.error(
                    f"findings[{i}] ({f.get('id', '?')}): validation_status is "
                    "required for harness >= 0.15.0 — audit-stage findings "
                    "default to 'not_verified'"
                )

    # 11. Disposition-block consistency (cumulative reports produced by the
    #     track-findings skill; no-op for audit-stage reports).
    _cross_validate_dispositions(report, result)


from traust_engine.ledger import compute_claim_hash, compute_event_id


def cross_validate_layer(
    report: dict,
    result: ValidationResult,
    merkle_pubkey: str | None = None,
    signing_pubkey: Path | None = None,
):
    """Cross-checks specific to layer.schema.json disposition ledgers."""
    events = report.get("events", [])

    # 1. event_id integrity: recomputable from canonical fields, and unique.
    #    A mismatched hash means the event was edited after the fact or the
    #    id was fabricated — either breaks idempotent re-ingestion.
    seen_ids = Counter(e.get("event_id") for e in events)
    for eid, cnt in seen_ids.items():
        if cnt > 1:
            result.error(f"Duplicate event_id: {eid}")
    for i, e in enumerate(events):
        disp = e.get("disposition") or {}
        expected = compute_event_id(
            (e.get("source") or {}).get("ref", ""),
            e.get("finding_ref", ""),
            disp.get("validity"),
            disp.get("resolution"),
        )
        if e.get("event_id") != expected:
            result.error(
                f"events[{i}] ({e.get('finding_ref')}): event_id does not match "
                f"sha256(source.ref|finding_ref|validity|resolution) — expected "
                f"{expected}"
            )

    # 2. Append-only implies chronological order — and no time travel in
    #    either direction. recorded_at is self-declared by the emitter
    #    (--recorded-at), and adjudication is latest-wins within an
    #    evidence class: a FUTURE-dated event would outrank every later
    #    legitimate event forever (self-audit -015). Allow 24h of clock
    #    skew; beyond that the timestamp is a forgery or a broken clock,
    #    both of which must fail the gate.
    prev_dt = None
    horizon = datetime.now(UTC) + timedelta(hours=24)
    for i, e in enumerate(events):
        try:
            dt = datetime.fromisoformat(str(e.get("recorded_at", "")))
        except ValueError:
            dt = None  # malformed dates are rejected by the schema
        if dt is not None and prev_dt is not None and dt < prev_dt:
            result.error(
                f"events[{i}]: recorded_at is earlier than the previous event — "
                f"the layer is append-only and must stay chronological"
            )
        if dt is not None and dt.tzinfo is not None and dt > horizon:
            result.error(
                f"events[{i}]: recorded_at '{e.get('recorded_at')}' is more "
                f"than 24h in the future — a future-dated event would pin "
                f"latest-wins adjudication forever"
            )
        if dt is not None:
            prev_dt = dt

    # 3. Human-identity rule: a human false_positive determination must be
    #    attributable — LDAP-verified identity required. Machine events may
    #    carry validity 'false_positive' (refutation evidence) but the build
    #    script never lets them set validation_status.
    for i, e in enumerate(events):
        disp = e.get("disposition") or {}
        actor = (e.get("source") or {}).get("actor") or {}
        if (
            disp.get("validity") == "false_positive"
            and actor.get("kind") == "human"
            and (not actor.get("identity") or not _actor_is_verified(actor))
        ):
            result.error(
                f"events[{i}] ({e.get('finding_ref')}): human false_positive "
                f"determination requires a verified identity "
                f"(actor.identity set and identity verified)"
            )

    # 3a2. Severity overrides are HUMAN-only: a machine actor may never
    #      carry disposition.severity (harness >= 0.128.0). Human severity
    #      events need the same LDAP-verified attribution as human FPs,
    #      plus a rationale — a severity change without a why is not
    #      recordable.
    for i, e in enumerate(events):
        disp = e.get("disposition") or {}
        actor = (e.get("source") or {}).get("actor") or {}
        if disp.get("severity"):
            if actor.get("kind") != "human":
                result.error(
                    f"events[{i}] ({e.get('finding_ref')}): "
                    f"disposition.severity is a human-only override — "
                    f"machine actors may not set severity"
                )
            elif not actor.get("identity") or not _actor_is_verified(actor):
                result.error(
                    f"events[{i}] ({e.get('finding_ref')}): human severity "
                    f"override requires a verified identity"
                )
            if not (e.get("rationale") or "").strip():
                result.error(
                    f"events[{i}] ({e.get('finding_ref')}): severity override requires a rationale"
                )

    # 3a3. Embargo assertions are HUMAN-only, on the same footing as
    #      severity: whether a finding warrants embargoed handling is a
    #      disclosure-risk judgement, never a machine verdict, and an
    #      embargo call without a why is not recordable.
    #
    #      This rule existed briefly in the harness's own validate_report.py
    #      and was lost when that module was deleted in the C8 restructure,
    #      leaving `disposition.embargo`'s schema description asserting
    #      validator enforcement that nothing performed. Re-landed here,
    #      where validation now lives.
    for i, e in enumerate(events):
        disp = e.get("disposition") or {}
        actor = (e.get("source") or {}).get("actor") or {}
        if disp.get("embargo"):
            if actor.get("kind") != "human":
                result.error(
                    f"events[{i}] ({e.get('finding_ref')}): "
                    f"disposition.embargo is a human-only assertion — "
                    f"machine actors may not set embargo"
                )
            elif not actor.get("identity") or not _actor_is_verified(actor):
                result.error(
                    f"events[{i}] ({e.get('finding_ref')}): human embargo "
                    f"assertion requires a verified identity"
                )
            if not (e.get("rationale") or "").strip():
                result.error(
                    f"events[{i}] ({e.get('finding_ref')}): embargo assertion requires a rationale"
                )

    # 3b. occurred_at (source timestamp) should not postdate recorded_at
    #     (ledger append time) — that means one of them is wrong.
    for i, e in enumerate(events):
        occ, rec = e.get("occurred_at"), e.get("recorded_at")
        if occ and rec and str(occ) > str(rec):
            result.warn(
                f"events[{i}] ({e.get('finding_ref')}): occurred_at '{occ}' is "
                f"later than recorded_at '{rec}' — a determination cannot "
                f"happen after it was recorded"
            )

    # 5. Baseline claim-hash verification — tamper-evidence for the audit
    #    report the layer annotates. metadata.claim_hashes pins each
    #    baselined finding's claim fields; a mismatch means the audit file
    #    was edited in place (only 'corrected' findings may drift, pending
    #    an explicit --rebaseline via the harness's baseline_claims.py
    #    (harnessing/4-triage/track-findings/scripts/)).
    meta = report.get("metadata") or {}
    hashes = meta.get("claim_hashes") or {}
    if hashes:
        audit_path = Path(result.file_path).parent / str(meta.get("audit_report", ""))
        if not audit_path.is_file():
            result.warn(
                f"metadata.claim_hashes present but the audit report "
                f"'{meta.get('audit_report')}' was not found next to the layer "
                f"— baseline integrity could not be verified"
            )
        else:
            try:
                audit = json.loads(audit_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as e:
                audit = None
                result.warn(f"cannot read audit report for claim verification: {e}")
            if audit is not None:
                by_id = {f.get("id"): f for f in audit.get("findings", [])}
                for fid, recorded in sorted(hashes.items()):
                    f = by_id.get(fid)
                    if f is None:
                        result.error(
                            f"claim_hashes[{fid}]: baselined finding is missing "
                            f"from the audit report — findings must never be "
                            f"deleted or re-id'd; retire them via the ledger"
                        )
                    elif compute_claim_hash(f) != recorded:
                        if f.get("validation_status") == "corrected":
                            result.warn(
                                f"claim_hashes[{fid}]: claim drifted but the "
                                f"finding is marked 'corrected' — re-baseline "
                                f"it: baseline_claims.py record --rebaseline {fid}"
                            )
                        else:
                            result.error(
                                f"claim_hashes[{fid}]: claim hash mismatch — "
                                f"the finding was edited in place without a "
                                f"'corrected' revision; the audit report is "
                                f"the immutable claim source, changes flow "
                                f"through the ledger"
                            )
                unbaselined = sorted(set(by_id) - set(hashes))
                if unbaselined:
                    result.warn(
                        f"{len(unbaselined)} audit finding(s) not yet baselined "
                        f"in claim_hashes (new appends?) — run "
                        f"baseline_claims.py record to pin them: "
                        f"{', '.join(unbaselined[:5])}" + ("…" if len(unbaselined) > 5 else "")
                    )

    # 4. Confirmed review items must have produced an event from their source
    event_refs = {(e.get("source") or {}).get("ref") for e in events}
    for i, item in enumerate(report.get("needs_review", [])):
        if item.get("status") == "confirmed" and item.get("source_ref") not in event_refs:
            result.error(
                f"needs_review[{i}]: status is 'confirmed' but no event "
                f"references source_ref '{item.get('source_ref')}'"
            )
        if item.get("status") in ("confirmed", "rejected") and not item.get("resolution_note"):
            result.warn(
                f"needs_review[{i}]: {item.get('status')} without a "
                f"resolution_note — record why and by whom"
            )

    _cross_validate_merkle(report, result, merkle_pubkey, signing_pubkey)


def check_metadata_repository(report: dict, result: ValidationResult):
    """`metadata.repository` must be a well-formed repository URL.

    It is the FIRST field of the fingerprint payload
    (`sha256(canon_repo | sorted paths | primary_cwe)`), so a malformed value
    silently produces a wrong cross-scan identity — and under the 3D decision a
    downstream consumer reads that stamp as authoritative rather than computing
    its own. The field is schema-typed as a bare string with no pattern, and
    `canon_repo(None)` returns "", so a report with no repository stamps happily
    over an empty repo component.

    Measured 2026-08-13 before the P0.2 migration: 258 audit reports carried a
    malformed value — 211 wrapped in markdown autolink brackets
    (`<https://github.com/org/repo>`, hashing the brackets too), 2 missing the
    scheme, and 45 pointing at an ORG rather than a repo.

    An ERROR as of 2026-08-13. It shipped as a warning only because 45 org-level
    stub reports would otherwise have failed the corpus — shipping a gate the
    corpus fails is how a check gets reverted instead of respected. Those stubs
    were dropped in a prior corpus cleanup, the corpus now holds **zero**
    malformed values, so the gate can enforce.
    """
    repo = (report.get("metadata") or {}).get("repository")
    if repo is None or not str(repo).strip():
        result.error(
            "metadata.repository is absent — it is the first field of the "
            "cross-scan fingerprint, so an empty value silently produces a "
            "wrong identity. Set it from the caller, not from the model."
        )
        return
    s = str(repo).strip()
    if s.startswith("<") and s.endswith(">"):
        result.error(
            f"metadata.repository is wrapped in markdown autolink brackets "
            f"({s[:60]}) — the brackets are hashed into the fingerprint. "
            f"Strip them and re-run {_IDENTITY_CMD} fingerprint <report.json> --write."
        )
        return
    if not _REPO_URL_RE.match(s):
        result.error(
            f"metadata.repository {s[:60]!r} does not look like a "
            f"<scheme>://<host>/<org>/<repo> URL — it is the first field of "
            f"the cross-scan fingerprint, so a malformed value yields a wrong "
            f"identity."
        )


_REPO_URL_RE = re.compile(r"^https://[a-z0-9.-]+/[^/]+/.+$", re.I)


def _default_signing_pubkey(pubkey: Path | None = None) -> str | None:
    """Return ``str(pubkey)`` when injected by the engine facade, else None."""
    return str(pubkey) if pubkey is not None else None


def _cross_validate_merkle(
    report: dict,
    result: ValidationResult,
    pubkey_path: str | None = None,
    signing_pubkey: Path | None = None,
) -> None:
    from traust_engine.ledger import (
        Severity,
        verify_merkle_integrity,
        verify_merkle_signature,
    )

    for finding in verify_merkle_integrity(report):
        if finding.severity == Severity.ERROR:
            result.error(finding.message)
        else:
            result.warn(finding.message)

    pubkey = pubkey_path or _default_signing_pubkey(signing_pubkey)
    for finding in verify_merkle_signature(report, pubkey):
        if finding.severity == Severity.ERROR:
            result.error(finding.message)
        else:
            result.warn(finding.message)


def _cross_validate_dispositions(report: dict, result: ValidationResult):
    """Disposition-block consistency for cumulative reports produced by the
    track-findings skill. No-op for audit-stage reports (no disposition data)."""
    findings = report.get("findings", [])
    ds = report.get("disposition_summary")
    with_disposition = [f for f in findings if "disposition" in f]

    if ds is None and not with_disposition:
        return
    if ds is not None and len(with_disposition) != len(findings):
        result.error(
            "disposition_summary present but "
            f"{len(findings) - len(with_disposition)} finding(s) have no "
            "disposition block — cumulative reports must disposition every finding"
        )
    if ds is None:
        result.warn("findings carry disposition blocks but disposition_summary is absent")

    # validation_status must mirror the disposition validity axis
    for i, f in enumerate(findings):
        disp = f.get("disposition")
        if disp and disp.get("validity") != f.get("validation_status"):
            result.error(
                f"findings[{i}] ({f.get('id', '?')}): validation_status "
                f"'{f.get('validation_status')}' does not equal "
                f"disposition.validity '{disp.get('validity')}'"
            )

    if ds is None:
        return

    # Count consistency
    res_counts = Counter(f["disposition"].get("resolution") for f in with_disposition)
    for key, declared in (ds.get("by_resolution") or {}).items():
        if res_counts.get(key, 0) != declared:
            result.error(
                f"disposition_summary.by_resolution[{key}]: declared {declared}, "
                f"but {res_counts.get(key, 0)} finding(s) have that resolution"
            )
    val_counts = Counter(f["disposition"].get("validity") for f in with_disposition)
    for key, declared in (ds.get("by_validity") or {}).items():
        if val_counts.get(key, 0) != declared:
            result.error(
                f"disposition_summary.by_validity[{key}]: declared {declared}, "
                f"but {val_counts.get(key, 0)} finding(s) have that validity"
            )

    # Conflicts list must match per-finding conflict flags
    flagged = {f["id"] for f in with_disposition if f["disposition"].get("conflict")}
    listed = set(ds.get("conflicts") or [])
    for fid in sorted(flagged - listed):
        result.error(
            f"finding {fid} has disposition.conflict but is not in disposition_summary.conflicts"
        )
    for fid in sorted(listed - flagged):
        result.error(
            f"disposition_summary.conflicts lists {fid} but that "
            f"finding's disposition.conflict is not true"
        )


def cross_validate_cloud_config_current(report: dict, result: ValidationResult):
    """Cross-checks specific to cloud-config-findings-current.schema.json
    cumulative reports (build_cumulative.py over a *-cloud-config-audit.json
    baseline).

    Errors are limited to what build_cumulative.py deterministically
    guarantees (finding-ID uniqueness, effective_severity derivation, the
    disposition/summary invariants). Summary counts copied through from the
    audit baseline drifted across vintages in the real corpus (2026-07
    survey: 4/91 status-count and 6/91 gaps-count mismatches), so those are
    warnings, not errors."""
    findings = report.get("findings", [])

    # 1. Finding ID uniqueness
    ids = [f.get("id") for f in findings]
    for fid, cnt in Counter(ids).items():
        if cnt > 1:
            result.error(f"Duplicate finding ID: {fid}")

    # 2. effective_severity derivation: severity_override wins, else severity
    for i, f in enumerate(findings):
        ov = (f.get("disposition") or {}).get("severity_override")
        expected = ov["severity"] if ov else f.get("severity")
        if f.get("effective_severity") != expected:
            result.error(
                f"findings[{i}] ({f.get('id', '?')}): effective_severity "
                f"'{f.get('effective_severity')}' does not equal the "
                f"{'severity_override' if ov else 'original severity'} "
                f"'{expected}'"
            )

    # 3. Audit-baseline summary counts (copied through by build_cumulative;
    #    vintage drift observed in the corpus — warn only)
    summary = report.get("summary") or {}
    status_counts = Counter(f.get("status") for f in findings)
    for key in ("confirmed", "suppressed", "needs_review"):
        declared = summary.get(key)
        actual = status_counts.get(key, 0)
        if declared is not None and declared != actual:
            result.warn(
                f"summary.{key}: declared {declared}, but {actual} finding(s) have status '{key}'"
            )
    if "gaps" in summary and summary.get("gaps") != len(report.get("gaps", [])):
        result.warn(
            f"summary.gaps: declared {summary.get('gaps')}, but gaps[] has "
            f"{len(report.get('gaps', []))} entries"
        )

    # 4. Disposition-block invariants (validation_status mirrors
    #    disposition.validity; disposition_summary counts and conflict list
    #    reconcile) — shared with code-audit cumulative reports.
    _cross_validate_dispositions(report, result)


def cross_validate_remediation(report: dict, result: ValidationResult):
    """Cross-checks specific to remediation.schema.json reports."""
    findings = report.get("source_findings", [])
    patch = report.get("patch", {})
    checks = report.get("checks", [])
    summary = report.get("summary", {})

    # 1. summary.findings_addressed matches len(source_findings)
    declared = summary.get("findings_addressed")
    if declared is not None and declared != len(findings):
        result.error(
            f"summary.findings_addressed: declared {declared}, "
            f"but source_findings has {len(findings)} entries"
        )

    # 2. summary checks_passed/total match checks[]
    passed = sum(1 for c in checks if c.get("outcome") == "pass")
    if summary.get("checks_passed") != passed:
        result.error(
            f"summary.checks_passed: declared {summary.get('checks_passed')}, "
            f"but {passed} check(s) have outcome 'pass'"
        )
    if summary.get("checks_total") != len(checks):
        result.error(
            f"summary.checks_total: declared {summary.get('checks_total')}, "
            f"but checks[] has {len(checks)} entries"
        )

    # 3. diffstat.files matches len(files_changed)
    fc = patch.get("files_changed", [])
    ds = patch.get("diffstat", {})
    if ds.get("files") != len(fc):
        result.error(
            f"patch.diffstat.files: declared {ds.get('files')}, "
            f"but files_changed has {len(fc)} entries"
        )

    # 4. Every source_findings[].locations[].path is touched by patch.files_changed
    changed_paths = {f["path"] for f in fc}
    for sf in findings:
        for loc in sf.get("locations", []):
            if loc.get("path") not in changed_paths:
                result.warn(
                    f"source_findings[{sf['finding_ref']}] location "
                    f"'{loc.get('path')}' is not in patch.files_changed — "
                    f"verify the fix actually addresses this site"
                )

    # 5. Status consistency  (skip is a non-signal — tool unavailable — and is
    #    compatible with checks_passed; only an actual 'fail' contradicts it)
    failed = sum(1 for c in checks if c.get("outcome") == "fail")
    status = summary.get("status")
    if status == "checks_passed" and failed > 0:
        result.error("summary.status is 'checks_passed' but not all checks passed")
    if status == "checks_failed" and failed == 0:
        result.error("summary.status is 'checks_failed' but all checks passed")
    rev = report.get("revalidation", {})
    if status == "revalidated_fixed" and not rev.get("fixed"):
        result.error("summary.status is 'revalidated_fixed' but revalidation.fixed is not true")
    if status in ("pr_opened", "merged") and "pull_request" not in report:
        result.error(f"summary.status is '{status}' but no pull_request block present")

    # 6. fork.upstream_remote should match metadata.repository
    fork = report.get("fork", {})
    meta = report.get("metadata", {})
    upstream = fork.get("upstream_remote")
    if (
        upstream
        and meta.get("repository")
        and upstream.rstrip("/").removesuffix(".git")
        != meta["repository"].rstrip("/").removesuffix(".git")
    ):
        result.warn(
            f"fork.upstream_remote ({upstream}) does not match "
            f"metadata.repository ({meta['repository']})"
        )

    # 7. PR target safety — automated remediation must never target upstream directly
    pr = report.get("pull_request", {})
    if pr.get("target") == "upstream":
        result.warn(
            "pull_request.target is 'upstream' — automated remediation should open "
            "PRs against private-fork or downstream only; upstream disclosure is a "
            "separate human-driven step"
        )

    # 8. diff_path should exist relative to the report (warn only)
    dp = patch.get("diff_path")
    if dp:
        rp = Path(result.file_path).parent / dp
        if not rp.exists():
            result.warn(f"patch.diff_path '{dp}' not found at {rp}")


def cross_validate_validation(report: dict, result: ValidationResult):
    """Cross-checks specific to validation.schema.json reports."""
    # 1. summary.by_verdict matches validated_findings[].verdict counts
    actual = Counter(f["verdict"] for f in report.get("validated_findings", []))
    declared = report.get("summary", {}).get("by_verdict", {})
    for v, n in declared.items():
        if actual.get(v, 0) != n:
            result.error(
                f"summary.by_verdict[{v}]: declared {n}, "
                f"but {actual.get(v, 0)} validated_findings have verdict '{v}'"
            )
    # 2. attack_chains[].steps[].finding_ref reference known validated findings
    known = {f["source_id"] for f in report.get("validated_findings", [])}
    for c in report.get("attack_chains", []):
        for s in c.get("steps", []):
            ref = s.get("finding_ref")
            if ref and ref not in known:
                result.warn(
                    f"attack_chains[{c['chain_id']}] step references unknown finding '{ref}'"
                )
    # 3. novel_findings IDs must not collide with source finding IDs
    for nf in report.get("novel_findings", []):
        if nf["id"] in known:
            result.error(f"novel_findings[{nf['id']}] collides with source finding ID")
    # 4. execution_log_ref should exist relative to the report (warn only)
    log_ref = report.get("execution_log_ref")
    if log_ref:
        rp = Path(result.file_path).parent / log_ref
        if not rp.exists():
            result.warn(f"execution_log_ref '{log_ref}' not found at {rp}")


def cross_validate_triage(report: dict, result: ValidationResult):
    """Cross-checks specific to triage.schema.json reports.

    Machine-enforces the verdict-taxonomy invariants introduced in harness
    0.24.0: hardening gaps (exclusion rule 13) and undetermined findings
    must never be recorded as false positives, false positives must carry
    positive evidence of wrongness, and summary counts must reconcile.
    """
    findings = report.get("findings", [])
    summary = report.get("summary", {})

    # 1. Finding ID uniqueness
    ids = [f.get("id") for f in findings]
    for fid, cnt in Counter(ids).items():
        if cnt > 1:
            result.error(f"Duplicate triage finding ID: {fid}")
    id_set = set(ids)

    # 2. Summary counts reconcile with the findings array
    verdicts = Counter(f.get("verdict") for f in findings)
    declared = {
        "input_count": len(findings),
        "true_positives": verdicts.get("true_positive", 0),
        "hardening": verdicts.get("hardening", 0),
        "false_positives": verdicts.get("false_positive", 0),
        "undetermined": verdicts.get("undetermined", 0),
        "duplicates": verdicts.get("duplicate", 0),
    }
    for key, actual in declared.items():
        if summary.get(key) != actual:
            result.error(f"summary.{key}: declared {summary.get(key)}, but findings show {actual}")

    # 3. by_severity reconciles with confirmed true positives
    sev_actual = Counter(
        str(f.get("severity", "")).lower()
        for f in findings
        if f.get("verdict") == "true_positive" and f.get("severity")
    )
    for level, n in (summary.get("by_severity") or {}).items():
        if sev_actual.get(level, 0) != n:
            result.error(
                f"summary.by_severity[{level}]: declared {n}, but "
                f"{sev_actual.get(level, 0)} true positives have that severity"
            )

    for i, f in enumerate(findings):
        fid = f.get("id", f"findings[{i}]")
        verdict = f.get("verdict")
        rule = f.get("exclusion_rule")
        rule_s = str(rule) if rule is not None else None

        # 4. Rule 13 IS the hardening verdict — in both directions
        if verdict == "hardening" and rule_s != "13":
            result.error(
                f"{fid}: verdict 'hardening' requires exclusion_rule 13 "
                f"(got {rule_s!r}) — hardening is defined by rule 13"
            )
        if verdict == "false_positive" and rule_s == "13":
            result.error(
                f"{fid}: verdict 'false_positive' with exclusion_rule 13 — "
                "rule-13 (missing-hardening-only) findings must be verdict "
                "'hardening', never false positives"
            )

        # 5. A false positive claim requires positive evidence of wrongness
        if verdict == "false_positive" and not f.get("refute_reasons"):
            result.error(
                f"{fid}: verdict 'false_positive' with empty refute_reasons — "
                "refutation requires evidence"
            )

        # 6. Undetermined means nothing was decided
        if verdict == "undetermined":
            conf = f.get("confidence")
            if conf not in (None, 0, 0.0) and f.get("verify_verdict") != "needs_manual_test":
                result.error(
                    f"{fid}: verdict 'undetermined' with confidence {conf} and "
                    "verify_verdict != needs_manual_test — undetermined findings "
                    "carry no confident conclusion"
                )

        # 7. Derived severity only on confirmed true positives
        if verdict != "true_positive" and f.get("severity") is not None:
            result.error(
                f"{fid}: severity {f['severity']!r} set on verdict "
                f"'{verdict}' — derived severity applies to true positives only"
            )

        # 8. Duplicates reference a real, non-duplicate canonical
        if verdict == "duplicate":
            target = f.get("duplicate_of")
            if not target:
                result.error(f"{fid}: verdict 'duplicate' without duplicate_of")
            elif target not in id_set:
                result.error(f"{fid}: duplicate_of '{target}' is not a known finding id")
            else:
                canon = next(x for x in findings if x.get("id") == target)
                if canon.get("verdict") == "duplicate":
                    result.error(f"{fid}: duplicate_of '{target}' is itself a duplicate")

        # 9. Verdict should agree with a strict vote majority (warn only:
        #    noise-tolerance policies may legitimately override splits)
        vb = f.get("vote_breakdown")
        if isinstance(vb, dict) and verdict in ("true_positive", "hardening", "false_positive"):
            countable = {k: vb.get(k, 0) for k in ("true_positive", "hardening", "false_positive")}
            total = sum(countable.values())
            if total:
                top_verdict, top_votes = max(countable.items(), key=lambda kv: kv[1])
                if top_votes * 2 > total and top_verdict != verdict:
                    result.warn(
                        f"{fid}: verdict '{verdict}' contradicts strict vote "
                        f"majority '{top_verdict}' ({countable}) — confirm a "
                        "noise-tolerance policy justified the override"
                    )

    # 10. Canonical orig_id hygiene: if the batch is traust-sourced (most
    #     orig_ids canonical), stragglers are probably transcription errors
    orig_ids = [f.get("orig_id") for f in findings if f.get("orig_id")]
    canonical = [o for o in orig_ids if CANONICAL_FINDING_ID.match(str(o))]
    if orig_ids and len(canonical) >= len(orig_ids) / 2:
        for o in orig_ids:
            if not CANONICAL_FINDING_ID.match(str(o)):
                result.warn(
                    f"orig_id '{o}' is not canonical while most of the batch is "
                    "— check for a transcription error"
                )


def cross_validate_impact_analysis(report: dict, result: ValidationResult):
    """Cross-checks specific to impact-analysis.schema.json reports."""
    repos = report.get("repos", [])
    summary = report.get("summary", {})

    # 1. Summary counts reconcile with repos array
    class_counts = Counter(r.get("classification") for r in repos)
    declared = {
        "affected": class_counts.get("affected", 0),
        "likely_affected": class_counts.get("likely_affected", 0),
        "not_observed": class_counts.get("not_observed", 0),
        "version_not_in_range": class_counts.get("version_not_in_range", 0),
        "not_imported": class_counts.get("not_imported", 0),
        "inconclusive": class_counts.get("inconclusive", 0),
    }
    for key, actual in declared.items():
        if summary.get(key) != actual:
            result.error(f"summary.{key}: declared {summary.get(key)}, but repos show {actual}")

    # 2. repos_in_blast_radius should equal len(repos)
    if summary.get("repos_in_blast_radius") != len(repos):
        result.error(
            f"summary.repos_in_blast_radius: declared "
            f"{summary.get('repos_in_blast_radius')}, but repos[] has "
            f"{len(repos)} entries"
        )

    # 3. version_in_range consistency
    in_range = sum(
        1
        for r in repos
        if r.get("classification") != "version_not_in_range"
        and r.get("classification") != "not_imported"
    )
    if summary.get("version_in_range") != in_range:
        result.warn(
            f"summary.version_in_range: declared "
            f"{summary.get('version_in_range')}, expected {in_range} "
            f"(repos - version_not_in_range - not_imported)"
        )

    # 4. Repo ID uniqueness
    repo_ids = [r.get("repo") for r in repos]
    for rid, cnt in Counter(repo_ids).items():
        if cnt > 1:
            result.error(f"Duplicate repo entry: {rid}")

    # 5. Evidence consistency per classification
    for i, r in enumerate(repos):
        rid = r.get("repo", f"repos[{i}]")
        cls = r.get("classification")
        ev = r.get("evidence", {})
        if cls == "affected" and not (
            ev.get("govulncheck") == "symbol_reachable"
            or (ev.get("feature_pattern_matches") or 0) > 0
        ):
            result.warn(
                f"{rid}: classification 'affected' without "
                "govulncheck symbol_reachable or feature_pattern_matches > 0"
            )
        if cls == "version_not_in_range" and ev.get("l1_version_in_range") is True:
            result.error(
                f"{rid}: classification 'version_not_in_range' but l1_version_in_range is true"
            )


def cross_validate_vuln_findings(report: dict, result: ValidationResult):
    """Cross-checks specific to vuln-findings.schema.json reports.

    Machine-enforces the vuln-scan output contract (harness >= 0.38.0):
    finding IDs must be unique and derive from the scan's own
    repo_slug/scanned_ref, summary counts must reconcile, and baseline
    bookkeeping must be internally consistent.
    """
    findings = report.get("findings", [])
    known = report.get("known_findings", []) or []
    summary = report.get("summary", {})
    meta = report.get("metadata", {})

    # 1. Finding ID uniqueness
    ids = [f.get("id") for f in findings]
    for fid, cnt in Counter(ids).items():
        if cnt > 1:
            result.error(f"Duplicate finding ID: {fid}")

    # 2. IDs derive from this scan's identity
    slug = meta.get("repo_slug")
    ref = str(meta.get("scanned_ref", ""))[:7]
    if slug and ref:
        prefix = f"{slug}-{ref}-"
        for fid in ids:
            if fid and not str(fid).startswith(prefix):
                result.error(
                    f"{fid}: id does not start with '{prefix}' — finding IDs "
                    "must derive from metadata.repo_slug + scanned_ref"
                )

    # 3. Summary counts reconcile
    sev_actual = Counter(str(f.get("severity", "")).lower() for f in findings)
    declared = {
        "total": len(findings),
        "critical": sev_actual.get("critical", 0),
        "high": sev_actual.get("high", 0),
        "medium": sev_actual.get("medium", 0),
        "low": sev_actual.get("low", 0),
        "informational": sev_actual.get("informational", 0),
        "known": len(known),
        "low_confidence": sum(
            1
            for f in findings
            if isinstance(f.get("confidence"), (int, float)) and f["confidence"] < 0.4
        ),
    }
    for key, actual in declared.items():
        if summary.get(key) != actual:
            result.error(f"summary.{key}: declared {summary.get(key)}, but findings show {actual}")

    # 4. Baseline bookkeeping: no baseline means nothing to dedupe against
    if meta.get("baseline") is None:
        if known:
            result.error(
                f"{len(known)} known_findings recorded but metadata.baseline "
                "is null — known findings must match a baseline audit"
            )
        if meta.get("baseline_findings"):
            result.error("metadata.baseline_findings > 0 but metadata.baseline is null")


def cross_validate_verification(report: dict, result: ValidationResult):
    """Cross-checks specific to verification.schema.json reports.

    Automates the consistency checklist from the verify-remediation skill's
    Phase 7a: verdict counts, finding coverage, commit attribution
    consistency, timeline ordering, and regression ID hygiene.
    """
    findings = report.get("verified_findings", [])
    regressions = report.get("regressions", [])
    timeline = report.get("commit_timeline", [])
    summary = report.get("summary", {})
    meta = report.get("metadata", {})

    # 1. original_id uniqueness
    ids = [f.get("original_id") for f in findings]
    for fid, cnt in Counter(ids).items():
        if cnt > 1:
            result.error(f"Duplicate verified_findings original_id: {fid}")
    known_ids = set(ids)

    # 1b. Cross-repo fix honesty: an upstream fix the original repo has
    # not consumed cannot resolve the finding — the product still ships
    # the vulnerable version. (Two-legged rule; see verify-remediation
    # SKILL.md "Cross-repo fixes".)
    for f in findings:
        cr = f.get("cross_repo")
        if not cr:
            continue
        if cr.get("propagation") == "pending" and f.get("verdict") == "resolved":
            result.error(
                f"{f.get('original_id')}: verdict 'resolved' with "
                f"cross_repo.propagation 'pending' — the fix in "
                f"{cr.get('fix_repo')} is not consumed by this repo; use "
                f"'partially_resolved' (ledger maps it to fix_in_progress)"
            )
        if (
            cr.get("fix_repo")
            and meta.get("repository")
            and cr["fix_repo"].rstrip("/").lower() == str(meta["repository"]).rstrip("/").lower()
        ):
            result.error(
                f"{f.get('original_id')}: cross_repo.fix_repo equals "
                f"metadata.repository — cross_repo is for fixes in a "
                f"DIFFERENT repo; drop the block for same-repo fixes"
            )

    # 2. summary.total_findings matches verified_findings length
    declared_total = summary.get("total_findings")
    if declared_total is not None and declared_total != len(findings):
        result.error(
            f"summary.total_findings: declared {declared_total}, "
            f"but verified_findings has {len(findings)} entries"
        )

    # 3. summary.by_verdict matches actual verdict counts
    actual = Counter(f.get("verdict") for f in findings)
    for v, n in (summary.get("by_verdict") or {}).items():
        if actual.get(v, 0) != n:
            result.error(
                f"summary.by_verdict[{v}]: declared {n}, "
                f"but {actual.get(v, 0)} verified_findings have verdict '{v}'"
            )

    # 4. summary.regressions matches regressions[] length
    declared_reg = summary.get("regressions")
    if declared_reg is not None and declared_reg != len(regressions):
        result.error(
            f"summary.regressions: declared {declared_reg}, "
            f"but regressions[] has {len(regressions)} entries"
        )

    # 5. Per-finding verdict/attribution consistency
    for i, f in enumerate(findings):
        fid = f.get("original_id", "?")
        verdict = f.get("verdict")
        commits = f.get("remediation_commits") or []
        unattributed = f.get("unattributed")
        if commits and unattributed:
            result.error(
                f"verified_findings[{i}] ({fid}): unattributed is true but "
                f"remediation_commits is non-empty"
            )
        if (
            not commits
            and not unattributed
            and verdict in ("resolved", "partially_resolved", "new_approach", "regression")
        ):
            result.error(
                f"verified_findings[{i}] ({fid}): verdict '{verdict}' requires "
                f"remediation_commits, or unattributed: true with an explanation"
            )
        if verdict in ("false_positive", "risk_accepted") and not f.get("disposition_rationale"):
            result.error(
                f"verified_findings[{i}] ({fid}): verdict '{verdict}' requires "
                f"disposition_rationale (who made the determination and why)"
            )
        if verdict == "partially_resolved" and not f.get("residual_risk"):
            result.error(
                f"verified_findings[{i}] ({fid}): verdict 'partially_resolved' "
                f"requires residual_risk"
            )
        if verdict == "new_approach" and not f.get("residual_risk"):
            result.warn(
                f"verified_findings[{i}] ({fid}): verdict 'new_approach' should "
                f"describe residual_risk (or state there is none)"
            )
        for c in commits:
            if not str(c.get("sha", "")).startswith(str(c.get("short_sha", ""))):
                result.error(
                    f"verified_findings[{i}] ({fid}): remediation commit "
                    f"short_sha '{c.get('short_sha')}' is not a prefix of "
                    f"sha '{c.get('sha')}'"
                )

    # 6. Commit timeline: chronological order, sha consistency, known IDs
    prev_dt = None
    for i, t in enumerate(timeline):
        if not str(t.get("full_sha", "")).startswith(str(t.get("sha", ""))):
            result.error(
                f"commit_timeline[{i}]: sha '{t.get('sha')}' is not a prefix "
                f"of full_sha '{t.get('full_sha')}'"
            )
        for fid in t.get("addresses") or []:
            if fid not in known_ids:
                result.error(f"commit_timeline[{i}] references unknown finding ID: {fid}")
        try:
            dt = datetime.fromisoformat(str(t.get("date", "")))
        except ValueError:
            dt = None  # malformed dates are rejected by the schema
        if dt is not None and prev_dt is not None and dt < prev_dt:
            result.error(
                f"commit_timeline[{i}] ({t.get('sha')}): entries are not in chronological order"
            )
        if dt is not None:
            prev_dt = dt

    # 7. remediation_commits and commit_timeline should agree (warn only —
    #    the timeline is an aggregation of the per-finding attributions)
    attributed_shas = {c.get("sha") for f in findings for c in (f.get("remediation_commits") or [])}
    timeline_shas = {t.get("full_sha") for t in timeline}
    for sha in sorted(attributed_shas - timeline_shas):
        result.warn(f"remediation commit {sha} is not in commit_timeline")
    for sha in sorted(timeline_shas - attributed_shas):
        result.warn(
            f"commit_timeline entry {sha} does not appear in any finding's remediation_commits"
        )

    # 8. Regression SHORTSHA segment should match metadata.patched_commit
    patched = str(meta.get("patched_commit", ""))[:7]
    for i, r in enumerate(regressions):
        rid = r.get("id", "")
        if patched and f"-{patched}-REG-" not in rid:
            result.warn(
                f"regressions[{i}] ({rid}): SHORTSHA segment does not match "
                f"metadata.patched_commit ({patched})"
            )

    # 8b. routed_id (traust route regressions, harness >= 0.196.0):
    #     the routed campaign finding is minted at the patched sha, and one
    #     regression routes to exactly one baseline finding.
    routed_seen = Counter(r.get("routed_id") for r in regressions if r.get("routed_id"))
    for rid, cnt in routed_seen.items():
        if cnt > 1:
            result.error(
                f"regressions: routed_id {rid} assigned to "
                f"{cnt} regressions — routing must be one-to-one"
            )
    for i, r in enumerate(regressions):
        routed = r.get("routed_id")
        if routed and patched and f"-{patched}-" not in routed:
            result.warn(
                f"regressions[{i}] ({r.get('id')}): routed_id {routed} "
                f"SHORTSHA segment does not match metadata.patched_commit "
                f"({patched})"
            )

    # 9. Verifying a repo against itself is almost always an input mistake
    if meta.get("original_commit") and meta.get("original_commit") == meta.get("patched_commit"):
        result.warn(
            "metadata.original_commit equals patched_commit — the 'patched' "
            "code is identical to what was audited"
        )


# CIS/STIG recommendation-title phrasing. Report findings must cite bare
# section IDs ("CIS 5.1.3") with original prose — copied benchmark text is a
# content-license violation (docs/external-dependencies.md). Corpus-verified
# 2026-07-16: zero hits across 5,000+ reports, so any hit is new text.
CIS_CONTROL_TEXT_RE = re.compile(
    r"[Ee]nsure that the [^\n]{0,80}?(argument|parameter|plugin) is set"
)


# Code-profile reports from this version on record the fate of each
# deterministic pre-scan so evidence quality is comparable across a batch
# (docs/report-structure.md, code-profile deltas).
DETERMINISTIC_STEPS_MIN_VERSION = (0, 60, 1)


# Mirrors build_org_index.py's parse_org_repo() acceptance rules: the
# org-index and repo-graph attribute reports to repos via this field, so a
# value they cannot parse makes the report invisible to org navigation.
_REPO_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_REPO_HOST_RE = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$")


def _repository_parses(url: str) -> bool:
    url = url.strip().strip("<>")
    try:
        parsed = urlparse(url if "://" in url else "https://" + url)
    except ValueError:
        return False
    parts = [p for p in parsed.path.split("/") if p]
    return (
        len(parts) >= 2
        and _REPO_HOST_RE.match((parsed.hostname or "").lower()) is not None
        and all(_REPO_SEGMENT_RE.match(p) and any(c.isalnum() for c in p) for p in parts)
    )


def check_finding_identity(report: dict, result: ValidationResult):
    """Every finding carries the deterministic cross-scan fingerprint.

    `fingerprint` is schema-declared and pattern-constrained but OPTIONAL,
    so a report that never ran the stamp step validates clean while being
    invisible to every cross-scan consumer: continuation matching,
    disposition carry-forward, and the downstream platform's finding
    identity all key on it.

    Two distinct failures, two severities:

    * ABSENT -> error (P6 flip, 2026-08-13 — corpus is 100% stamped).
    * MISMATCH -> error. Recompute-and-compare against traust-ledger.
    """
    findings = report.get("findings") or []
    if not findings:
        return

    missing = [f.get("id", "?") for f in findings if not f.get("fingerprint")]
    if missing:
        shown = ", ".join(missing[:5]) + ("..." if len(missing) > 5 else "")
        result.error(
            f"{len(missing)} of {len(findings)} finding(s) have no cross-scan "
            f"`fingerprint` ({shown}) — cross-scan continuation, disposition "
            f"carry-forward and the downstream platform's identity all key on "
            f"it. Fix: {_IDENTITY_CMD} "
            f"fingerprint <report.json> --write"
        )

    try:
        from traust_engine.ledger import fingerprint as _fingerprint
    except ImportError:
        result.warn(
            "cannot import traust_engine.ledger — `fingerprint` values were "
            "checked for presence but NOT verified against the recipe"
        )
        return

    repo = (report.get("metadata") or {}).get("repository")
    wrong = []
    for f in findings:
        stored = f.get("fingerprint")
        if not stored:
            continue
        try:
            expected = _fingerprint(f, repo)
        except Exception as e:
            result.warn(f"finding {f.get('id', '?')}: cannot recompute `fingerprint` ({e})")
            continue
        if stored != expected:
            wrong.append((f.get("id", "?"), stored, expected))

    if wrong:
        shown = ", ".join(fid for fid, _, _ in wrong[:5]) + ("..." if len(wrong) > 5 else "")
        fid, got, exp = wrong[0]
        result.error(
            f"{len(wrong)} of {len(findings)} finding(s) carry a `fingerprint` "
            f"that the recipe does not produce ({shown}) — the stamp was not "
            f"written by the ledger identity recipe, so it is not a cross-scan "
            f"identity and must not be trusted as one. First mismatch {fid}: "
            f"stored {got[:16]}…, recomputed {exp[:16]}…. Fix: "
            f"{_IDENTITY_CMD} fingerprint <report.json> --write "
            f"(this CHANGES those findings' identity — check disposition "
            f"continuity before re-stamping)"
        )


def strict_checks(report: dict, result: ValidationResult):
    # No identity check here: check_finding_identity already ERRORS on an
    # absent or non-reproducing stamp on the DEFAULT path (P6 flip,
    # 2026-08-13, once the corpus reached 100% stamped). A strict re-scan
    # would report the same defect twice, and the comment that used to sit
    # here — "advisory by default, an error under --strict" — outlived the
    # behaviour it described.

    # write-time secret gate: evidence fields may quote target code, but an
    # UNREDACTED live secret in a report is an incident, not evidence — strict mode
    # makes it a validation ERROR. Redact via traust_engine._util.redact
    # (first-5-chars + ...REDACTED) before writing.
    try:
        from traust_engine._util.redact import HIGH_CONFIDENCE, scan_text

        hits = scan_text(json.dumps(report, ensure_ascii=False))
        for h in hits:
            msg = (
                f"Strict: unredacted secret-shaped value in report "
                f"(class={h['category']}, prefix={h['match_prefix']!r})"
                " — redact at write time (traust_engine._util.redact)"
            )
            if h["category"] in HIGH_CONFIDENCE:
                result.error(msg)  # structured token: near-certain live
            else:
                result.warn(msg)  # heuristic: may be quoted evidence
    except ImportError:
        result.warn("Strict: traust_engine._util.redact unavailable — secret scan skipped")
    if "dependency_audit" not in report:
        result.warn("Strict: missing recommended section 'dependency_audit'")
    repo_url = (report.get("metadata", {}).get("repository") or "").strip()
    if not repo_url:
        result.warn(
            "Strict: metadata.repository missing — org-index and repo-graph "
            "cannot attribute this report to a repository"
        )
    elif not _repository_parses(repo_url):
        result.warn(
            f"Strict: metadata.repository {repo_url!r} does not parse as "
            "https://<host>/<org>/<repo> — build_org_index.py skips such "
            "reports; use the concrete repository URL (org-only URLs are "
            "valid only for org-URL stub reports)"
        )
    meta_ds = report.get("metadata", {})
    hv_ds = _parse_harness_version(meta_ds)
    if (
        meta_ds.get("audit_profile") == "code"
        and hv_ds is not None
        and hv_ds >= DETERMINISTIC_STEPS_MIN_VERSION
        and "deterministic_steps" not in (meta_ds.get("additional") or {})
    ):
        result.warn(
            "Strict: code profile missing "
            "metadata.additional.deterministic_steps — record ran/skipped "
            "for k8s-hardening, opengrep, sbom-grype so a skipped scanner "
            "is not read as a quiet one (docs/report-structure.md)"
        )
    for i, f in enumerate(report.get("findings", [])):
        for text_field in ("description", "remediation"):
            if CIS_CONTROL_TEXT_RE.search(f.get(text_field) or ""):
                result.warn(
                    f"Strict: findings[{i}] ({f.get('id', '?')}) {text_field} "
                    "matches CIS/STIG recommendation-title phrasing — cite "
                    "bare section IDs with original prose; do not copy "
                    "benchmark text (docs/external-dependencies.md)"
                )
    if "negative_results" not in report:
        result.warn("Strict: missing recommended section 'negative_results'")
    if "footer" not in report:
        result.warn("Strict: missing 'footer'")
    es = report.get("executive_summary", {})
    if "positive_observations" not in es:
        result.warn("Strict: missing 'executive_summary.positive_observations'")
    meta = report.get("metadata", {})
    hv = _parse_harness_version(meta)
    # Container-profile reports measure an image, not source — no LoC by design
    # (they record metadata.additional.sbom_packages instead).
    if meta.get("audit_profile") == "container":
        if "sbom_packages" not in (meta.get("additional") or {}):
            result.warn("Strict: container profile missing 'metadata.additional.sbom_packages'")
    elif "loc_reviewed" not in meta and "loc_breakdown" not in meta:
        result.warn("Strict: metadata missing 'loc_reviewed' / 'loc_breakdown'")
    elif hv is not None and hv >= CONSISTENCY_MIN_VERSION and "loc_breakdown" not in meta:
        result.warn(
            "Strict: metadata missing 'loc_breakdown' — per-language LoC "
            "counts feed the campaign dashboards"
        )
    if "peach_isolation_review" not in report:
        result.warn(
            "Strict: missing 'peach_isolation_review' (record applicable:false "
            "with rationale if the component is single-tenant)"
        )
    else:
        pr = report["peach_isolation_review"]
        rationale = str(pr.get("rationale") or "")
        if pr.get("applicable") is False and len(rationale) < 40:
            result.warn(
                "Strict: peach_isolation_review.applicable is false with a "
                f"{len(rationale)}-char rationale — justify against the "
                "multi-tenant triggers in the secure-code-audit skill"
            )
    # metadata.date is the audit execution date. This validator runs as part
    # of the harness right after the audit, so the report date should match
    # validation time to within a day (tolerates multi-hour runs that cross
    # midnight, and timezone skew). A stale date is almost always a commit or
    # CVE date pasted into the wrong field.
    date_s = str(meta.get("date", ""))
    if date_s:
        try:
            report_date = date_type.fromisoformat(date_s)
        except ValueError:
            report_date = None  # malformed dates are rejected by the schema
        if report_date is not None:
            today = datetime.now(UTC).date()
            if abs(report_date - today) > timedelta(days=1):
                result.warn(
                    f"Strict: metadata.date '{date_s}' was not generated "
                    "within the last day — this must be the audit execution "
                    "date, not a commit/CVE date"
                )
    # CVSS is expected on every actionable finding; informational findings
    # (posture/hygiene observations) are exempt by convention.
    _BANDS = (("critical", 9.0), ("high", 7.0), ("medium", 4.0), ("low", 0.1))
    _BAND_ORDER = ["informational", "low", "medium", "high", "critical"]
    _DOWNGRADE_RATIONALE = re.compile(
        r"deployment context|contextual|downgrad|base score|CVSS base|"
        r"advisory (score|CVSS)|rated (low|medium|informational)|"
        r"not attacker.reachable|reachab",
        re.IGNORECASE,
    )

    def _band_of(score: float) -> str:
        for name, floor in _BANDS:
            if score >= floor:
                return name
        return "informational"

    for i, f in enumerate(report.get("findings", [])):
        sev = str(f.get("severity", "")).lower()
        if "cvss" not in f and sev != "informational":
            result.warn(f"Strict: findings[{i}] ({f.get('id', '?')}): missing CVSS scoring")
        # Severity ↔ CVSS-band consistency (2026-07-21, after 11 legacy
        # reports shipped 'informational' findings carrying CVSS 7.7-9.1):
        # informational findings must not be scored at all (hard error), and
        # a severity ≥2 bands below the CVSS band requires the description to
        # state the contextual downgrade of the advisory/base score.
        score = (f.get("cvss") or {}).get("score")
        if score is not None:
            if sev == "informational":
                msg = (
                    f"findings[{i}] ({f.get('id', '?')}): 'informational' "
                    f"finding carries CVSS {score} — informational findings "
                    "are never scored; set the severity the score implies "
                    f"('{_band_of(float(score))}') or drop the cvss block"
                )
                # score >= 7 is the proven data-corruption class (hard error);
                # lower scores on legacy reports degrade to a strict warning
                # so existing pipelines keep validating while the debt burns
                # down through re-audits.
                if float(score) >= 7.0:
                    result.error(msg)
                elif float(score) > 0.0:
                    result.warn("Strict: " + msg)
                # score 0.0 = no-impact vector; consistent with informational
            elif sev in _BAND_ORDER:
                gap = _BAND_ORDER.index(_band_of(float(score))) - _BAND_ORDER.index(sev)
                if gap >= 2 and not _DOWNGRADE_RATIONALE.search(f.get("description", "")):
                    result.warn(
                        f"Strict: findings[{i}] ({f.get('id', '?')}): severity "
                        f"'{sev}' is {gap} bands below the CVSS {score} band "
                        f"('{_band_of(float(score))}') with no stated rationale — "
                        "when an upstream advisory score is contextually "
                        "downgraded, the description must say so and why"
                    )
        if sev in ("critical", "high") and not f.get("attack_pattern"):
            result.warn(
                f"Strict: findings[{i}] ({f.get('id', '?')}): {sev} finding "
                "missing 'attack_pattern' (concrete attack scenario)"
            )
    # An audit-stage report marking every finding 'confirmed' is over-claiming:
    # this skill is static analysis, and confirmation requires execution
    # evidence — a fuzz crash, PoC, failing test, or a validations-pipeline
    # report (validation.schema.json under analysis-results/validations/) —
    # or a human reviewer's triage determination. Automated review votes do
    # not qualify.
    findings = report.get("findings", [])
    statuses = [f.get("validation_status") for f in findings]
    if len(findings) >= 5 and statuses and all(s == "confirmed" for s in statuses):
        result.warn(
            "Strict: every finding is validation_status 'confirmed' — "
            "audit-stage findings default to 'not_verified'; reserve "
            "'confirmed' for findings verified by execution (fuzz crash, "
            "PoC, failing test), a validations-pipeline report, or a "
            "human reviewer's triage"
        )
    # Category vocabulary (harness >= 0.15.0): free text is schema-valid but
    # off-vocabulary values fragment cross-report aggregation.
    if hv is not None and hv >= CONSISTENCY_MIN_VERSION:
        off_vocab = sorted(
            {
                f["category"]
                for f in findings
                if f.get("category")
                and _normalize_category(f["category"]) not in RECOMMENDED_CATEGORIES
            }
        )
        if off_vocab:
            result.warn(
                "Strict: finding categories outside the recommended "
                f"vocabulary: {off_vocab} — use one of "
                f"{sorted(RECOMMENDED_CATEGORIES)}"
            )


def validate_report(
    file_path: str,
    schema: dict,
    strict: bool = False,
    registry: Registry | None = None,
    merkle_pubkey: str | None = None,
    signing_pubkey: Path | None = None,
) -> ValidationResult:
    result = ValidationResult(file_path=file_path)

    try:
        with Path(file_path).open(encoding="utf-8") as f:
            report = json.load(f)
    except json.JSONDecodeError as e:
        result.error(f"Invalid JSON: {e}")
        return result
    except Exception as e:
        result.error(f"Cannot read file: {e}")
        return result

    kwargs = {"format_checker": jsonschema.FormatChecker()}
    if registry is not None:
        kwargs["registry"] = registry
    validator = jsonschema.Draft202012Validator(schema, **kwargs)
    for err in sorted(validator.iter_errors(report), key=lambda e: list(e.absolute_path)):
        path = _format_path(err.absolute_path)
        result.error(f"{path}: {err.message}")

    if result.passed:
        sid = schema.get("$id", "")
        if "verification" in sid:
            cross_validate_verification(report, result)
        elif "layer" in sid:
            cross_validate_layer(report, result, merkle_pubkey, signing_pubkey)
        elif "remediation" in sid:
            cross_validate_remediation(report, result)
        elif "triage" in sid:
            cross_validate_triage(report, result)
        elif "vuln-findings" in sid:
            cross_validate_vuln_findings(report, result)
        elif "impact-analysis" in sid:
            cross_validate_impact_analysis(report, result)
        elif "cloud-config-findings-current" in sid:
            cross_validate_cloud_config_current(report, result)
        elif "cloud-config-audit" in sid:
            # Layer-2 cloud-config report: content cross-checks (fact-ID
            # citations, rubric-row rationale, count reconciliation) live in
            # run_checkov.py --validate-report, the skill's canonical gate;
            # here only the schema applies. The code-audit cross-checks
            # (severity_criteria, findings_summary) do not fit this shape.
            pass
        elif "validation" in sid:
            cross_validate_validation(report, result)
        else:
            cross_validate(report, result)

    sid = schema.get("$id", "")
    # Schemas whose findings are not code-audit findings and so carry no
    # cross-scan fingerprint.
    _non_audit = (
        "validation",
        "remediation",
        "verification",
        "layer",
        "triage",
        "vuln-findings",
        "cloud-config-findings-current",
        "cloud-config-audit",
    )
    if not any(k in sid for k in _non_audit):
        check_finding_identity(report, result)
        check_metadata_repository(report, result)
    if strict and not any(k in sid for k in _non_audit):
        strict_checks(report, result)

    return result


def collect_report_files(path: str) -> list[Path]:
    target = Path(path)
    if target.is_dir():
        # Refuted registers are operational worklists (countersign/fuzzing
        # inputs), not schema'd reports — skip them in directory sweeps.
        return sorted(
            p for p in target.rglob("*.json") if not p.name.endswith("-refuted-register.json")
        )
    elif target.is_file():
        return [target]
    return []


def _is_cloud_config_current(file_path: Path) -> bool:
    """True when a *-findings-current.json is the cloud-config variant.

    Primary signal: build_cumulative.py stamps
    metadata.additional.cumulative.source_audit with the baseline audit
    filename — a *-cloud-config-audit.json reference is authoritative in
    both directions (a *-security-audit.json / *-container-audit.json stamp
    definitively means the code/container variant, which keeps its
    pre-existing report.schema.json route). Fallback for stripped or
    unreadable metadata: a sibling <base>-cloud-config-audit.json next to
    the cumulative report (build_cumulative writes the pair side by side).
    """
    try:
        doc = json.loads(file_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        doc = None
    if isinstance(doc, dict):
        meta = doc.get("metadata")
        additional = meta.get("additional") if isinstance(meta, dict) else None
        cumulative = additional.get("cumulative") if isinstance(additional, dict) else None
        source_audit = cumulative.get("source_audit") if isinstance(cumulative, dict) else None
        if source_audit:
            return str(source_audit).endswith("-cloud-config-audit.json")
    base = file_path.name[: -len("-findings-current.json")]
    return (file_path.parent / f"{base}-cloud-config-audit.json").is_file()


def detect_schema_path(file_path: Path) -> Path | None:
    """Filename-based schema auto-detection for directory sweeps.

    Returns a schema path when the filename unambiguously identifies a
    non-default artifact type, else None (caller falls back to the default
    or explicitly-passed schema). Keeps `validate_report.py findings/`
    honest: triage artifacts stop failing against the audit-report schema.

    *-findings-current.json needs one content peek: code-audit and
    container-audit cumulatives are report.schema.json-shaped (default
    route, unchanged), but cloud-config cumulatives carry the
    cloud-config-audit finding core and get their own schema.
    """
    name = file_path.name
    if name == "TRIAGE.json" or name.endswith("-triage.json"):
        return SCHEMA_DIR / "triage.schema.json"
    if name.endswith("-findings-layer.json"):
        return SCHEMA_DIR / "layer.schema.json"
    if name.endswith("-vuln-findings.json"):
        # Legacy VULN-FINDINGS.json (pre-0.38.0) predates this contract and
        # is deliberately NOT auto-detected — it would fail a schema it
        # never promised to meet.
        return SCHEMA_DIR / "vuln-findings.schema.json"
    if name.endswith("-threat-model.json"):
        # The threat model IS the JSON; the .md beside it is rendered from
        # this document. Auto-detected so a sweep validates it the same way
        # it validates every other artifact.
        return SCHEMA_DIR / "threat-model.schema.json"
    if name.endswith("-impact-analysis.json"):
        return SCHEMA_DIR / "impact-analysis.schema.json"
    if name.endswith("-cloud-config-audit.json"):
        # Layer-2 cloud-config report: run_checkov.py --validate-report is
        # the canonical gate, but sweeps must not fail it against the
        # code-audit schema (observed: 128 bogus errors, 2026-07-29).
        return SCHEMA_DIR / "cloud-config-audit.schema.json"
    if name.endswith("-findings-current.json") and _is_cloud_config_current(file_path):
        return SCHEMA_DIR / "cloud-config-findings-current.schema.json"
    return None
