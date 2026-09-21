"""Ledger gateway — the single place traust-engine touches traust-ledger.

Two tiers:

    1. LedgerService (stateful)
       All layer I/O goes through this object: submit events, sign, verify,
       query findings. One object, one config, one place to mock in tests.

    2. SDK functions (stateless, import freely)
       Pure computation re-exported here: fingerprint, compute_event_id,
       derive_disposition, etc. No service instance needed.

Usage:
    from traust_engine.ledger import LedgerService, fingerprint, compute_event_id

    ledger = LedgerService()
    ledger.submit_events(layer_path, events)
    result = ledger.verify(layer_path)

    fp = fingerprint(finding)  # pure — no service needed
"""

# ─── SDK-tier: disposition ──────────────────────────────────────────────
from traust_ledger.api.disposition import (
    derive_disposition,
    is_actor_verified,
)

# ─── SDK-tier: events ───────────────────────────────────────────────────
from traust_ledger.api.events import (
    FINGERPRINT_ALGO_CURRENT,
    aliases_from_events,
    attach_identity,
    compute_claim_hash,
    compute_event_id,
    findings_from_events,
    fingerprint_index,
    make_alias_event,
)

# ─── SDK-tier: identity ─────────────────────────────────────────────────
from traust_ledger.api.identity import (
    ALGO_LADDER,
    ALGO_VERSION,
    attribute,
    canon_path,
    canon_repo,
    fingerprint,
    primary_cwe,
)

# ─── SDK-tier: integrity (read-only verification) ───────────────────────
from traust_ledger.api.integrity import (
    IntegrityFinding,
    Severity,
    verify_merkle_integrity,
    verify_merkle_signature,
)

# ─── SDK-tier: reports (pure computation) ───────────────────────────────
from traust_ledger.api.reports import (
    check_artifact_digests,
    check_report_digest,
    report_sha256,
    stamp_artifact_digests,
    stamp_report_reference,
)

from traust_engine.ledger.service import (
    LedgerClient,
    LedgerError,
    LedgerService,
    SubmitResult,
    VerifyResult,
)

# REMOVED: stamp_and_sign — all callers migrated to LedgerService.sign().
# Historical context: stamp_and_sign was the only in-memory signing entrypoint.
# Each router called it independently, leading to inconsistent error handling
# and missed signs (e.g. route_impact_findings before 2026-08-17). The service
# encapsulates all signing concerns atomically.


# RUF022 is suppressed below: this list is grouped by concern (Identity /
# Events / Integrity / Service + SDK) with section comments, and sorting the
# whole list would strip the grouping, which is the only navigation here.
__all__ = [  # noqa: RUF022
    # Legacy (removed: stamp_and_sign — use LedgerService.sign())
    # Identity
    "ALGO_LADDER",
    "ALGO_VERSION",
    "attribute",
    # Events
    "FINGERPRINT_ALGO_CURRENT",
    # Integrity
    "IntegrityFinding",
    # Service + SDK
    "LedgerClient",
    "LedgerError",
    "LedgerService",
    "Severity",
    "SubmitResult",
    "VerifyResult",
    "aliases_from_events",
    "attach_identity",
    "canon_path",
    "canon_repo",
    # Reports
    "check_artifact_digests",
    "check_report_digest",
    "compute_claim_hash",
    "compute_event_id",
    # Disposition
    "derive_disposition",
    "findings_from_events",
    "fingerprint",
    "fingerprint_index",
    "is_actor_verified",
    "make_alias_event",
    "primary_cwe",
    "report_sha256",
    "stamp_artifact_digests",
    "stamp_report_reference",
    "verify_merkle_integrity",
    "verify_merkle_signature",
]
