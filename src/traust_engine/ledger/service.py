"""LedgerService — the traust-engine's gateway to traust-ledger.

Wraps ``LedgerClient`` (the in-process Python SDK) so the harness has a
single object for all ledger I/O.  Callers interact with the ledger through
this service, never through scattered imports of traust-ledger internals.

All write operations delegate to ``LedgerClient`` → ``Backend``.
Backend-agnostic; work with file or db materializers.  Every write
is atomic (mutate + stamp + sign inside one lock).

Pure computation (fingerprint, compute_event_id, derive_disposition) stays
importable directly from traust_engine.ledger — those are stateless
algorithms that don't need a service boundary.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from traust_contracts.v1.models.layer import LayerActor
from traust_ledger.api import reports
from traust_ledger.client import LedgerClient, LedgerError


@dataclass
class VerifyResult:
    """Outcome of a layer integrity check."""

    passed: bool
    findings: list[dict] = field(default_factory=list)
    checked_at: str = ""


@dataclass
class SubmitResult:
    """Outcome of appending events to a layer."""

    event_ids: list[str] = field(default_factory=list)
    queue_added: int = 0


class LedgerService:
    """Stateful gateway to traust-ledger operations.

    Delegates to ``LedgerClient`` for all authenticated ledger I/O.
    Signing configuration is read from environment by LedgerClient
    (LAAS_SIGNING_*, HARNESS_SIGNING_*) — callers never supply credentials.

    Usage:
        ledger = LedgerService()
        ledger = LedgerService(data_dir=Path("/data"))

        ledger.submit_events(layer_path, events)
        result = ledger.query_findings(layer_path)
        ledger.verify(layer_path)
    """

    def __init__(
        self,
        client: LedgerClient | None = None,
        *,
        data_dir: Path | None = None,
    ):
        if client is not None:
            self._client = client
            return

        # LedgerClient resolves SigningConfig.from_env() internally when no
        # signing_config is passed — no need to import or forward it here.
        if data_dir is not None:
            self._client = LedgerClient(data_dir=str(data_dir))
        else:
            self._client = LedgerClient()

    # ─── Ledger operations (delegate to LedgerClient → Backend) ─────────

    def actor(self):
        """The verified actor this service writes as: the ledger identity
        token, verified, with the deployment's optional employee-directory
        cross-check applied (``LEDGER_DIRECTORY_COMMAND``). Raises
        ``LedgerError`` when either refuses. Callers that record human
        decisions resolve this once, up front, so a refusal happens before
        any work — the SDK re-derives the same actor at submit time."""
        return self._client.actor()

    def query_findings(self, layer_path: Path) -> dict[str, Any]:
        """Resolve current dispositions for all findings in a layer."""
        return self._client.query_findings(layer_path.stem)

    def verify(self, layer_path: Path, *, check_signatures: bool = False) -> VerifyResult:
        """Verify Merkle integrity (and optionally signatures) of a layer."""
        result = self._client.verify(layer_path.stem, check_signatures=check_signatures)
        return VerifyResult(
            passed=result.get("passed", False),
            findings=result.get("findings", []),
            checked_at=result.get("checked_at", ""),
        )

    def submit_events(
        self,
        layer_path: Path,
        events: list[dict],
        *,
        report_path: Path | None = None,
        queue_items: list[dict] | None = None,
    ) -> SubmitResult:
        """Append events to a layer via LedgerClient.

        Deduplication, actor stamping, Merkle finalization, and signing
        are handled by the SDK's submit handler.
        """
        layer_id = layer_path.stem
        result = self._client.submit(
            layer_id,
            events,
            needs_review=queue_items,
        )

        if report_path is not None:
            digest = reports.report_sha256(str(report_path))
            self._client.patch_metadata(
                layer_id,
                {
                    "audit_report_sha256": digest,
                },
            )

        return SubmitResult(
            event_ids=result.get("event_ids", []),
            queue_added=result.get("queue_added", 0),
        )

    def sign(self, layer_path: Path, *, rekor: bool = False) -> None:
        """Stamp Merkle metadata and sign a layer file."""
        self._client.sign(layer_path.stem, rekor=rekor)

    def resolve_review_item(
        self,
        layer_path: Path,
        key: str,
        decision: str,
        note: str = "",
    ) -> dict:
        """Mark a review queue item as resolved."""
        return self._client.resolve(layer_path.stem, key, decision, note)

    def countersign(
        self,
        layer_path: Path,
        finding_ref: str,
        *,
        rationale: str,
        recorded_at: str,
        decision: str | None = None,
        severity: str | None = None,
        actor: LayerActor | None = None,
    ) -> dict:
        """Record a human countersign/severity event through the gated SDK handler.

        The SDK runs the human-lane gates, stamps the actor, and signs
        atomically — the harness never appends or signs events itself.
        """
        return self._client.countersign(
            layer_path.stem,
            finding_ref,
            rationale=rationale,
            recorded_at=recorded_at,
            decision=decision,
            severity=severity,
            actor=actor,
        )

    def whoami(self) -> LayerActor:
        """The verified actor for the current token (see LedgerClient.whoami)."""
        return self._client.whoami()

    # ─── Layer file I/O (local filesystem, bypasses Backend) ──────────

    def read_layer_file(self, layer_path: Path) -> dict:
        """Load a layer dict from a local JSON file."""
        return json.loads(layer_path.read_text(encoding="utf-8"))

    def ensure_layer_file(self, layer_path: Path, *, shell: dict | None = None) -> dict:
        """Load or create a layer via LedgerClient. Returns the layer dict."""
        layer_id = layer_path.stem
        try:
            return self.read_layer_file(layer_path)
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        base = shell or {"events": [], "metadata": {}}
        self._client.create(layer_id, shell=base)
        return dict(base)

    def patch_layer_file(
        self,
        layer_path: Path,
        updates: dict[str, Any],
        *,
        sign: bool = True,
    ) -> None:
        """Merge *updates* into layer metadata atomically via LedgerClient.

        Used by baseline_claims (claim_hashes), route_regressions (claim_hashes),
        and countersign (finding_aliases). Atomic: mutate + stamp + sign in one
        Backend.mutate call.

        *sign* parameter is accepted for backward compat but ignored — writes
        are always atomic (stamped + signed) through the SDK.
        """
        self._client.patch_metadata(layer_path.stem, updates)

    def stamp_report_file(self, layer_path: Path, report_path: Path, *, sign: bool = True) -> bool:
        """Record audit_report_sha256 in layer metadata atomically via SDK.

        Returns True (always stamps — idempotency is handled by the SDK).
        *sign* accepted for backward compat but ignored — writes are atomic.
        """
        digest = reports.report_sha256(str(report_path))
        self._client.patch_metadata(
            layer_path.stem,
            {
                "audit_report_sha256": digest,
            },
        )
        return True

    def stamp_event_identities(self, layer_path: Path, fingerprints: dict[str, str]) -> int:
        """Backfill event fingerprints and re-sign atomically via the SDK.

        The skill hands the fingerprint map (finding_ref -> fp) to the ledger,
        which stamps identity onto the events inside the Merkle tree and re-signs
        in one atomic write — the skill never writes the layer itself. Returns
        the number of events stamped.
        """
        result = self._client.stamp_event_identities(layer_path.stem, fingerprints)
        return int(result.get("stamped", 0))

    def store_layer(self, layer_path: Path, layer: dict) -> None:
        """Persist a complete layer dict through the backend.

        Use when a caller has built an entire layer in memory and needs
        to write it before signing.  Typical pattern::

            svc.store_layer(layer_path, layer)
            svc.sign(layer_path)          # stamps + signs atomically
        """
        self._client.store(layer_path.stem, layer)

    # ─── Utilities ───────────────────────────────────────────────────────

    @staticmethod
    def layer_id_from_path(layer_path: Path) -> str:
        """Derive layer_id from a filesystem path (stem without extension)."""
        return layer_path.stem

    @staticmethod
    def review_item_key(item: dict) -> str:
        """Compute the addressable key for a review queue item.

        Returns a JSON string ready to pass to :meth:`resolve_review_item`.
        """
        key = (
            item.get("source_ref"),
            item.get("suggested_finding_ref"),
            item.get("queue_reason"),
            item.get("quote"),
        )
        return json.dumps(list(key))


__all__ = ["LedgerClient", "LedgerError", "LedgerService", "SubmitResult", "VerifyResult"]
