"""The fourth trigger: remediation-driven work, read off the ops feed.

The remediation pipeline's pieces — the scheduling door that opens a remediation with its
assessment and order, the runner, the record door, verification, SCI's filing loop — all
exist or land with traust-core's `RemediationSchedulingService`; nothing started them
automatically before this. The engine never writes the remediation table: it reads the
feed, asks the service below for current state, and plans orders the same admission gate
admits as the tick's (REMEDIATION-SCHEDULING-DESIGN.md, "Engine trigger")."""

from __future__ import annotations

from datetime import timedelta
from typing import Protocol
from uuid import UUID

from traust_core.v1.models.base import Model
from traust_core.v1.models.operations import AssetName
from traust_core.v1.models.vocabulary import RemediationStatus

#: The pack assets the trigger dispatches. `remediate_finding` is the skill session that
#: patches (the security pack does not run it — SCI's local pack defines it);
#: `verify_remediation` is the verification sweep the security pack already runs weekly,
#: queued on demand when a remediation is implemented.
REMEDIATE_ASSET = AssetName("remediate_finding")
VERIFY_ASSET = AssetName("verify_remediation")

#: How many times a remediation that verification still finds vulnerable is re-attempted
#: before it waits for a person (REMEDIATION-SCHEDULING-DESIGN.md, "Verification trigger").
REATTEMPT_LIMIT = 2

#: How long an attempted order (finished, degraded, failed or refused) suppresses
#: re-dispatching the same subject, the cadence path's "a refused or failed run waits out
#: the cadence" rule carried over to event-driven work: a sweep that fails without a
#: verdict, or a run that finishes without recording, is retried at most this often —
#: by the next pass after the window, not by every restart or recheck.
RETRY_AFTER = timedelta(hours=1)


class RemediationState(Model):
    """One remediation's current state as core reads it: the row the scheduling door
    creates, the status the record and verification doors move (an explicitly maintained
    view of the decisions), and how many remediation attempts have run. Read-only to the
    engine; core derives `reattempts` from the remediation's orders, so every order this
    trigger plans for it carries `rule = "remediation:<remediation_id>"`."""

    remediation_id: UUID
    assessment_id: UUID | None = None
    repository_id: UUID
    status: RemediationStatus
    reattempts: int = 0


class Remediations(Protocol):
    """The remediation-table reads the trigger needs; core's remediation scheduling
    service (the door that creates the row with its assessment and order, and the status
    sync that moves it) satisfies this once it lands."""

    def state_of(self, assessment_id: UUID) -> RemediationState | None:
        """The remediation of `assessment_id`, None when the assessment has no row — it
        was not opened through the scheduling door."""
        ...

    def states_of(self, repository_id: UUID) -> list[RemediationState]:
        """Every remediation of the repository, whatever its status: what a finished
        remediation run or a recorded verification may have moved."""
        ...
