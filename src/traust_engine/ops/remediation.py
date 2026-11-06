"""The fourth trigger: remediation-driven work, read off the ops feed.

The remediation pipeline's pieces — the scheduling door that opens the work item and
submits the order carrying its fork facts, the runner, the record door, verification,
SCI's filing loop — all live with traust-core's `RemediationSchedulingService`; nothing
started them automatically before this. The engine never creates an effort: it reads the
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
    """One scheduled effort's current state as core reads it: the work item the effort is
    (a `remediation` assessment, its status the fold of its decisions and the verification
    verdicts on its fix), the repository its findings belong to, and how many remediation
    attempts have run. `remediation_id` is the work item's id — the effort's handle, and
    the assessment's: the work item IS the assessment (contracts#117), so the feed's events
    name the effort they moved. Read-only to the engine; core derives `reattempts` from the
    effort's orders, so every order this trigger plans for it carries
    `rule = "remediation:<remediation_id>"`."""

    remediation_id: UUID
    repository_id: UUID
    status: RemediationStatus
    reattempts: int = 0


class Remediations(Protocol):
    """The scheduled-effort reads the trigger needs; core's remediation scheduling service
    (the door that opens the work item and submits the order carrying its fork facts, and
    the read fold that carries its status) satisfies this."""

    def state_of(self, assessment_id: UUID) -> RemediationState | None:
        """The scheduled effort of `assessment_id` — the work item the assessment is — None
        when the assessment is no effort: no work item, or no order carrying its fork facts
        (it was not opened through the scheduling door)."""
        ...

    def states_of(self, repository_id: UUID) -> list[RemediationState]:
        """Every scheduled effort of the repository, whatever its status: what a finished
        remediation run or a recorded verification may have moved."""
        ...
