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
from traust_core.v1.models.operations import AssetName, RunOrder
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
#: re-dispatching the same remediation, the cadence path's "a refused or failed run
#: waits out the cadence" rule carried over to event-driven work: a sweep that fails
#: without a verdict, or a run that finishes without recording, is retried at most
#: this often — by the next pass after the window, not by every restart or recheck.
#: The bound is per remediation (its rule), not per repository: an unrelated
#: remediation of the same repository is serialized by the open-order check alone.
RETRY_AFTER = timedelta(hours=1)

#: The rules the trigger's orders carry: "remediation:<remediation_id>" and
#: "verify-remediation:<remediation_id>". The retry window keys on them, and the
#: shadow comparison excludes runs that carry them (or a work item) as event-driven
#: remediation work, not cadence work.
REMEDIATE_RULE_PREFIX = "remediation:"
VERIFY_RULE_PREFIX = "verify-remediation:"


def is_remediation_rule(rule: str | None) -> bool:
    """Whether an order's rule is one the remediation trigger mints."""
    return rule is not None and (
        rule.startswith(REMEDIATE_RULE_PREFIX) or rule.startswith(VERIFY_RULE_PREFIX)
    )


def is_remediation_run(order: RunOrder) -> bool:
    """Whether a finished order is remediation work rather than cadence work: the
    trigger's own orders carry its rules, and the scheduling door's orders name a
    work item. The shadow comparison measures cadence work only. Every work-item
    order today is remediation work — the door opens work items for remediations
    alone — so the classification is exact; if core grows non-remediation work
    items, this must discriminate before the shadow diff silently shrinks. The
    work-item column is read defensively because this pin predates it (core#377
    added it): on the pinned core no order names one and the rule alone decides,
    and on a pin that carries the column the attribute should be read directly,
    so drift fails loudly instead of classifying as cadence work."""
    work_item = getattr(order, "work_item_id", None)
    return is_remediation_rule(order.rule) or work_item is not None


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
    #: Prior attempts of the effort's findings, as core models them: an attempt that is
    #: over is retried as a new work item over the same findings, so the count is the
    #: repository's over efforts sharing a finding. The adapter computes it on the
    #: repository listing; the feed-driven keyed read has no siblings and reads zero.
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
