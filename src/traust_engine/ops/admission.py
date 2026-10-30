"""Admission: one pass over the planned orders per tick, most important first."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from uuid import UUID

from traust_core.v1.context import Clock, OpsService, SpendService
from traust_core.v1.models.base import Model
from traust_core.v1.models.common import every_item
from traust_core.v1.models.operations import (
    AssetName,
    Budget,
    BudgetVerdict,
    LaneName,
    OrderFilter,
    OrderReason,
    OrderState,
    RunOrder,
)

from traust_engine.ops.pack import AssetSpec, Pack, Quota


class AdmissionReport(Model):
    admitted: int = 0
    awaiting_approval: int = 0
    withheld: int = 0
    deferred: int = 0


@dataclass
class TokenBucket:
    """Refills `per_hour` tokens an hour, holding at most an hour's worth."""

    per_hour: int
    tokens: float
    at: datetime

    def take(self, now: datetime) -> bool:
        refill = (now - self.at).total_seconds() * self.per_hour / 3600
        self.tokens, self.at = min(self.per_hour, self.tokens + refill), now
        if self.tokens < 1:
            return False
        self.tokens -= 1
        return True


class Admission:
    def __init__(self, pack: Pack, ops: OpsService, spend: SpendService, clock: Clock) -> None:
        self._pack = pack
        self._ops = ops
        self._spend = spend
        self._clock = clock
        self._buckets: dict[str, TokenBucket] = {}

    def admit(self, hosts: Mapping[UUID, str]) -> AdmissionReport:
        """Admit, hold for approval, withhold (budget) or defer (pacing, quota) each planned
        order; `hosts` maps repository ids to forge hosts for the quota buckets."""
        now = self._clock.now()
        planned = every_item(lambda p: self._ops.list(OrderFilter(states=(OrderState.PLANNED,)), p))
        budgets: dict[LaneName, BudgetVerdict] = {}
        committed: dict[LaneName, Decimal] = {}
        paced: Counter[AssetName] = Counter()
        report = Counter[str]()
        for order in sorted(planned, key=lambda o: (o.priority, o.created_at)):
            asset = AssetName(order.asset)
            spec = self._pack.assets.get(asset)
            if spec is None:
                self._ops.withhold(order.id, OrderReason.ASSET_NOT_IN_PACK)
                report["withheld"] += 1
                continue
            verdict = self._verdict(order, spec, budgets, committed)
            pacing, quota = spec.admission.pacing, spec.admission.quota
            if verdict is not None and verdict.binding:
                self._ops.withhold(order.id, OrderReason.BUDGET_OVER, verdict)
                report["withheld"] += 1
                continue
            if (pacing and paced[asset] >= pacing.per_tick) or (
                quota and not self._token(quota, order, hosts, now)
            ):
                report["deferred"] += 1
                continue
            if spec.admission.approval:
                self._ops.request_approval(order.id)
                report["awaiting_approval"] += 1
            else:
                self._ops.admit(order.id, verdict)
                report["admitted"] += 1
            paced[asset] += 1
            if verdict is not None and verdict.estimate_usd is not None:
                committed[verdict.lane] = verdict.estimate_usd
        return AdmissionReport(**report)

    def _verdict(
        self,
        order: RunOrder,
        spec: AssetSpec,
        budgets: dict[LaneName, BudgetVerdict],
        committed: Mapping[LaneName, Decimal],
    ) -> BudgetVerdict | None:
        """This order's verdict on top of what the tick already admitted in its lane; orders
        share the lane budget in priority order, and unknown cost never binds."""
        estimate = spec.admission.estimate_usd
        if order.lane is None or estimate is None:
            return None
        lane = LaneName(order.lane)
        if lane not in budgets:
            budgets[lane] = self._spend.check_budget(lane, Decimal(0))
        base = budgets[lane]
        total = committed.get(lane, Decimal(0)) + estimate
        if base.budget_usd is None or base.enforcement is None:
            return base.model_copy(update={"estimate_usd": total})
        budget = Budget(lane=lane, monthly_usd=base.budget_usd, enforcement=base.enforcement)
        return budget.verdict(base.spent_usd, total)

    def _token(
        self, quota: Quota, order: RunOrder, hosts: Mapping[UUID, str], now: datetime
    ) -> bool:
        host = hosts.get(order.repository_id, "") if order.repository_id else ""
        full = TokenBucket(quota.per_hour, quota.per_hour, now)
        return self._buckets.setdefault(quota.bucket(host), full).take(now)
