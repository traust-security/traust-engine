"""Five-field cron expressions (minute hour day-of-month month day-of-week, UTC): when a
clock-time job last fell due."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

_MONTHS = ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec")
_WEEKDAYS = ("sun", "mon", "tue", "wed", "thu", "fri", "sat")
_NAMES = {
    4: {m: i for i, m in enumerate(_MONTHS, 1)},
    5: {d: i for i, d in enumerate(_WEEKDAYS)},
}
_RANGES = ((0, 59), (0, 23), (1, 31), (1, 12), (0, 7))
# A year and a day back covers every expression that names a real date (29 February aside).
_HORIZON = 367


def _value(token: str, field: int) -> int:
    lo, hi = _RANGES[field - 1]
    value = _NAMES.get(field, {}).get(token.lower())
    if value is None:
        if not token.isdigit():
            raise ValueError(f"cron field {field}: {token!r} is not a number")
        value = int(token)
    if not lo <= value <= hi:
        raise ValueError(f"cron field {field}: {value} is outside {lo}-{hi}")
    return value


def _field(text: str, field: int) -> frozenset[int]:
    lo, hi = _RANGES[field - 1]
    values: set[int] = set()
    for part in text.split(","):
        span, _, step = part.partition("/")
        if span == "*":
            start, end = lo, hi
        elif "-" in span:
            a, b = span.split("-", 1)
            start, end = _value(a, field), _value(b, field)
        else:
            start = end = _value(span, field)
        stride = int(step) if step else 1
        if stride < 1 or start > end:
            raise ValueError(f"cron field {field}: {part!r} names no value")
        values.update(range(start, end + 1, stride))
    if field == 5 and 7 in values:  # 7 is Sunday too
        values = (values - {7}) | {0}
    return frozenset(values)


@dataclass(frozen=True)
class Cron:
    expression: str
    minutes: frozenset[int]
    hours: frozenset[int]
    days: frozenset[int]
    months: frozenset[int]
    weekdays: frozenset[int]
    any_day: bool
    any_weekday: bool

    @classmethod
    def parse(cls, expression: str) -> Cron:
        fields = expression.split()
        if len(fields) != 5:
            raise ValueError(f"cron {expression!r}: five fields, not {len(fields)}")
        parsed = [_field(text, n) for n, text in enumerate(fields, 1)]
        return cls(expression, *parsed, any_day=fields[2] == "*", any_weekday=fields[4] == "*")

    def _on(self, day: datetime) -> bool:
        if day.month not in self.months:
            return False
        dom, dow = day.day in self.days, (day.weekday() + 1) % 7 in self.weekdays
        # Cron's rule: with both day fields restricted, either one matching is enough.
        if self.any_day or self.any_weekday:
            return dom and dow
        return dom or dow

    def last(self, now: datetime) -> datetime:
        """The latest time at or before `now` the expression names."""
        now = now.astimezone(UTC).replace(second=0, microsecond=0)
        for back in range(_HORIZON):
            day = now - timedelta(days=back)
            if not self._on(day):
                continue
            for hour in sorted(self.hours, reverse=True):
                for minute in sorted(self.minutes, reverse=True):
                    at = day.replace(hour=hour, minute=minute)
                    if at <= now:
                        return at
        raise ValueError(f"cron {self.expression!r} names no time in the past year")
