"""Shared contract-model helpers for adapter scan() functions."""

from __future__ import annotations

import datetime
from typing import Any

from traust_contracts.enums import Severity
from traust_contracts.models import AdapterMetadata, AdapterResult, AdapterSummary, Finding


def utc_now() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def map_severity(hint: str, default: str = "low") -> Severity:
    return Severity((hint or default).lower())


def format_lines(start: int | None, end: int | None) -> str:
    if not start:
        return ""
    if end and end != start:
        return f"{start}-{end}"
    return str(start)


def build_adapter_result(
    target: str,
    tool: str,
    findings_data: list[dict[str, Any]],
    *,
    scanned_at: str | None = None,
    scanner_version: str = "",
    focus_areas: list[str] | None = None,
) -> AdapterResult:
    """Build AdapterResult from raw finding dicts produced by adapter parsers."""
    scanned_at = scanned_at or utc_now()
    findings: list[Finding] = []
    by_severity: dict[str, int] = {}
    for item in findings_data:
        unknown = item.keys() - Finding.model_fields.keys()
        if unknown:
            raise ValueError(f"undeclared adapter finding fields: {', '.join(sorted(unknown))}")
        data = {
            "cwes": [],
            "locations": [],
            "description": "",
            "remediation": "",
            **item,
            "severity": Severity(item.get("severity", Severity.LOW)),
        }
        finding = Finding.model_validate(data)
        findings.append(finding)
        key = finding.severity.value
        by_severity[key] = by_severity.get(key, 0) + 1

    return AdapterResult(
        target=target,
        scanned_at=scanned_at,
        focus_areas=focus_areas or [],
        metadata=AdapterMetadata(tool=tool, scanner_version=scanner_version),
        findings=findings,
        summary=AdapterSummary(total=len(findings), by_severity=by_severity),
    )


# Backwards-compatible alias used by existing adapters
build_scan_result = build_adapter_result
