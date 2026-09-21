"""
Render a validated JSON security report to Markdown.

Usage:
  traust reporting render findings/report.json              # stdout
  traust reporting render findings/report.json -o report.md  # file
"""

from __future__ import annotations

import re
from pathlib import Path

try:
    from traust_contracts.models import Report

    HAS_CONTRACTS = True
except ImportError:
    HAS_CONTRACTS = False

# --- output escaping (H10) ---------------------------------------------------
# Report content is authored under prompt-injection pressure from hostile
# repositories: titles, captions, and evidence code are untrusted. Escape
# table pipes, strip control/bidi-override characters from inline text, and
# size code fences past the longest backtick run in the evidence so embedded
# ``` sequences cannot break out of the code block into raw markdown/HTML.

_CTRL_RX = re.compile("[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f\\u202a-\\u202e\\u2066-\\u2069]")
_BACKTICK_RUN_RX = re.compile(r"`+")


def _clean_inline(text) -> str:
    """One-line text (headings, labels, cells): drop control and bidi
    override characters, collapse all whitespace (a newline in a heading
    lets content fabricate its own sections)."""
    text = _CTRL_RX.sub("", str(text if text is not None else ""))
    return " ".join(text.split())


def _clean_block(text) -> str:
    """Multi-line prose: preserve newlines/markdown, drop other control
    and bidi override characters."""
    return _CTRL_RX.sub("", str(text if text is not None else ""))


def _cell(text) -> str:
    """Markdown table cell: pipes break columns, newlines break rows."""
    return _clean_inline(text).replace("|", "\\|")


def _fence_for(code: str) -> str:
    """A fence longer than any backtick run inside the content (min 3)."""
    longest = max((len(m) for m in _BACKTICK_RUN_RX.findall(code)), default=0)
    return "`" * max(3, longest + 1)


def _table(headers: list[str], rows: list[list[str]]) -> str:
    lines = [
        "| " + " | ".join(_cell(h) for h in headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(_cell(c) for c in row) + " |")
    return "\n".join(lines)


def render_title(report: dict) -> str:
    return f"# {_clean_inline(report['title'])}\n"


def _fmt_int(n) -> str:
    try:
        return f"{int(n):,}"
    except (TypeError, ValueError):
        return str(n)


def render_metadata(meta: dict) -> str:
    field_map = [
        ("date", "Date"),
        ("scope", "Scope"),
        ("repository", "Repository"),
        ("commit", "Commit"),
        ("framework", "Framework"),
        ("auditor", "Auditor"),
        ("methodology", "Methodology"),
    ]
    present = [(label, meta[key]) for key, label in field_map if key in meta]

    lb = meta.get("loc_breakdown")
    if lb:
        loc_val = _fmt_int(lb.get("total"))
        if lb.get("tool"):
            loc_val += f" ({lb['tool']})"
        present.append(("Lines Reviewed", loc_val))
    elif "loc_reviewed" in meta:
        present.append(("Lines Reviewed", _fmt_int(meta["loc_reviewed"])))

    additional = meta.get("additional", {})
    if additional.get("harness_version"):
        present.append(("Harness Version", additional["harness_version"]))

    if "tools" in meta:
        present.append(("Tools", ", ".join(meta["tools"])))

    parts = []
    if len(present) >= 4:
        parts.append(_table(["Field", "Value"], [[f"**{lbl}**", str(val)] for lbl, val in present]))
    else:
        parts.append("\n".join(f"**{label}:** {value}" for label, value in present))

    if lb and lb.get("by_language"):
        parts.append("")
        parts.append("**Lines of code by language:**")
        parts.append("")
        rows = sorted(lb["by_language"].items(), key=lambda kv: kv[1], reverse=True)
        parts.append(_table(["Language", "LoC"], [[k, _fmt_int(v)] for k, v in rows]))
        if lb.get("excludes"):
            parts.append("")
            parts.append(f"*Excluded from count: {', '.join(f'`{e}`' for e in lb['excludes'])}*")

    return "\n".join(parts)


def render_executive_summary(es: dict) -> str:
    parts = ["## 1. Executive Summary\n", _clean_block(es["prose"]), ""]

    counts = es["severity_counts"]
    sev_order = ["critical", "high", "medium", "low", "informational"]
    rows = []
    for sev in sev_order:
        if sev in counts:
            rows.append([f"**{sev.capitalize()}**", str(counts[sev])])
    parts.append(_table(["Severity", "Count"], rows))

    if es.get("key_risks"):
        parts.append("")
        parts.append("**Key risks:**")
        for risk in es["key_risks"]:
            parts.append(f"- {_clean_inline(risk)}")

    if es.get("positive_observations"):
        parts.append("")
        parts.append("**Positive observations:**")
        for obs in es["positive_observations"]:
            parts.append(f"- {_clean_inline(obs)}")

    return "\n".join(parts)


def render_severity_criteria(criteria: list[dict]) -> str:
    parts = ["## 2. Severity Criteria\n"]

    has_cvss = any(c.get("cvss_range") for c in criteria)
    if has_cvss:
        headers = ["Level", "CVSS Range", "Definition"]
        rows = [
            [f"**{c['level'].capitalize()}**", c.get("cvss_range") or "N/A", c["definition"]]
            for c in criteria
        ]
    else:
        headers = ["Level", "Definition"]
        rows = [[f"**{c['level'].capitalize()}**", c["definition"]] for c in criteria]

    parts.append(_table(headers, rows))
    return "\n".join(parts)


def _render_finding(f: dict) -> str:
    parts = [f"### {_clean_inline(f['id'])} — {_clean_inline(f['title'])}\n"]

    meta_rows = [
        ["**Severity**", f"**{f['severity'].capitalize()}**"],
        ["**CWE**", ", ".join(f["cwes"])],
    ]

    if f.get("asvs_references"):
        meta_rows.append(["**ASVS**", ", ".join(f["asvs_references"])])

    if f.get("peach_references"):
        meta_rows.append(["**PEACH**", ", ".join(f["peach_references"])])

    if f.get("cvss"):
        meta_rows.append(
            [
                "**CVSS**",
                f"{f['cvss']['score']} — `{f['cvss']['vector']}`",
            ]
        )

    for loc in f["locations"]:
        loc_str = f"`{loc['path']}"
        if loc.get("lines"):
            loc_str += f":{loc['lines']}"
        loc_str += "`"
        if loc.get("description"):
            loc_str += f" ({loc['description']})"
        meta_rows.append(["**Location**", loc_str])

    if f.get("category"):
        meta_rows.append(["**Category**", f["category"]])

    parts.append(_table(["", ""], meta_rows))
    parts.append("")

    parts.append("**Description**\n")
    parts.append(_clean_block(f["description"]))

    if f.get("evidence"):
        parts.append("")
        for ev in f["evidence"]:
            if ev.get("caption"):
                parts.append(f"*{_clean_inline(ev['caption'])}*")
            # Language tag must not smuggle characters past the fence line;
            # fence sized past the longest backtick run in the code so an
            # embedded ``` cannot terminate the block early.
            lang = re.sub(r"[^A-Za-z0-9_+#.-]", "", str(ev.get("language", "")))[:20]
            code = _clean_block(ev["code"])
            fence = _fence_for(code)
            parts.append(f"{fence}{lang}")
            parts.append(code)
            parts.append(fence)

    if f.get("attack_pattern"):
        parts.append("")
        parts.append("**Attack pattern**\n")
        parts.append(_clean_block(f["attack_pattern"]))

    parts.append("")
    parts.append("**Remediation**\n")
    parts.append(_clean_block(f["remediation"]))

    return "\n".join(parts)


def render_findings(findings: list[dict]) -> str:
    parts = ["## 3. Detailed Findings\n"]
    for i, f in enumerate(findings):
        if i > 0:
            parts.append("\n---\n")
        parts.append(_render_finding(f))
    return "\n".join(parts)


def render_findings_summary(summary: list[dict]) -> str:
    parts = ["## 4. Findings Summary\n"]
    rows = [
        [
            f"**{e['severity'].capitalize()}**",
            str(e["count"]),
            ", ".join(e["finding_ids"]) if e["finding_ids"] else "—",
        ]
        for e in summary
    ]
    parts.append(_table(["Severity", "Count", "Finding IDs"], rows))
    return "\n".join(parts)


def render_remediation_roadmap(roadmap: list[dict]) -> str:
    parts = ["## 5. Remediation Roadmap\n"]
    has_effort = any(r.get("effort") for r in roadmap)
    if has_effort:
        headers = ["Priority", "Action", "Addresses", "Effort"]
        rows = [
            [
                f"**{r['priority']}**",
                r["action"],
                ", ".join(r["addresses"]),
                r.get("effort", ""),
            ]
            for r in roadmap
        ]
    else:
        headers = ["Priority", "Action", "Addresses"]
        rows = [[f"**{r['priority']}**", r["action"], ", ".join(r["addresses"])] for r in roadmap]
    parts.append(_table(headers, rows))
    return "\n".join(parts)


def render_dependency_audit(dep: dict, section_num: int) -> str:
    parts = [f"## {section_num}. Dependency Audit\n"]
    if dep.get("prose"):
        parts.append(_clean_block(dep["prose"]))
        parts.append("")
    if dep.get("entries"):
        rows = [
            [e["package"], e["version"], e["status"], e.get("notes", "")] for e in dep["entries"]
        ]
        parts.append(_table(["Package", "Version", "Status", "Notes"], rows))
    return "\n".join(parts)


def render_negative_results(results: list[dict], section_num: int) -> str:
    parts = [f"## {section_num}. Negative Results (Verified Clean)\n"]
    for r in results:
        line = f"- **{_clean_inline(r['area'])}**"
        if r.get("files"):
            line += f" ({_clean_inline(r['files'])})"
        line += f": {_clean_inline(r['result'])}"
        parts.append(line)
    return "\n".join(parts)


def render_asvs_coverage(chapters: list[dict], section_num: int) -> str:
    parts = [f"## {section_num}. ASVS Coverage Matrix\n"]
    has_assessed = any("requirements_assessed" in ch for ch in chapters)
    has_violations = any("violations" in ch for ch in chapters)
    has_severity = any("highest_severity" in ch for ch in chapters)
    headers = ["Chapter", "Area"]
    if has_assessed:
        headers.append("Assessed")
    if has_violations:
        headers.append("Violations")
    if has_severity:
        headers.append("Highest")
    rows = []
    for ch in chapters:
        row = [ch["chapter"], ch["area"]]
        if has_assessed:
            row.append(str(ch.get("requirements_assessed", "")))
        if has_violations:
            row.append(str(ch.get("violations", "")))
        if has_severity:
            sev = ch.get("highest_severity")
            row.append(sev.capitalize() if sev else "")
        rows.append(row)
    parts.append(_table(headers, rows))
    return "\n".join(parts)


_PEACH_BOUNDARY_LABELS = {
    "hardware_separation": "Hardware separation",
    "hardware_virtualization": "Hardware virtualization",
    "containerization": "Containerization",
    "data_segmentation": "Data segmentation",
    "network_segmentation": "Network segmentation",
    "identity_segmentation": "Identity segmentation",
}


def render_peach_isolation_review(peach: dict, section_num: int) -> str:
    parts = [f"## {section_num}. PEACH Tenant Isolation Review\n"]
    if not peach.get("applicable"):
        parts.append("**Applicable:** No — component is single-tenant.")
        if peach.get("rationale"):
            parts.append("")
            parts.append(peach["rationale"])
        return "\n".join(parts)

    parts.append(
        "**Applicable:** Yes — component serves multiple tenants from a shared deployment."
    )
    if peach.get("rationale"):
        parts.append("")
        parts.append(peach["rationale"])

    if peach.get("interfaces"):
        parts.append("")
        rows = []
        for i in peach["interfaces"]:
            rows.append(
                [
                    i["name"],
                    i["complexity"].capitalize(),
                    "Shared" if i["shared"] else "Per-tenant",
                    _PEACH_BOUNDARY_LABELS.get(i["boundary_type"], i["boundary_type"]),
                    ", ".join(i.get("hardening_gaps") or []) or "—",
                    ", ".join(i.get("finding_ids") or []) or "—",
                ]
            )
        parts.append(
            _table(
                ["Interface", "Complexity", "Sharing", "Boundary", "Hardening Gaps", "Findings"],
                rows,
            )
        )
    return "\n".join(parts)


def render_scanner_correlation(scanners: list[dict], section_num: int) -> str:
    parts = [f"## {section_num}. Scanner Correlation\n"]
    rows = [
        [
            s["tool"],
            "✅" if s.get("configured") else "❌" if s.get("configured") is False else "",
            s["result"],
            s.get("notes", ""),
        ]
        for s in scanners
    ]
    parts.append(_table(["Tool", "Configured", "Result", "Notes"], rows))
    return "\n".join(parts)


def render_report(report: dict) -> str:
    sections = [
        render_title(report),
        render_metadata(report["metadata"]),
    ]

    sections.append("\n---\n")
    sections.append(render_executive_summary(report["executive_summary"]))
    sections.append("\n---\n")
    sections.append(render_severity_criteria(report["severity_criteria"]))
    sections.append("\n---\n")
    sections.append(render_findings(report["findings"]))
    sections.append("\n---\n")
    sections.append(render_findings_summary(report["findings_summary"]))
    sections.append("\n---\n")
    sections.append(render_remediation_roadmap(report["remediation_roadmap"]))

    section_num = 6
    if "dependency_audit" in report:
        sections.append("\n---\n")
        sections.append(render_dependency_audit(report["dependency_audit"], section_num))
        section_num += 1

    if "negative_results" in report:
        sections.append("\n---\n")
        sections.append(render_negative_results(report["negative_results"], section_num))
        section_num += 1

    if "peach_isolation_review" in report:
        sections.append("\n---\n")
        sections.append(
            render_peach_isolation_review(report["peach_isolation_review"], section_num)
        )
        section_num += 1

    if "asvs_coverage" in report:
        sections.append("\n---\n")
        sections.append(render_asvs_coverage(report["asvs_coverage"], section_num))
        section_num += 1

    if "scanner_correlation" in report:
        sections.append("\n---\n")
        sections.append(render_scanner_correlation(report["scanner_correlation"], section_num))
        section_num += 1

    if report.get("footer"):
        sections.append("\n---\n")
        sections.append(f"*{_clean_inline(report['footer'])}*")

    return "\n".join(sections) + "\n"


def render_from_report(report: Report, output: Path | None = None) -> str:
    """Render a typed Report to markdown or structured output."""
    if not HAS_CONTRACTS:
        raise ImportError("traust_contracts required")
    md = render_report(report.to_dict())
    if output is not None:
        output.write_text(md, encoding="utf-8")
    return md


# ---------------------------------------------------------------------------
# Threat models
# ---------------------------------------------------------------------------
#
# Same relationship as every other artifact: `threat-model.schema.json`
# defines the model, the JSON is authored and validated against it, and the
# Markdown is rendered from the validated document. The prose cannot
# disagree with the artifact because it is generated from it.

#: Provenance bullets, in contract order.
THREAT_PROVENANCE_FIELDS = (
    "mode",
    "date",
    "target",
    "inputs",
    "owner",
    "harness_version",
)

#: Section 4 columns, in contract order. `isolation_dimensions` is appended
#: only when some threat carries it (multi-tenant lens, optional).
THREAT_COLUMNS = (
    "id",
    "threat",
    "actor",
    "surface",
    "asset",
    "impact",
    "likelihood",
    "status",
    "controls",
    "evidence",
    "attack_refs",
)


def _cell(value) -> str:
    """One table cell. Lists join with ', '; a pipe would break the row."""
    if value is None:
        return ""
    if isinstance(value, list):
        value = ", ".join(str(v) for v in value)
    return str(value).replace("|", "\\|").replace("\n", " ").strip()


def _table(columns: tuple[str, ...], rows: list[dict]) -> list[str]:
    out = [
        "| " + " | ".join(columns) + " |",
        "|" + "|".join("---" for _ in columns) + "|",
    ]
    out.extend("| " + " | ".join(_cell(row.get(c)) for c in columns) + " |" for row in rows)
    return out


def _section(number: int, title: str, body: list[str]) -> list[str]:
    """A section is emitted even when empty.

    An absent section and an empty one are different claims: "no
    deprioritized threats" is a statement, "we never considered
    deprioritisation" is not. schema.md requires the headings in order.
    """
    return [f"## {number}. {title}", ""] + (body or ["_none_"]) + [""]


def render_threat_model(document: dict) -> str:
    """The Markdown view of a validated threat-model artifact.

    Renders every section schema.md requires, in order, so the output
    passes `traust reporting lint` and reads the same as an authored
    model. Optional sections that the document does not carry render as
    `_none_` rather than being dropped.
    """
    threats = document.get("threats") or []
    columns = THREAT_COLUMNS
    if any(t.get("isolation_dimensions") for t in threats):
        columns = (*columns, "isolation_dimensions")

    lines: list[str] = [f"# Threat model — {document.get('system', '')}".rstrip(), ""]

    lines += _section(1, "System context", [document["system_context"]]
                      if document.get("system_context") else [])
    lines += _section(2, "Assets", _table(
        ("asset", "description", "sensitivity"), document.get("assets") or [])
        if document.get("assets") else [])
    lines += _section(3, "Entry points & trust boundaries", _table(
        ("entry_point", "description", "trust_boundary", "reachable_assets"),
        document.get("entry_points") or [])
        if document.get("entry_points") else [])
    lines += _section(4, "Threats", _table(columns, threats) if threats else [])
    lines += _section(5, "Deprioritized", _table(
        ("threat", "reason"), document.get("deprioritized") or [])
        if document.get("deprioritized") else [])
    lines += _section(6, "Open questions", [
        f"- {q}" for q in document.get("open_questions") or []])

    provenance_block = document.get("provenance") or {}
    lines += _section(7, "Provenance", [
        f"- {field}: {provenance_block[field]}"
        for field in THREAT_PROVENANCE_FIELDS
        if provenance_block.get(field)
    ])

    lines += _section(8, "Recommended mitigations", _table(
        ("mitigation", "threat_ids", "closes_class", "effort"),
        document.get("mitigations") or [])
        if document.get("mitigations") else [])

    scenarios = document.get("attack_scenarios") or []
    body: list[str] = []
    for scenario in scenarios:
        body.append(f"### {scenario.get('id', '')} — {scenario.get('threat', '')}".rstrip(" —"))
        body.append("")
        for step in scenario.get("steps") or []:
            body.append(f"- {step}")
        body.append("")
    lines += _section(9, "Attack scenarios", body)

    lines += _section(10, "Tenant boundaries", _table(
        ("boundary_id", "interface", "kind", "exposure", "complexity", "privilege",
         "encryption", "authentication", "connectivity", "hygiene", "threat_ids",
         "isolation_review_ref"),
        document.get("tenant_boundaries") or [])
        if document.get("tenant_boundaries") else [])

    history = document.get("update_history") or []
    if history:
        lines += ["### Update history", ""]
        lines += _table(("date", "changes", "reason"), history)
        lines += [""]

    return "\n".join(lines).rstrip() + "\n"
