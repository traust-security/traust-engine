"""Structured threats from a per-subject threat model.

Threat models are prose Markdown, one per subject, filed beside that
subject's audit -- 7,584 of the corpus's 8,604 subjects have one. The
threats live in a documented table (section `4. Threats`), so the parse is
deterministic, and `traust_engine.reporting.lint` already owns it.

This is the ingest path for that data. The alternative -- projecting the
fleet-wide register instead -- reads the DASHBOARD'S OWN OUTPUT, since
the register is written into the dashboards tree by the builder that
renders it. That is circular, and it also models the wrong grain: the
estate has 7,584 threat models belonging to subjects, not one document of
82,850 threats belonging to nothing.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from traust_engine.reporting.lint import (
    THREATS_COLUMN_VARIANTS,
    parse_sections,
    parse_table,
)

#: Ordering weights. The product is a TRIAGE ORDER, never a calibrated risk
#: value and never comparable to CVSS. Enums come from the threat-model
#: schema (harnessing/2-threat-model/threat-model/schema.md), which states
#: that the section headings, column order and enum values ARE a contract.
IMPACT_W = {"low": 1, "medium": 2, "high": 4, "critical": 8, "existential": 16}
LIKELIHOOD_W = {"very_rare": 1, "rare": 2, "possible": 4, "likely": 8, "almost_certain": 16}


def _split(value: str) -> list[str]:
    return [part.strip() for part in re.split(r"[,;]\s*", value or "") if part.strip()]


def parse_threats(path: Path, root: Path, subject_id: str | None = None) -> dict[str, Any] | None:
    """Parse one threat model into a structured document, or None.

    Returns None when the model does not carry a recognised threats table:
    a model that cannot be parsed must be visibly absent rather than
    silently counted as having no threats.

    `key` is `<product>/<slug>:<id>`, matching what the register builder
    emits, so the two agree on identity. The in-model `id` alone is not
    unique -- every model numbers its threats from T1.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    sections = dict(parse_sections(text))
    columns, rows = parse_table(sections.get("4. Threats", []))
    if columns not in THREATS_COLUMN_VARIANTS:
        return None

    relative = str(path.relative_to(root))
    parts = path.relative_to(root).parts
    product = parts[1] if len(parts) > 2 else parts[0]
    slug = path.parent.name

    threats = []
    for row_values in rows:
        if len(row_values) != len(columns):
            continue
        row = dict(zip(columns, row_values, strict=False))
        threat = {
            "key": f"{product}/{slug}:{row['id']}",
            "id": row["id"],
            "model": relative,
            "product": product,
            "threat": row["threat"],
            "actors": _split(row.get("actor", "")),
            "surface": row.get("surface", ""),
            "asset": row.get("asset", ""),
            "impact": row.get("impact", ""),
            "likelihood": row.get("likelihood", ""),
            "status": row.get("status", ""),
            "controls": row.get("controls", ""),
            "evidence": _split(row.get("evidence", "")),
            # Rows from the optional LINDDUN privacy overlay carry a
            # leading `linddun:` tag in the threat cell (schema.md S4).
            "linddun": row["threat"].lower().startswith("linddun:"),
            "score": IMPACT_W.get(row.get("impact", ""), 0)
            * LIKELIHOOD_W.get(row.get("likelihood", ""), 0),
        }
        if subject_id:
            threat["subject_id"] = subject_id
        # Column 11, DEFAULT since harness 0.82.0 and the input to the
        # attack-coverage rollup. Omitting it silently drops every MITRE
        # mapping the estate has recorded.
        attack_refs = _split(row.get("attack_refs", ""))
        if attack_refs:
            threat["attack_refs"] = attack_refs
        # Column 12, OPTIONAL, multi-tenant services only (PEACH lens).
        dimensions = _split(row.get("isolation_dimensions", ""))
        if dimensions:
            threat["isolation_dimensions"] = dimensions
        threats.append(threat)

    if not threats:
        return None
    return {
        "version": 1,
        "meta": {"models": 1, "threat_count": len(threats), "root": relative},
        "threats": threats,
    }
