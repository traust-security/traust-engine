"""Shared escaping helpers for untrusted text reaching emitters.

Public, zero-coupling text-safety helpers — safe for app emitters to import
directly as ``from traust_engine.escaping import md_cell``.

Threat model per helper:

- ``esc_html``      — text node / attribute value in generated HTML.
- ``json_script``   — JSON embedded in an inline ``<script>``: the JSON
                      string ``</script>`` terminates the element early
                      regardless of JSON validity; ``<!--`` opens an
                      HTML comment hiding subsequent markup.
- ``md_cell``       — Markdown table cell: ``|`` forges columns,
                      newlines break the row, link/image syntax turns a
                      hostile title into a live link or fetch beacon.
- ``csv_cell``      — spreadsheet formula injection: a leading ``=``,
                      ``+``, ``-``, ``@``, tab or CR makes Excel/Sheets
                      execute the cell (CWE-1236).
- ``safe_slug``     — identifier from a CSV/manifest about to become a
                      path segment, API path, or cache filename.
"""

from __future__ import annotations

import html
import json
import re

__all__ = [
    "csv_cell",
    "esc_html",
    "json_script",
    "md_cell",
    "safe_slug",
]


def esc_html(s) -> str:
    """HTML-escape for text nodes and attribute values (quotes too)."""
    return html.escape(str(s), quote=True)


def json_script(obj) -> str:
    """JSON serialized for safe embedding inside an inline <script>.

    ``json.dumps`` output is NOT script-safe: a string containing
    ``</script>`` closes the element early and everything after it is
    attacker-controlled markup. Escape ``/`` after ``<`` and the HTML
    comment opener; both remain valid JSON/JS.
    """
    return json.dumps(obj).replace("</", "<\\/").replace("<!--", "<\\u0021--")


def md_cell(s) -> str:
    """Neutralize untrusted text for a Markdown table cell.

    Escapes column forgery (|), row breaks (newlines), and defangs
    link/image syntax so a hostile finding title cannot render as a
    live link or image-fetch beacon in Drive/GitLab/IDE previews.
    """
    out = str(s).replace("|", "\\|")
    out = re.sub(r"[\r\n]+", " ", out)
    out = re.sub(r"\]\(", "]\\(", out)
    out = re.sub(r"\bjavascript:", "javascriptː", out, flags=re.I)
    return out


def csv_cell(s) -> str:
    """Guard a CSV cell against spreadsheet formula injection.

    A leading =, +, -, @, tab, or CR makes Excel/Sheets evaluate the
    cell (CWE-1236). Prefix with a quote — the standard neutralization;
    numeric-looking values are left alone so counts stay sortable.
    """
    text = str(s)
    if text[:1] in ("=", "+", "-", "@", "\t", "\r") and not _NUMERIC_RX.match(text):
        return "'" + text
    return text


_NUMERIC_RX = re.compile(r"^[+-]?\d[\d,._]*(?:[eE][+-]?\d+)?%?$")

_SLUG_RX = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


def safe_slug(s, *, segments: int = 1) -> str | None:
    """Validate an identifier about to become a path/API segment.

    Returns the slug unchanged when it is ``segments`` slash-separated
    tokens of [A-Za-z0-9._-] (no leading dot/dash, no dot-runs), else
    None — callers must treat None as a rejected record, never
    substitute a default.
    """
    text = str(s)
    parts = text.split("/")
    if len(parts) != segments:
        return None
    for part in parts:
        if not _SLUG_RX.fullmatch(part) or ".." in part:
            return None
    return text
