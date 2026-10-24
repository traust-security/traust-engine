"""Review-surface tags survive the threat model's Markdown rendering.

The JSON is the artifact; the `.md` is rendered from it, linted as the prose
contract, and parsed back by the corpus. A `review_surfaces` tag on a threat
or entry point (traust-contracts 0.57.0), or on a deprioritized threat (0.60.0), must show in the rendering, pass the
linter, and come back out of the parser.
"""

import copy

from traust_engine.reporting import lint, render

DOC = {
    "system": "example",
    "provenance": {
        "mode": "bootstrap",
        "date": "2026-01-02",
        "target": "https://example.test/repo @ abc1234",
    },
    "assets": [{"asset": "tokens", "description": "API tokens", "sensitivity": "high"}],
    "entry_points": [
        {
            "entry_point": "api",
            "description": "public REST API",
            "trust_boundary": "internet -> service",
            "reachable_assets": "tokens",
            "review_surfaces": ["credential-acceptance", "scope-enforcement"],
        },
        {
            "entry_point": "cli",
            "description": "operator CLI",
            "trust_boundary": "operator -> service",
            "reachable_assets": "tokens",
        },
    ],
    "threats": [
        {
            "id": "T1",
            "threat": "Refresh token accepted as an access token",
            "actor": ["remote_auth"],
            "surface": "api",
            "asset": "tokens",
            "impact": "high",
            "likelihood": "likely",
            "status": "unmitigated",
            "controls": "none",
            "evidence": [],
            "attack_refs": ["T1550"],
            "review_surfaces": ["credential-acceptance"],
        },
        {
            "id": "T2",
            "threat": "Operator CLI misuse",
            "actor": ["insider"],
            "surface": "cli",
            "asset": "tokens",
            "impact": "medium",
            "likelihood": "rare",
            "status": "mitigated",
            "controls": "audit log",
            "evidence": [],
            "attack_refs": [],
        },
    ],
}


def _md(tmp_path, document):
    path = tmp_path / "repo-threat-model.md"
    path.write_text(render.render_threat_model(document), encoding="utf-8")
    return path


def _rows(markdown, header_start):
    lines = markdown.splitlines()
    i = next(n for n, line in enumerate(lines) if line.startswith(header_start))
    header = [c.strip() for c in lines[i].strip("|").split("|")]
    rows = []
    for line in lines[i + 2 :]:
        if not line.startswith("|"):
            break
        rows.append(
            dict(zip(header, (c.strip() for c in line.strip("|").split("|")), strict=False))
        )
    return header, rows


def test_tags_render_in_sections_3_and_4(tmp_path):
    markdown = _md(tmp_path, DOC).read_text()
    header, rows = _rows(markdown, "| entry_point |")
    assert header[-1] == "review_surfaces"
    assert rows[0]["review_surfaces"] == "credential-acceptance, scope-enforcement"
    assert rows[1]["review_surfaces"] == ""
    header, rows = _rows(markdown, "| id |")
    assert header[-1] == "review_surfaces"
    assert rows[0]["review_surfaces"] == "credential-acceptance"


def test_the_tagged_rendering_passes_the_linter(tmp_path):
    errors, _ = lint.lint_file(_md(tmp_path, DOC))
    assert errors == []


def test_an_untagged_model_renders_exactly_as_before(tmp_path):
    untagged = copy.deepcopy(DOC)
    for row in untagged["entry_points"] + untagged["threats"]:
        row.pop("review_surfaces", None)
    markdown = _md(tmp_path, untagged).read_text()
    assert "review_surfaces" not in markdown
    assert lint.lint_file(_md(tmp_path, untagged))[0] == []


def test_the_linter_rejects_an_unknown_surface(tmp_path):
    path = _md(tmp_path, DOC)
    path.write_text(path.read_text().replace("| credential-acceptance |", "| made-up-surface |"))
    errors, _ = lint.lint_file(path)
    assert any("made-up-surface" in e for e in errors), errors


def _with_deprioritized(rows):
    document = copy.deepcopy(DOC)
    document["deprioritized"] = rows
    return document


def test_section_5_tags_render_and_lint(tmp_path):
    document = _with_deprioritized(
        [
            {
                "threat": "Webhook replay",
                "reason": "no inbound webhooks",
                "review_surfaces": ["credential-acceptance"],
            },
            {"threat": "physical access", "reason": "out of scope"},
        ]
    )
    path = _md(tmp_path, document)
    header, rows = _rows(path.read_text(), "| threat | reason |")
    assert header == ["threat", "reason", "review_surfaces"]
    assert rows[0]["review_surfaces"] == "credential-acceptance"
    assert rows[1]["review_surfaces"] == ""
    assert lint.lint_file(path)[0] == []


def test_untagged_section_5_keeps_two_columns(tmp_path):
    document = _with_deprioritized([{"threat": "physical access", "reason": "out of scope"}])
    header, _ = _rows(_md(tmp_path, document).read_text(), "| threat | reason |")
    assert header == ["threat", "reason"]


def test_the_linter_rejects_an_unknown_section_5_surface(tmp_path):
    document = _with_deprioritized(
        [{"threat": "Webhook replay", "reason": "n/a", "review_surfaces": ["outbound-fetch"]}]
    )
    path = _md(tmp_path, document)
    path.write_text(path.read_text().replace("| outbound-fetch |", "| made-up-surface |"))
    errors, _ = lint.lint_file(path)
    assert any("section 5" in e and "made-up-surface" in e for e in errors), errors
