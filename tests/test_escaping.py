"""Tests for traust_engine._util.escaping — the shared untrusted-text helpers."""

import json

from traust_engine import escaping as esc


def test_esc_html_escapes_quotes_and_tags():
    assert esc.esc_html('<img src=x onerror="a">') == "&lt;img src=x onerror=&quot;a&quot;&gt;"


def test_json_script_neutralizes_script_close():
    out = esc.json_script({"t": "</script><script>alert(1)</script>"})
    assert "</script>" not in out
    assert "<!--" not in esc.json_script({"t": "<!--"})
    # stays valid JSON after the escapes
    assert json.loads(out)["t"] == "</script><script>alert(1)</script>"


def test_md_cell_blocks_column_forgery_and_links():
    assert esc.md_cell("a|b") == "a\\|b"
    assert esc.md_cell("x\ny") == "x y"
    assert "](" not in esc.md_cell("![beacon](https://evil/x.png)")
    assert "javascript:" not in esc.md_cell("[x](javascript:alert(1))").lower()


def test_csv_cell_neutralizes_formulas_keeps_numbers():
    assert esc.csv_cell("=HYPERLINK(evil)") == "'=HYPERLINK(evil)"
    assert esc.csv_cell("@SUM(A1)") == "'@SUM(A1)"
    assert esc.csv_cell("+cmd|' /C calc'!A0") == "'+cmd|' /C calc'!A0"
    assert esc.csv_cell("-12.5") == "-12.5"
    assert esc.csv_cell("+7") == "+7"
    assert esc.csv_cell("plain") == "plain"


def test_safe_slug_shapes():
    assert esc.safe_slug("repo-x") == "repo-x"
    assert esc.safe_slug("org/repo", segments=2) == "org/repo"
    assert esc.safe_slug("org/repo") is None  # wrong arity
    assert esc.safe_slug("../etc", segments=1) is None  # traversal
    assert esc.safe_slug("a/../b", segments=2) is None
    assert esc.safe_slug("-flag") is None  # leading dash
    assert esc.safe_slug("", segments=1) is None
