"""Regression: traust_engine is a library — no runnable CLI entry points, apart from the
continuous-ops service's one (`traust-engine`, design D6: the engine runs the pack)."""

from __future__ import annotations

import ast
import re
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "traust_engine"
SERVICE = SRC / "ops" / "cli.py"


def _module_paths() -> list[Path]:
    return sorted(p for p in SRC.rglob("*.py") if p.is_file() and p != SERVICE)


def test_no_main_guard_in_source():
    offenders = []
    for path in _module_paths():
        text = path.read_text(encoding="utf-8")
        if 'if __name__ == "__main__"' in text or "if __name__ == '__main__'" in text:
            offenders.append(path.relative_to(SRC))
    assert offenders == [], f"__main__ blocks remain: {offenders}"


def test_no_argparse_in_source():
    offenders = []
    for path in _module_paths():
        text = path.read_text(encoding="utf-8")
        if re.search(r"\bargparse\b", text):
            offenders.append(path.relative_to(SRC))
    assert offenders == [], f"argparse remains: {offenders}"


def test_no_def_main_in_source():
    offenders = []
    for path in _module_paths():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name == "main":
                offenders.append(path.relative_to(SRC))
                break
    assert offenders == [], f"def main remains: {offenders}"
