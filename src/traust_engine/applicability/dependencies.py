"""The installed package's own dependencies, where the fix's code uses them.

Whether a version is affected can depend on code the package imports rather than
code it ships: multer's crash depends on what busboy passes it for an empty field
name. When a file the fix touches imports one of the installed version's direct
dependencies, that dependency's source joins the packet, up to MAX_DEPS.

Direct dependencies come from the module's own go.mod for Go (exact versions)
and from deps.dev's resolved graph for npm, PyPI, Maven and Cargo. A dependency
that can't be resolved or fetched is recorded, never silently skipped.
"""

from __future__ import annotations

import re
from pathlib import Path

from traust_engine.applicability.fetch import Fetcher, FetchRefused

MAX_DEPS = 3


def go_requires(root: Path) -> list[tuple[str, str]]:
    """(module, version) for every require in the module zip's go.mod."""
    gomod = root / "go.mod"
    if not gomod.is_file():
        return []
    text = gomod.read_text(errors="replace")
    out = []
    for block in re.findall(r"(?ms)^require\s*\((.*?)^\)", text):
        out += re.findall(r"(?m)^\s*(\S+)\s+(v\S+)", block)
    out += re.findall(r"(?m)^require\s+(\S+)\s+(v\S+)", text)
    return [(m, v.removeprefix("v")) for m, v in out]


def direct(
    ecosystem: str, name: str, version: str, root: Path, resolver
) -> tuple[list[tuple[str, str]], str | None]:
    """(direct dependencies, failure reason or None)."""
    if ecosystem == "Go":
        return go_requires(root), None
    if resolver is None:
        return [], "no dependency resolver configured"
    res = resolver.dependencies(ecosystem, name, version)
    if not res.ok:
        return [], f"deps.dev {res.status}: {res.detail}".strip()
    return [(n, v) for n, v, rel in res.nodes if rel == "DIRECT"], None


def imports(ecosystem: str, dependency: str, text: str) -> bool:
    """Whether source text imports the dependency (a lead, not a proof)."""
    d = re.escape(dependency)
    if ecosystem == "npm":
        pattern = rf"""(?:require\(\s*|from\s+|import\s+)['"]{d}(?:['"/])"""
    elif ecosystem == "PyPI":
        module = re.escape(re.sub(r"[-.]", "_", dependency.lower()))
        pattern = rf"(?m)^\s*(?:from|import)\s+{module}\b"
    elif ecosystem == "Maven":
        group = re.escape(dependency.split(":", 1)[0])
        pattern = rf"(?m)^\s*import\s+(?:static\s+)?{group}\."
    elif ecosystem == "crates.io":
        crate = re.escape(dependency.replace("-", "_"))
        pattern = rf"\b(?:use|extern crate)\s+{crate}\b|\b{crate}::"
    elif ecosystem == "Go":
        pattern = rf'"{d}(?:/[^"]*)?"'
    else:
        return False
    return re.search(pattern, text, flags=re.IGNORECASE if ecosystem == "PyPI" else 0) is not None


def gather(
    ecosystem: str,
    name: str,
    version: str,
    root: Path,
    touched: list[Path],
    resolver,
    fetcher: Fetcher,
    dest: Path,
) -> tuple[list[dict], list[dict]]:
    """(dependency sources, dependency gaps) for the files the fix touches."""
    if not touched:
        return [], []
    deps, failure = direct(ecosystem, name, version, root, resolver)
    if failure:
        return [], [{"reason": failure}]
    texts = {p: p.read_text(errors="replace") for p in touched}
    used = []
    for dep, ver in deps:
        by = [str(p.relative_to(root)) for p, t in texts.items() if imports(ecosystem, dep, t)]
        if by:
            used.append((dep, ver, by))
    sources, gaps = [], []
    for dep, ver, by in used[:MAX_DEPS]:
        d = dest / re.sub(r"[^A-Za-z0-9._@-]+", "_", f"{dep}@{ver}")
        try:
            src = fetcher.source(ecosystem, dep, ver, d)
        except (FetchRefused, OSError, ValueError) as e:
            gaps.append({"package": dep, "version": ver, "reason": f"{type(e).__name__}: {e}"})
            continue
        sources.append({"package": dep, "version": ver, "imported_by": by, "dir": d, **src})
    for dep, ver, _ in used[MAX_DEPS:]:
        gaps.append({"package": dep, "version": ver, "reason": "over MAX_DEPS"})
    return sources, gaps
