"""Locating a patch's files in the installed tree and reporting hunk presence.

A patch's paths are relative to the upstream repository; the installed tree is a
module zip or an sdist, often a sub-directory of that repository under a
version-stamped root. Paths are matched by stripping a consistent number of
leading components from every patch path, and choosing the strip that finds
the most files. A file is never matched by base name alone, so an unrelated
file with the same name (`lib/web/cache/cache.js` for `lib/util/cache.js`) is
never reported as the fix's target.
"""

from __future__ import annotations

import re
from pathlib import Path

from traust_engine.applicability.fixes import FileChange

# a Maven module's sources sit under <module>/src/main/java/ in the repository
MAX_STRIP = 6


def root_of(tree: Path) -> Path:
    """The package root of an extracted archive: descend while the directory holds
    a single sub-directory and no files (a Go module zip nests
    `example.com/lib@v1.4.0/`; an sdist has one `name-version/`)."""
    while True:
        entries = [p for p in tree.iterdir() if not p.name.startswith(".")]
        if len(entries) != 1 or not entries[0].is_dir():
            return tree
        tree = entries[0]


def anchor(files: list[FileChange], root: Path) -> tuple[int, dict[str, Path]]:
    """(strip, {patch path: installed file}) for the strip that matches most files."""
    best: tuple[int, dict[str, Path]] = (0, {})
    for strip in range(MAX_STRIP + 1):
        found: dict[str, Path] = {}
        for f in files:
            parts = f.path.split("/")
            if len(parts) <= strip:
                continue
            p = root.joinpath(*parts[strip:])
            if p.is_file():
                found[f.path] = p
        if len(found) > len(best[1]):
            best = (strip, found)
    return best


def _norm(line: str) -> str:
    return re.sub(r"\s+", " ", line).strip()


def presence(files: list[FileChange], root: Path) -> list[dict]:
    """Per file: where it is installed, and per hunk how many removed and added
    lines appear there (whitespace-normalized). Blank lines are ignored."""
    _strip, found = anchor(files, root)
    out = []
    for f in files:
        installed = found.get(f.path)
        row: dict = {
            "patch_path": f.path,
            "installed_path": str(installed.relative_to(root)) if installed else None,
            "hunks": [],
        }
        if installed is not None:
            text = {_norm(x) for x in installed.read_text(errors="replace").splitlines()}
            for h in f.hunks:
                rem = [n for x in h["removed"] if (n := _norm(x))]
                add = [n for x in h["added"] if (n := _norm(x))]
                row["hunks"].append(
                    {
                        "removed_lines": len(rem),
                        "removed_present": sum(x in text for x in rem),
                        "added_lines": len(add),
                        "added_present": sum(x in text for x in add),
                    }
                )
        out.append(row)
    return out
