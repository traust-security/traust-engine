#!/usr/bin/env python3
"""Estate-data guard: keep one deployment's figures out of a public repo.

This repository is PUBLIC. Anything committed here is published, and
unlike a credential -- which is rotated and forgotten -- a corpus figure
is a permanent statement about the size, backlog and error rate of the
deployment that produced it. There is nothing to rotate.

The failure is not carelessness about secrets. It is writing an accurate
comment: "measured 2026-08-06, N of M". Every instinct is right except
that the number is one organisation's and the file is public. It has
happened repeatedly, including in a schema `description` that ships
inside the contract itself, where every adopter reads it.

Standalone by design: this repo does not depend on the harness, so the
guard cannot live there. Keep the copies behaviourally identical.

  --staged   scan only the lines being ADDED (the pre-commit mode);
             in a merge, only lines new to both parents.
             A public repo already carrying such figures cannot adopt a
             whole-tree gate without blocking every commit, and a gate
             people bypass is not a gate. Blocking what is ADDED stops
             the bleeding now; the existing debt is a reviewed burndown.

A genuinely public figure takes an inline `estate-data-ok: <reason>`.

Exit 0 when clean, 1 on any finding.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

#: Comma-grouped numbers of four digits or more. Narrow on purpose:
#: years, versions, CWE ids and ports carry no comma, and a figure of
#: this shape in prose is almost always a measurement.
COUNT_RE = re.compile(r"(?<![{,\d])\b\d{1,3}(?:,\d{3})+\b(?![,\d}])")

#: A regex quantifier -- `{36,255}` -- is not a measurement.
QUANTIFIER_RE = re.compile(r"\{\d+,\d+\}")

#: A multi-line source reference -- `oauthproxy.go:525,685`,
#: `login.go:127,157`. The comma separates two LINE NUMBERS in one file,
#: which is the most useful thing a finding can cite, and it carries no
#: information about the estate at all. Discarded like a quantifier
#: rather than narrowed into COUNT_RE, because a line number four digits
#: long is ordinary.
SOURCE_LINE_REF_RE = re.compile(r"\.\w+:\d+(?:,\d+)+")

#: A CONFIGURED THRESHOLD, not a measurement: `C >= 8,000`, `C >= 8,000`.
#: The distinction is the whole point of this gate -- a measurement says
#: what this deployment IS, a threshold says what the policy DOES, and
#: only the first is a disclosure. Bare `=` is deliberately excluded:
#: `X = 1,234` is an assignment (estate-data-ok: invented), and silencing
#: assignments would hide the
#: most ordinary way a figure gets hard-coded into a script.
THRESHOLD_RE = re.compile(r"\b[A-Z]\s*(?:>=|<=|[><≥≤])\s*\d{1,3}(?:,\d{3})+")

#: Currency. Requires a comma group or decimals so shell `$0` and JSON
#: `$defs` do not match; a bare `$5` is not the disclosure this guards.
MONEY_RE = re.compile(r"[$£€]\s?\d{1,3}(?:,\d{3})+(?:\.\d+)?|[$£€]\s?\d+\.\d{2}\b")

WAIVER_RE = re.compile(r"estate-data-ok:\s*\S")
ALLOWED = {"CHANGELOG.md"}
SKIP_SUFFIXES = (".lock", ".svg", ".png", ".jpg", ".gz", ".db", ".ipynb")


def _git(root: Path, *args: str) -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True, check=True
    ).stdout
    return [line for line in out.splitlines() if line]


def is_public(root: Path) -> bool | None:
    """True/False from the forge; None when undeterminable.

    Callers treat None as public. Being wrong that way costs a false
    alarm; being wrong the other way publishes.
    """
    try:
        url = _git(root, "remote", "get-url", "origin")[0]
    except (subprocess.CalledProcessError, IndexError):
        return None
    slug = re.sub(r"^.*github\.com[:/]", "", url).removesuffix(".git")
    try:
        r = subprocess.run(
            ["gh", "repo", "view", slug, "--json", "visibility"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    try:
        return json.loads(r.stdout)["visibility"] == "PUBLIC"
    except (json.JSONDecodeError, KeyError):
        return None


HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def _merge_side_lines(root: Path, rel: str) -> set[str]:
    """Lines of `rel` as committed on MERGE_HEAD; empty outside a merge.

    A merge stages every line the other side changed, and that side has
    already been through this gate (or predates it). Re-flagging it
    blocks every upstream sync on debt nobody is adding -- which is what
    blocked a CI branch merge. Only lines new to BOTH parents,
    i.e. what the merge itself authors, are checked.
    """
    try:
        _git(root, "rev-parse", "-q", "--verify", "MERGE_HEAD")
        blob = _git(root, "show", f"MERGE_HEAD:{rel}")
    except subprocess.CalledProcessError:
        return set()
    return set(blob)


def _added_lines(root: Path) -> dict[str, list[tuple[int, str]]]:
    """Staged ADDED lines per file, numbered as in the index.

    `--staged` means "what this commit adds". Scanning the whole of each
    touched file made a one-line fix to a file carrying old figures
    unshippable, the very burndown-first trap the mode exists to avoid.
    """
    out = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "-c",
            "core.quotePath=false",
            "diff",
            "--cached",
            "-U0",
            "--no-color",
            "--no-ext-diff",
            "--src-prefix=a/",
            "--dst-prefix=b/",
            "--diff-filter=ACM",
        ],
        capture_output=True,
        text=True,
        check=True,
        errors="replace",
    ).stdout
    added: dict[str, list[tuple[int, str]]] = {}
    rel, number, header = None, 0, False
    for line in out.splitlines():
        # File headers run from `diff --git` to the first hunk; inside a
        # hunk, an added line that itself begins `++` looks like `+++`.
        if line.startswith("diff --git "):
            rel, header = None, True
            continue
        if header:
            if line.startswith("+++ b/"):
                rel = line[6:]
            elif hunk := HUNK_RE.match(line):
                number, header = int(hunk.group(1)), False
            continue
        if hunk := HUNK_RE.match(line):
            number = int(hunk.group(1))
            continue
        if rel and line.startswith("+"):
            added.setdefault(rel, []).append((number, line[1:]))
            number += 1
    for rel in list(added):
        theirs = _merge_side_lines(root, rel)
        if theirs:
            added[rel] = [(n, t) for n, t in added[rel] if t not in theirs]
    return added


def _whole_files(root: Path) -> dict[str, list[tuple[int, str]]]:
    files: dict[str, list[tuple[int, str]]] = {}
    for rel in _git(root, "ls-files"):
        path = root / rel
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        files[rel] = list(enumerate(text.splitlines(), 1))
    return files


def scan(root: Path, *, staged: bool = False) -> list[dict]:
    findings = []
    for rel, lines in (_added_lines(root) if staged else _whole_files(root)).items():
        if rel in ALLOWED or rel.endswith(SKIP_SUFFIXES):
            continue
        for number, line in lines:
            if WAIVER_RE.search(line):
                continue
            probe = QUANTIFIER_RE.sub("", line)
            probe = SOURCE_LINE_REF_RE.sub("", probe)
            probe = THRESHOLD_RE.sub("", probe)
            for hit in COUNT_RE.findall(probe) + MONEY_RE.findall(probe):
                findings.append(
                    {"file": rel, "line": number, "match": hit, "text": line.strip()[:120]}
                )
    return findings


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("repo", nargs="?", default=".", type=Path)
    ap.add_argument("--staged", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--assume-public", action="store_true")
    args = ap.parse_args(argv)
    root = args.repo.resolve()

    public = True if args.assume_public else is_public(root)
    if public is False:
        if not args.quiet:
            print("estate-data: repository is PRIVATE — nothing to guard")
        return 0
    if public is None and not args.quiet:
        print("estate-data: visibility UNKNOWN — treating as public", file=sys.stderr)

    findings = scan(root, staged=args.staged)
    if not findings:
        if not args.quiet:
            print("✓ no estate data")
        return 0
    print(f"\n✗ {len(findings)} estate-data finding(s) in a PUBLIC repo:\n", file=sys.stderr)
    for f in findings[:30]:
        print(f"    {f['file']}:{f['line']}  {f['text']}", file=sys.stderr)
    if len(findings) > 30:
        print(f"    … and {len(findings) - 30} more", file=sys.stderr)
    print(
        "\nA measurement of one deployment does not belong in a public repo. "
        "Generalise it — the engineering point survives without the number — "
        "or, if the figure is genuinely public, add an inline "
        "`estate-data-ok: <reason>`.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
