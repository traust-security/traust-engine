#!/usr/bin/env python3
"""CI gates: conventional-commit lint.

Used by:
  - .githooks/commit-msg  (subject validation)
  - .gitlab-ci.yml        (range command)
"""

from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

# --- Conventional commit patterns ---

HEADER_RE = re.compile(
    r"^(?P<type>build|chore|ci|docs|feat|fix|perf|refactor|revert|style|test)"
    r"(?:\((?P<scope>[^)]+)\))?(?P<breaking>!)?: (?P<subject>.+)$"
)
MERGE_RE = re.compile(r"^Merge (branch|commit|remote-tracking branch|pull request) ")
REVERT_RE = re.compile(r"^Revert ")
HINT = "expected: type(scope): subject  (e.g. feat(adapters): add joern cache)"


@dataclass(frozen=True)
class Commit:
    sha: str
    subject: str
    body: str


class GitError(Exception):
    pass


# --- Git helpers ---


def _git(*args: str, cwd: Path | None = None) -> str:
    try:
        return subprocess.run(
            ("git", *args), cwd=cwd, check=True, text=True, capture_output=True
        ).stdout
    except subprocess.CalledProcessError as exc:
        raise GitError(f"git {' '.join(args)} failed") from exc


def _resolve(ref: str, *, cwd: Path | None = None) -> None:
    _git("rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}", cwd=cwd)


def _log(range_spec: str, *, cwd: Path | None = None) -> list[Commit]:
    commits: list[Commit] = []
    for entry in _git("log", "--format=%H%x1f%s%x1f%b%x1e", range_spec, cwd=cwd).split("\x1e"):
        entry = entry.strip("\n")
        if not entry:
            continue
        sha, subject, body = entry.split("\x1f", 2)
        commits.append(Commit(sha=sha, subject=subject, body=body))
    return commits


# --- Conventional commit validation ---


def validate_subject(subject: str) -> str | None:
    """Return error message if subject is non-conventional, else None."""
    if MERGE_RE.match(subject) or REVERT_RE.match(subject):
        return None
    if not HEADER_RE.match(subject):
        return f"non-conventional subject: {subject!r}"
    return None


def validate_range(base: str, head: str, *, cwd: Path | None = None) -> str | None:
    """Validate all commit subjects in base..head. Returns first error or None."""
    _resolve(base, cwd=cwd)
    _resolve(head, cwd=cwd)
    for commit in _log(f"{base}..{head}", cwd=cwd):
        if err := validate_subject(commit.subject):
            return f"{commit.sha[:8]}: {err}"
    return None


# --- CLI ---


def _fail_commit(message: str) -> int:
    print("conventional-commit check failed:", file=sys.stderr)
    print(f"  {message}", file=sys.stderr)
    print(f"  {HINT}", file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if not args:
        print("usage: gates.py {subject|range} ...", file=sys.stderr)
        return 2

    match args[0]:
        case "subject":
            if len(args) < 2:
                print("usage: gates.py subject <message-file>", file=sys.stderr)
                return 2
            text = Path(args[1]).read_text(encoding="utf-8")
            subject = text.splitlines()[0].strip() if text else ""
            if err := validate_subject(subject):
                return _fail_commit(err)
            return 0

        case "range":
            if len(args) < 3:
                print("usage: gates.py range <base> <head>", file=sys.stderr)
                return 2
            try:
                if err := validate_range(args[1], args[2]):
                    return _fail_commit(err)
            except GitError as exc:
                print(f"gates: {exc}", file=sys.stderr)
                return 1
            return 0

        case _:
            print(f"unknown command: {args[0]}", file=sys.stderr)
            print("usage: gates.py {subject|range} ...", file=sys.stderr)
            return 2


if __name__ == "__main__":
    sys.exit(main())
