"""Choosing an advisory's fix commit and reading its patch.

An OSV record links commits without saying which one is the fix. GHSA records
type commit links `WEB`, and the first link is often the commit that introduced
the feature, a refactor, or a pull request bundling several commits. So a fix is
chosen, not assumed:

- references are ranked: a GIT range's `fixed` commit, then `FIX` references,
  then other commit or pull-request links;
- each patch is scored on whether it touches source files present in the
  installed tree, whether its commit message names the advisory, and whether it
  only adds code (the shape of a feature introduction), and whether it is a
  release or version-bump commit (a fix's release, not the fix);
- a bundle is narrowed to the commits that name the advisory, when any do.

The choice and every alternative's score are recorded, so a reviewer can see why.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field

TEST_PATH = re.compile(
    r"(^|/)(tests?|__tests__|spec|testdata|fixtures?)/|_test\.go$|(^|/)test_[^/]*\.py$|"
    r"[^/]*_test\.py$|\.test\.|\.spec\.|Test\.java$"
)
COMMIT_OR_PR = re.compile(r"/(?:-/)?commit/[0-9a-f]{7,40}|/pull/\d+|/merge_requests/\d+")
MAX_PATCHES = 6  # a fix often has one commit per release branch


@dataclass
class FileChange:
    path: str
    hunks: list[dict] = field(default_factory=list)  # {"removed": [...], "added": [...]}


@dataclass
class Commit:
    sha: str
    subject: str
    message: str
    files: list[FileChange]


def references(
    vuln: dict, forges: frozenset[str], aliases: list[dict] = ()
) -> list[tuple[int, str]]:
    """(rank, url) for every linked fix candidate on an allow-listed forge, best first.

    `aliases` are the records of the advisory's aliases. A GHSA or PYSEC record
    often links no commit while its CVE record (converted from NVD) carries the
    fix commits as GIT ranges, one per release branch.
    """
    out: list[tuple[int, str]] = []
    for rec in (vuln, *aliases):
        out += _links(rec)
    seen: set[str] = set()
    ranked = []
    for rank, url in sorted(out, key=lambda t: t[0]):
        url = url.split("#")[0].split("?")[0]
        if (urllib.parse.urlsplit(url).hostname or "") in forges and url not in seen:
            seen.add(url)
            ranked.append((rank, url))
    return ranked


def _links(vuln: dict) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    for aff in vuln.get("affected") or []:
        for rng in aff.get("ranges") or []:
            if rng.get("type") == "GIT" and rng.get("repo"):
                base = rng["repo"].rstrip("/").removesuffix(".git")
                for ev in rng.get("events") or []:
                    if ev.get("fixed"):
                        out.append((0, f"{base}/commit/{ev['fixed']}"))
    for ref in vuln.get("references") or []:
        url = ref.get("url") or ""
        if ref.get("type") == "FIX":
            out.append((1, url))
        elif COMMIT_OR_PR.search(url):
            out.append((2, url))
    return out


def patch_url(url: str) -> str | None:
    m = re.match(r"(https://github\.com/[^/]+/[^/]+/(?:commit/[0-9a-f]{7,40}|pull/\d+))", url)
    if m:
        return m.group(1) + ".patch"
    m = re.match(r"(https://gitlab\.com/.+?/-/(?:commit/[0-9a-f]{7,40}|merge_requests/\d+))", url)
    if m:
        return m.group(1) + ".patch"
    return None


def parse_mbox(text: str) -> list[Commit]:
    """Split a git format-patch stream into commits with their non-test file changes."""
    commits: list[Commit] = []
    chunks = re.split(r"(?m)^From ([0-9a-f]{40}) ", text)
    pairs = list(zip(chunks[1::2], chunks[2::2], strict=False)) or [("", text)]
    for sha, body in pairs:
        head, _, diff = body.partition("\ndiff --git ")
        subj = re.search(r"(?m)^Subject: (?:\[PATCH[^\]]*\] )?(.*(?:\n [^\n]+)*)", head)
        subject = re.sub(r"\s+", " ", subj.group(1)).strip() if subj else ""
        commits.append(Commit(sha, subject, head, _files("diff --git " + diff if diff else "")))
    return commits


def _files(diff: str) -> list[FileChange]:
    files: list[FileChange] = []
    cur: FileChange | None = None
    hunk: dict | None = None
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            cur, hunk = None, None
        elif line.startswith("+++ "):
            path = line[4:].strip().removeprefix("b/")
            cur = None if path == "/dev/null" else FileChange(path)
            if cur:
                files.append(cur)
        elif line.startswith("@@") and cur is not None:
            hunk = {"removed": [], "added": []}
            cur.hunks.append(hunk)
        elif cur is not None and hunk is not None:
            if line.startswith("-") and not line.startswith("---"):
                hunk["removed"].append(line[1:])
            elif line.startswith("+") and not line.startswith("+++"):
                hunk["added"].append(line[1:])
    return [f for f in files if f.hunks and not TEST_PATH.search(f.path)]


def advisory_ids(vuln: dict) -> set[str]:
    return {str(vuln.get("id"))} | {str(a) for a in vuln.get("aliases") or []}


def narrow(commits: list[Commit], ids: set[str]) -> list[Commit]:
    """The commits of a bundle that name the advisory, or all of them if none do."""
    named = [c for c in commits if any(i in c.message for i in ids)]
    return named or commits


RELEASE_SUBJECT = re.compile(
    r"^(?:\[[^\]]*\]\s*)?(?:bump(?:ed)? (?:the )?version|release|prepare (?:for )?release|"
    r"version bump|v?\d+\.\d+(?:\.\d+)*(?:\s|$))",
    re.IGNORECASE,
)
RELEASE_FILES = re.compile(
    r"(^|/)(__init__\.py|_version\.py|version\.py|setup\.(py|cfg)|pyproject\.toml|package\.json|"
    r"go\.mod|go\.sum|VERSION|CHANGE(LOG|S)[^/]*|HISTORY[^/]*|NEWS[^/]*)$|(^|/)docs?/",
    re.IGNORECASE,
)


def release_like(commits: list[Commit], files: list[FileChange]) -> bool:
    """True for a release or version-bump commit: a release subject, or every
    changed file a version, packaging, changelog or docs file."""
    if commits and all(RELEASE_SUBJECT.search(c.subject) for c in commits):
        return True
    return bool(files) and all(RELEASE_FILES.search(f.path) for f in files)


def only_adds(files: list[FileChange]) -> bool:
    """True when the change removes nothing: the shape of a feature introduction."""
    return bool(files) and all(not h["removed"] for f in files for h in f.hunks)
