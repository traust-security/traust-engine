"""Fetching fix patches and installed source from literal, allow-listed hosts.

Advisory data names the upstream repository, so a URL taken from it is
attacker-influenced. Nothing is fetched unless its host is on an allow-list, a
redirect must stay on the list, sizes are capped, and archives are extracted
with path and link checks. Nothing fetched is ever executed.

The defaults below are what an embedder gets; traust passes the hosts its
feeds.yaml names (decision D3: sources are configured like every other feed).
"""

from __future__ import annotations

import io
import json
import re
import tarfile
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Callable
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path

FORGES = frozenset({"github.com", "gitlab.com"})
REGISTRIES = frozenset(
    {
        "proxy.golang.org",
        "pypi.org",
        "files.pythonhosted.org",
        "registry.npmjs.org",
        "repo1.maven.org",
        "static.crates.io",
        "rubygems.org",
        "api.nuget.org",
        # A NuGet package ships compiled assemblies; its source is the forge
        # archive at the commit its nuspec declares.
        "github.com",
    }
)
# Hosts a fetch may be redirected to, keyed by the host it started on.
REDIRECTS = {
    "github.com": frozenset({"patch-diff.githubusercontent.com", "codeload.github.com"}),
    "gitlab.com": frozenset({"gitlab.com"}),
    "proxy.golang.org": frozenset({"storage.googleapis.com"}),
}
MAX_BYTES = 200 * 1024 * 1024
COMMIT = re.compile(r"[0-9a-f]{40}")
SEGMENT = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]*")
# crates.io asks bots to identify themselves with contact details.
USER_AGENT = "traust-applicability (+https://github.com/traust-security/traust)"

Transport = Callable[[str], tuple[bytes, str]]  # url -> (body, final url)


class FetchRefused(ValueError):
    """A URL or redirect off the allow-list, or a body over the size cap."""


def _urllib(url: str) -> tuple[bytes, str]:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=120) as r:
        data = r.read(MAX_BYTES + 1)
        return data, r.geturl()


@dataclass
class Fetcher:
    """Allow-listed HTTPS fetches. `transport` is the seam tests replace."""

    forges: frozenset[str] = FORGES
    registries: frozenset[str] = REGISTRIES
    redirects: dict[str, frozenset[str]] = field(default_factory=lambda: dict(REDIRECTS))
    transport: Transport = _urllib
    _npm_times: dict[str, dict] = field(default_factory=dict, repr=False)
    _gem_times: dict[str, dict] = field(default_factory=dict, repr=False)
    _nuspecs: dict[tuple[str, str], tuple[str, str]] = field(default_factory=dict, repr=False)

    def get(self, url: str, allowed: frozenset[str]) -> bytes:
        parts = urllib.parse.urlsplit(url)
        host = parts.hostname or ""
        if parts.scheme != "https" or host not in allowed:
            raise FetchRefused(f"host not allowed: {host or url}")
        body, final = self.transport(url)
        final_host = urllib.parse.urlsplit(final).hostname or ""
        if final_host != host and final_host not in self.redirects.get(host, frozenset()):
            raise FetchRefused(f"redirected off the allow-list: {host} -> {final_host}")
        if len(body) > MAX_BYTES:
            raise FetchRefused("body over the size cap")
        return body

    def patch(self, url: str) -> str:
        return self.get(url, self.forges).decode("utf-8", errors="replace")

    def source(self, ecosystem: str, name: str, version: str, dest: Path) -> dict:
        """Extract the installed version's source under `dest`; return its provenance."""
        declared = self.nuget_declared(name, version) if ecosystem == "NuGet" else None
        url, kind = self.source_url(ecosystem, name, version)
        blob = self.get(url, self.registries)
        files = extract(blob, kind, dest)
        out = {"url": url, "sha256": sha256(blob).hexdigest(), "files": files}
        if declared:
            out["declared_by"] = declared
        return out

    def nuspec(self, name: str, version: str) -> tuple[str, str]:
        """(url, text) of a NuGet package version's nuspec, fetched once."""
        ident, ver = name.lower(), nuget_version(version)
        if (ident, ver) not in self._nuspecs:
            url = f"https://api.nuget.org/v3-flatcontainer/{ident}/{ver}/{ident}.nuspec"
            text = self.get(url, self.registries).decode("utf-8", errors="replace")
            self._nuspecs[(ident, ver)] = (url, text)
        return self._nuspecs[(ident, ver)]

    def nuget_id(self, name: str, version: str) -> str:
        """The package id as its publisher cased it. NuGet ids are
        case-insensitive but OSV's NuGet lookup is not, and lockfiles and
        manifests carry whatever casing the project wrote."""
        _url, text = self.nuspec(name, version)
        m = re.search(r"<id>\s*([A-Za-z0-9_.-]+)\s*</id>", text)
        if not m or m.group(1).lower() != name.lower():
            raise FetchRefused(f"nuspec id does not match {name}")
        return m.group(1)

    def nuget_declared(self, name: str, version: str) -> dict:
        """The repository and commit a NuGet package's nuspec says it was built from.

        The package itself holds compiled assemblies, so this declaration is how
        its source is found. It is the publisher's claim, recorded as such.
        """
        url, text = self.nuspec(name, version)
        tag = re.search(r"<repository\b[^>]*>", text)
        attrs = dict(re.findall(r'(\w+)="([^"]*)"', tag.group(0))) if tag else {}
        repo, commit = attrs.get("url", ""), attrs.get("commit", "").lower()
        if not repo or not COMMIT.fullmatch(commit):
            raise FetchRefused(f"nuspec declares no source repository and commit: {url}")
        return {"nuspec": url, "repository": repo, "commit": commit}

    def release_time(self, ecosystem: str, name: str, version: str) -> str | None:
        """When the registry published this version (ISO 8601), or None.

        Go, PyPI, npm and RubyGems publish it on hosts the lane already fetches
        from; Maven Central, crates.io's CDN and NuGet's flat container don't,
        so those return None.
        """
        try:
            if ecosystem == "Go":
                v = version if version.startswith("v") else "v" + version
                info = json.loads(
                    self.get(
                        f"https://proxy.golang.org/{go_escape(name)}/@v/{go_escape(v)}.info",
                        self.registries,
                    )
                )
                return info.get("Time")
            if ecosystem == "PyPI":
                meta = json.loads(
                    self.get(f"https://pypi.org/pypi/{name}/{version}/json", self.registries)
                )
                times = sorted(
                    u["upload_time_iso_8601"]
                    for u in meta.get("urls") or []
                    if u.get("upload_time_iso_8601")
                )
                return times[0] if times else None
            if ecosystem == "RubyGems":
                if name not in self._gem_times:
                    rows = json.loads(
                        self.get(
                            f"https://rubygems.org/api/v1/versions/{name}.json", self.registries
                        )
                    )
                    self._gem_times[name] = {
                        r["number"]: r.get("created_at")
                        for r in rows
                        if r.get("platform", "ruby") == "ruby"
                    }
                return self._gem_times[name].get(version)
            if ecosystem == "npm":
                if name not in self._npm_times:
                    doc = json.loads(
                        self.get(f"https://registry.npmjs.org/{name}", self.registries)
                    )
                    self._npm_times[name] = doc.get("time") or {}
                return self._npm_times[name].get(version)
        except (FetchRefused, OSError, ValueError, KeyError):
            return None
        return None

    def source_url(self, ecosystem: str, name: str, version: str) -> tuple[str, str]:
        if ecosystem == "Go":
            v = version if version.startswith("v") else "v" + version
            return f"https://proxy.golang.org/{go_escape(name)}/@v/{go_escape(v)}.zip", "zip"
        if ecosystem == "PyPI":
            meta = json.loads(
                self.get(f"https://pypi.org/pypi/{name}/{version}/json", self.registries)
            )
            urls = meta.get("urls") or []
            pick = next((u for u in urls if u.get("packagetype") == "sdist"), None) or next(
                (u for u in urls if u.get("packagetype") == "bdist_wheel"), None
            )
            if not pick:
                raise FetchRefused(f"no sdist or wheel for {name} {version}")
            kind = "zip" if pick["filename"].endswith((".zip", ".whl")) else "tar"
            return pick["url"], kind
        if ecosystem == "npm":
            base = name.rsplit("/", 1)[-1]
            return f"https://registry.npmjs.org/{name}/-/{base}-{version}.tgz", "tar"
        if ecosystem == "crates.io":
            return f"https://static.crates.io/crates/{name}/{name}-{version}.crate", "tar"
        if ecosystem == "Maven":
            group, _, artifact = name.partition(":")
            if not group or not artifact:
                raise FetchRefused(f"not a Maven group:artifact: {name}")
            base = f"https://repo1.maven.org/maven2/{group.replace('.', '/')}/{artifact}/{version}"
            return f"{base}/{artifact}-{version}-sources.jar", "zip"
        if ecosystem == "RubyGems":
            return f"https://rubygems.org/downloads/{name}-{version}.gem", "gem"
        if ecosystem == "NuGet":
            d = self.nuget_declared(name, version)
            return archive_url(d["repository"], d["commit"]), "tar"
        raise FetchRefused(f"ecosystem not supported yet: {ecosystem}")


def nuget_version(version: str) -> str:
    """NuGet's normalized form, as its flat container names files: lower case,
    no build metadata, no leading zeros, and no fourth part when it is 0."""
    core, _, pre = version.lower().split("+", 1)[0].partition("-")
    parts = [str(int(p)) if p.isdigit() else p for p in core.split(".")]
    if len(parts) == 4 and parts[3] == "0":
        parts = parts[:3]
    return ".".join(parts) + (f"-{pre}" if pre else "")


def archive_url(repository: str, commit: str) -> str:
    """The source archive of `repository` at `commit`, on GitHub or GitLab.

    The repository URL comes from the package, so only plain path segments are
    accepted; the host is always one of the two literals."""
    parts = urllib.parse.urlsplit(repository.strip())
    path = parts.path.strip("/").removesuffix(".git")
    if not COMMIT.fullmatch(commit) or not all(SEGMENT.fullmatch(x) for x in path.split("/")):
        raise FetchRefused(f"not a plain repository path: {repository}")
    if parts.scheme in ("https", "http", "git") and parts.hostname == "github.com":
        owner_repo = "/".join(path.split("/")[:2])
        if owner_repo.count("/") == 1:
            return f"https://github.com/{owner_repo}/archive/{commit}.tar.gz"
    if parts.scheme in ("https", "http") and parts.hostname == "gitlab.com" and "/" in path:
        name = path.rsplit("/", 1)[-1]
        return f"https://gitlab.com/{path}/-/archive/{commit}/{name}-{commit}.tar.gz"
    raise FetchRefused(f"source repository not on a supported forge: {repository}")


def go_escape(path: str) -> str:
    """The module proxy's case encoding: an upper-case letter becomes '!' + lower."""
    return "".join("!" + ch.lower() if ch.isupper() else ch for ch in path)


def extract(blob: bytes, kind: str, dest: Path) -> int:
    """Regular files only, each kept inside `dest`; links and escapes are skipped.

    A `.gem` is a tar holding the gem's files as `data.tar.gz`; that inner
    archive is what is extracted."""
    if kind == "gem":
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:") as tf:
            member = next(
                (m for m in tf.getmembers() if m.name == "data.tar.gz" and m.isfile()), None
            )
            inner = tf.extractfile(member) if member else None
            if inner is None:
                raise FetchRefused("gem has no data.tar.gz")
            return extract(inner.read(MAX_BYTES + 1), "tar", dest)
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()

    def target(name: str) -> Path | None:
        p = (dest / name).resolve()
        return p if p.is_relative_to(root) and p != root else None

    n = 0
    if kind == "zip":
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            for info in z.infolist():
                if info.is_dir() or (info.external_attr >> 16) & 0o170000 == 0o120000:
                    continue
                t = target(info.filename)
                if t is None:
                    continue
                t.parent.mkdir(parents=True, exist_ok=True)
                t.write_bytes(z.read(info))
                n += 1
        return n
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as tf:
        for m in tf.getmembers():
            if not m.isfile():
                continue
            t = target(m.name)
            f = tf.extractfile(m) if t is not None else None
            if t is None or f is None:
                continue
            t.parent.mkdir(parents=True, exist_ok=True)
            t.write_bytes(f.read())
            n += 1
    return n
