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
    }
)
# Hosts a fetch may be redirected to, keyed by the host it started on.
REDIRECTS = {
    "github.com": frozenset({"patch-diff.githubusercontent.com"}),
    "gitlab.com": frozenset({"gitlab.com"}),
    "proxy.golang.org": frozenset({"storage.googleapis.com"}),
}
MAX_BYTES = 200 * 1024 * 1024
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
        url, kind = self.source_url(ecosystem, name, version)
        blob = self.get(url, self.registries)
        files = extract(blob, kind, dest)
        return {"url": url, "sha256": sha256(blob).hexdigest(), "files": files}

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
        raise FetchRefused(f"ecosystem not supported yet: {ecosystem}")


def go_escape(path: str) -> str:
    """The module proxy's case encoding: an upper-case letter becomes '!' + lower."""
    return "".join("!" + ch.lower() if ch.isupper() else ch for ch in path)


def extract(blob: bytes, kind: str, dest: Path) -> int:
    """Regular files only, each kept inside `dest`; links and escapes are skipped."""
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
