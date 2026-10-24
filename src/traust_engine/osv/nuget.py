"""NuGet package ids in their publisher's casing.

NuGet ids are case-insensitive, but OSV's NuGet lookup is not:
`Newtonsoft.Json` finds its advisory and `newtonsoft.json` finds nothing.
Lockfiles and project files carry whatever casing the project wrote, so an
id written in other casing would silently miss every advisory. nuget.org's
registration index gives the id as published.

Only a lookup that came back empty is retried, so the common case costs
nothing. An id nuget.org doesn't know (an internal package) stays as written.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable
from urllib.parse import quote

REGISTRATION = "https://api.nuget.org/v3/registration5-semver1/"
USER_AGENT = "traust-engine-osv-client"
MAX_BYTES = 16 * 1024 * 1024

Transport = Callable[[str], bytes]  # url -> body; raises OSError (HTTPError) on failure


def _urllib(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read(MAX_BYTES + 1)


class NugetIds:
    """Publisher casing for NuGet ids, from nuget.org, looked up once per id."""

    def __init__(self, transport: Transport | None = None) -> None:
        self._get = transport or _urllib
        self._cache: dict[str, str | None] = {}
        self.failures = 0  # lookups nuget.org didn't answer (not "unknown id")

    def _doc(self, url: str) -> dict:
        body = self._get(url)
        if len(body) > MAX_BYTES:
            raise ValueError("registration document over the size cap")
        doc = json.loads(body)
        if not isinstance(doc, dict):
            raise ValueError("unexpected registration document")
        return doc

    def canonical(self, name: str) -> str | None:
        """The id as nuget.org publishes it, or None when it is unknown there or
        nuget.org can't be reached."""
        key = name.lower()
        if key in self._cache:
            return self._cache[key]
        found = None
        try:
            index = self._doc(REGISTRATION + quote(key, safe="") + "/index.json")
            pages = index.get("items") or []
            if pages:
                # Large packages link their pages instead of inlining them.
                items = pages[0].get("items")
                if not items:
                    page = str(pages[0].get("@id") or "")
                    if not page.startswith(REGISTRATION):
                        raise ValueError(f"registration page off nuget.org: {page}")
                    items = self._doc(page).get("items") or []
                entry = (items[0] if items else {}).get("catalogEntry") or {}
                cid = entry.get("id")
                if isinstance(cid, str) and cid.lower() == key:
                    found = cid
        except urllib.error.HTTPError as e:
            if e.code != 404:
                self.failures += 1
        except (OSError, ValueError, KeyError, TypeError):
            self.failures += 1
        self._cache[key] = found
        return found
