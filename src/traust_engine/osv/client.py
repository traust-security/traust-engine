"""The one OSV API client every harness caller shares.

Queries the OSV.dev API (``/v1/querybatch``, ``/v1/query`` for pagination,
``/v1/vulns/{id}`` for details). Callers: the dependency pre-scan
(``adapters/osv.py``), the fleet sweep, advisory fetches, the CVE-replay
monitor.

**A failed lookup is never an empty result.** Every query that could not be
answered is returned as ``None`` and counted under one of three statuses,
the same vocabulary the continuous-ops comparison statuses use:

- ``unreachable``: network failure, timeout or a 5xx after the retries
- ``quota-deferred``: HTTP 429 after the retries
- ``error``: any other HTTP error, or a response that isn't the expected JSON

A caller reports any non-zero count as degraded coverage, never as
"no advisories". ``probe`` lets a caller find out up front that the API
cannot be used at all, and fail fast instead of retrying every batch.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections import Counter
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

DEFAULT_BASE_URL = "https://api.osv.dev/v1"
USER_AGENT = "traust-engine-osv-client"
STATUSES = ("unreachable", "quota-deferred", "error")


def normalize_base_url(url: str | None) -> str:
    """Accept ``.../v1``, ``.../v1/query`` or ``.../v1/querybatch``."""
    base = (url or DEFAULT_BASE_URL).rstrip("/")
    for suffix in ("/querybatch", "/query"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
    return base


@dataclass(frozen=True)
class Query:
    """One package version to look up. ``ecosystem`` is OSV's name (``PyPI``, ``npm``…).

    With ``version`` None the query asks for every advisory naming the package.
    """

    ecosystem: str
    name: str
    version: str | None

    def body(self, page_token: str | None = None) -> dict:
        doc: dict = {"package": {"name": self.name, "ecosystem": self.ecosystem}}
        if self.version is not None:
            doc["version"] = self.version
        if page_token:
            doc["page_token"] = page_token
        return doc


@dataclass
class BatchOutcome:
    """Advisory ids per query, aligned with the input. ``None`` = not answered."""

    ids: list[list[str] | None]
    issues: Counter = field(default_factory=Counter)

    @property
    def complete(self) -> bool:
        return not self.issues


class _Failure(Exception):
    def __init__(self, status: str, detail: str):
        super().__init__(detail)
        self.status = status


class OsvClient:
    def __init__(
        self,
        base_url: str | None = None,
        *,
        timeout: float = 60.0,
        retries: int = 3,
        backoff: float = 2.0,
        batch_size: int = 800,
        workers: int = 4,
        opener: Callable | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.base_url = normalize_base_url(base_url)
        self.timeout = timeout
        self.retries = max(1, retries)
        self.backoff = backoff
        self.batch_size = batch_size
        self.workers = max(1, workers)
        self._open = opener or urllib.request.urlopen
        self._sleep = sleep

    # -- transport ---------------------------------------------------------

    def _request(self, url: str, body: dict | None = None) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        headers = {"User-Agent": USER_AGENT}
        if data is not None:
            headers["Content-Type"] = "application/json"
        last: _Failure | None = None
        for attempt in range(self.retries):
            req = urllib.request.Request(url, data=data, headers=headers)
            try:
                with self._open(req, timeout=self.timeout) as resp:
                    raw = resp.read()
                try:
                    doc = json.loads(raw)
                except (json.JSONDecodeError, ValueError) as e:
                    raise _Failure("error", f"unparseable response from {url}: {e}") from None
                if not isinstance(doc, dict):
                    raise _Failure("error", f"unexpected response shape from {url}")
                return doc
            except urllib.error.HTTPError as e:
                if e.code == 429:
                    last = _Failure("quota-deferred", f"HTTP 429 from {url}")
                elif e.code >= 500:
                    last = _Failure("unreachable", f"HTTP {e.code} from {url}")
                else:
                    raise _Failure("error", f"HTTP {e.code} from {url}") from None
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                last = _Failure("unreachable", f"{type(e).__name__} reaching {url}")
            if attempt + 1 < self.retries:
                self._sleep(self.backoff * (attempt + 1))
        assert last is not None
        raise last

    # -- queries -----------------------------------------------------------

    def probe(self, query: Query) -> tuple[str, str] | None:
        """One lookup before a scan: ``None`` if the API answers, else (status, detail)."""
        try:
            self._request(f"{self.base_url}/query", query.body())
        except _Failure as f:
            return f.status, str(f)
        return None

    def _follow_pages(self, query: Query, token: str) -> list[str]:
        ids: list[str] = []
        while token:
            doc = self._request(f"{self.base_url}/query", query.body(page_token=token))
            ids += [v["id"] for v in doc.get("vulns") or [] if isinstance(v, dict) and v.get("id")]
            token = doc.get("next_page_token") or ""
        return ids

    def query_batch(self, queries: list[Query]) -> BatchOutcome:
        """Advisory ids for each query; failures are ``None`` plus a counted status."""
        out: list[list[str] | None] = [None] * len(queries)
        issues: Counter = Counter()
        for start in range(0, len(queries), self.batch_size):
            chunk = queries[start : start + self.batch_size]
            try:
                doc = self._request(
                    f"{self.base_url}/querybatch", {"queries": [q.body() for q in chunk]}
                )
                results = doc.get("results")
                if not isinstance(results, list) or len(results) != len(chunk):
                    raise _Failure("error", "querybatch returned a different number of results")
            except _Failure as f:
                issues[f.status] += len(chunk)
                continue
            for offset, (query, result) in enumerate(zip(chunk, results, strict=True)):
                result = result if isinstance(result, dict) else {}
                ids = [
                    v["id"]
                    for v in result.get("vulns") or []
                    if isinstance(v, dict) and v.get("id")
                ]
                token = result.get("next_page_token")
                if token:
                    try:
                        ids += self._follow_pages(query, token)
                    except _Failure as f:
                        issues[f.status] += 1
                        continue  # a partly paged answer is not an answer
                out[start + offset] = ids
        return BatchOutcome(out, issues)

    def get_vulns(self, ids: Iterable[str]) -> tuple[dict[str, dict], Counter]:
        """Full OSV records for each id; ids that could not be fetched are counted."""
        unique = sorted(set(ids))
        found: dict[str, dict] = {}
        issues: Counter = Counter()

        def fetch(vid: str):
            try:
                return vid, self._request(f"{self.base_url}/vulns/{vid}"), None
            except _Failure as f:
                return vid, None, f.status

        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            for vid, doc, status in pool.map(fetch, unique):
                if doc is not None:
                    found[vid] = doc
                else:
                    issues[status] += 1
        return found, issues
