"""The shared OSV client: answers, pagination, and failures that are never empty."""

import io
import json
import urllib.error

import pytest

from traust_engine.osv import NugetIds, OsvClient, Query, base_score, normalize_base_url
from traust_engine.osv.nuget import REGISTRATION


class FakeOpener:
    """Routes requests to canned responses: a dict, an HTTP status, or an exception."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def __call__(self, req, timeout=None):
        body = json.loads(req.data) if req.data else None
        self.calls.append((req.full_url, body))
        handler = self.routes[req.full_url.rsplit("/v1/", 1)[1].split("/")[0]]
        reply = handler(body, req.full_url) if callable(handler) else handler
        if isinstance(reply, Exception):
            raise reply
        if isinstance(reply, int):
            raise urllib.error.HTTPError(req.full_url, reply, "err", {}, None)
        return io.BytesIO(json.dumps(reply).encode())


def client(routes, **kw):
    return OsvClient("https://osv.test/v1", opener=FakeOpener(routes), sleep=lambda s: None, **kw)


Q1 = Query("PyPI", "requests", "2.19.0")
Q2 = Query("npm", "lodash", "4.17.15")


def test_normalize_base_url():
    assert normalize_base_url("https://api.osv.dev/v1/query") == "https://api.osv.dev/v1"
    assert normalize_base_url("https://api.osv.dev/v1/querybatch/") == "https://api.osv.dev/v1"
    assert normalize_base_url(None) == "https://api.osv.dev/v1"


def test_batch_ids_align_with_queries():
    c = client({"querybatch": {"results": [{"vulns": [{"id": "GHSA-1"}]}, {}]}})
    out = c.query_batch([Q1, Q2])
    assert out.ids == [["GHSA-1"], []]
    assert out.complete


def test_pages_are_followed():
    pages = {"querybatch": {"results": [{"vulns": [{"id": "A"}], "next_page_token": "t1"}]}}
    pages["query"] = lambda body, url: (
        {"vulns": [{"id": "B"}], "next_page_token": "t2"}
        if body["page_token"] == "t1"
        else {"vulns": [{"id": "C"}]}
    )
    assert client(pages).query_batch([Q1]).ids == [["A", "B", "C"]]


@pytest.mark.parametrize(
    ("reply", "status"),
    [
        (429, "quota-deferred"),
        (503, "unreachable"),
        (urllib.error.URLError("down"), "unreachable"),
        (TimeoutError(), "unreachable"),
        (400, "error"),
        ({"results": []}, "error"),  # wrong number of results
    ],
)
def test_a_failed_batch_is_none_and_counted_never_empty(reply, status):
    out = client({"querybatch": reply}).query_batch([Q1, Q2])
    assert out.ids == [None, None]
    assert out.issues == {status: 2}
    assert not out.complete


def test_retries_before_giving_up():
    attempts = []
    c = client({"querybatch": lambda b, u: attempts.append(1) or 503}, retries=3)
    c.query_batch([Q1])
    assert len(attempts) == 3


def test_a_client_error_is_not_retried():
    attempts = []
    client({"querybatch": lambda b, u: attempts.append(1) or 404}, retries=3).query_batch([Q1])
    assert len(attempts) == 1


def test_a_failed_page_leaves_that_query_unanswered():
    routes = {
        "querybatch": {"results": [{"vulns": [{"id": "A"}], "next_page_token": "t"}, {}]},
        "query": 503,
    }
    out = client(routes).query_batch([Q1, Q2])
    assert out.ids == [None, []]
    assert out.issues == {"unreachable": 1}


def test_get_vulns_counts_failures():
    routes = {"vulns": lambda b, url: {"id": "OK"} if url.endswith("/OK") else 503}
    found, issues = client(routes).get_vulns(["OK", "BAD", "OK"])
    assert list(found) == ["OK"]
    assert issues == {"unreachable": 1}


@pytest.mark.parametrize(
    ("vector", "score"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", None),
        ("AV:N/AC:L/Au:N/C:P/I:P/A:P", None),
        ("CVSS:3.1/AV:X", None),
    ],
)
def test_cvss_v3_base_score(vector, score):
    assert base_score(vector) == score


def test_probe_reports_why_the_api_cannot_be_used():
    assert client({"query": {}}).probe(Q1) is None
    status, detail = client({"query": urllib.error.URLError("down")}).probe(Q1)
    assert status == "unreachable" and "osv.test" in detail
    assert client({"query": 429}).probe(Q1)[0] == "quota-deferred"


# -- NuGet id casing -----------------------------------------------------------


def _registry(ids: dict[str, str], *, status: dict[str, int] | None = None):
    """A nuget.org stand-in: lower-case id -> published id, or an HTTP status."""

    def get(url):
        key = url.removeprefix(REGISTRATION).split("/")[0]
        if status and key in status:
            raise urllib.error.HTTPError(url, status[key], "err", {}, None)
        if key not in ids:
            raise urllib.error.HTTPError(url, 404, "not found", {}, None)
        return json.dumps({"items": [{"items": [{"catalogEntry": {"id": ids[key]}}]}]}).encode()

    return get


def _osv_by_exact_name(answers: dict[str, list[str]]):
    """querybatch that, like OSV, only matches the exact NuGet id."""
    return lambda body, url: {
        "results": [
            {"vulns": [{"id": i} for i in answers.get(q["package"]["name"], [])]}
            for q in body["queries"]
        ]
    }


def test_an_empty_nuget_answer_is_retried_under_the_published_casing():
    ids = NugetIds(_registry({"newtonsoft.json": "Newtonsoft.Json"}))
    c = client(
        {"querybatch": _osv_by_exact_name({"Newtonsoft.Json": ["GHSA-5crp"]})}, nuget_ids=ids
    )
    out = c.query_batch([Query("NuGet", "newtonsoft.json", "12.0.1"), Q1])
    assert out.ids == [["GHSA-5crp"], []] and out.complete
    assert c.recased == {"newtonsoft.json": "Newtonsoft.Json"}


def test_no_retry_without_a_resolver_or_when_the_casing_is_already_published():
    q = Query("NuGet", "xunit", "2.4.0")
    plain = client({"querybatch": _osv_by_exact_name({})})
    assert plain.query_batch([q]).ids == [[]] and plain.recased == {}
    ids = NugetIds(_registry({"xunit": "xunit"}))
    same = client({"querybatch": _osv_by_exact_name({})}, nuget_ids=ids)
    assert same.query_batch([q]).ids == [[]] and same.recased == {}
    assert len(same._open.calls) == 1  # no second querybatch


def test_an_unknown_nuget_id_stays_as_written_and_a_registry_outage_is_counted():
    ids = NugetIds(_registry({}, status={"flaky.pkg": 503}))
    c = client({"querybatch": _osv_by_exact_name({})}, nuget_ids=ids)
    out = c.query_batch(
        [Query("NuGet", "Internal.Pkg", "1.0.0"), Query("NuGet", "Flaky.Pkg", "1.0.0")]
    )
    assert out.ids == [[], []] and c.recased == {}
    assert ids.failures == 1  # the 503, not the 404


def test_a_failed_retry_is_unanswered_never_empty():
    ids = NugetIds(_registry({"newtonsoft.json": "Newtonsoft.Json"}))
    calls = iter([{"results": [{}]}, 500, 500, 500])
    c = client({"querybatch": lambda body, url: next(calls)}, nuget_ids=ids)
    out = c.query_batch([Query("NuGet", "newtonsoft.json", "12.0.1")])
    assert out.ids == [None] and out.issues["unreachable"] == 1


def test_linked_registration_pages_stay_on_nuget_org():
    page = REGISTRATION + "big.pkg/page/1.0.0/9.0.0.json"
    docs = {
        REGISTRATION + "big.pkg/index.json": {"items": [{"@id": page}]},
        page: {"items": [{"catalogEntry": {"id": "Big.Pkg"}}]},
        REGISTRATION + "evil.pkg/index.json": {"items": [{"@id": "https://evil.test/p.json"}]},
    }
    ids = NugetIds(lambda u: json.dumps(docs[u]).encode())
    assert ids.canonical("big.pkg") == "Big.Pkg"
    assert ids.canonical("evil.pkg") is None and ids.failures == 1
