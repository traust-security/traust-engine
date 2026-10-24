"""Resolve ownership context from the product registry.

Joins a findings package (or a repo URL, or a product id) to its
`ps_product`/`ps_module` records in the compiled product-definitions
artifact and emits the ownership-relevant slice: security-contact kerberos
ids, tagged by which field they came from, plus the product lifecycle
window.

CANDIDATE GENERATOR, NOT AN AUTHORITY. This contributes ownership context
and candidate seeds only. It never names an owner, and it never writes
ownership that belongs in operator-maintained inputs. Consumers: skills/
assign-findings-owners, skills/reassign-findings-owners.

Contact ladder, highest confidence first — each contact is tagged with its
originating field so a designated embargo contact is never mistaken for a
generic bug CC:

  1 private_tracker_cc (+ _component_override)  embargo-cleared: these
      people already receive private/embargoed trackers for the module
  2 component_cc                                per-component bug CC
  3 default_cc                                  module-wide bug CC

ONLY tier 1 is embargo-cleared. default_cc is a public-bug notification
list; CC'ing it on an embargoed finding would be a disclosure event.

Ownership-only field allowlist. `bts.key` (Jira/Bugzilla), `cpe`,
`errata_product_tags`, `team` (a legacy pre-2022 ProdSec team, not an
owning team) and `business_unit` are deliberately NOT emitted — they are
tracker/inventory concerns, and a field no consumer reads is the
under-wiring alignment rule A9 exists to catch. No free text
(`public_description`) ever reaches the caller.

Match tiers: mapped (reviewed config) > repo-url (exact
managed_service_components[].git_repo_url) > slug (advisory only, always
human-confirmed) > none. There is no CPE tier — findings packages carry a
Repository field, not a CPE.

`unavailable` is not `none`. A missing cache (off VPN) reports
source_status=unavailable with match_tier=null; a present cache that
matched nothing reports source_status=ok with match_tier="none". Exit
status is 0 in every case: this is an optional corroborating source, and a
network condition must never read as a failed run. Identity verification
in the consuming workflow may require the same network access.

Usage:
    python3 product_definitions.py [--package NAME ...] [--repo-url URL ...]
                                   [--product ID ...] [--all]
                                   [--map FILE] [--cache-dir DIR] [--json]
"""

from __future__ import annotations

import datetime
import json
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from traust_contracts import DeploymentConfigMissing, optional_config_path

from traust_engine.locations import configured_locations, progress_tracker_dir
from traust_engine.registry import feeds as ff

if TYPE_CHECKING:
    from traust_engine.engine import HarnessEngine


def _default_packages_dir() -> Path | None:
    """Processed-results dir under the configured metrics root, or None.

    Lazy: resolving at import froze it off env / a cwd guess. None when the
    metrics root location is not configured.
    """
    pt = progress_tracker_dir(configured_locations())
    return (pt / "processed-results") if pt else None


# Same discipline as countersign.py's IDENTITY_RE — these values may be
# passed to an employee verification tool.
IDENTITY_RE = re.compile(r"^[a-z0-9._-]{1,64}$")

# Tier 1 is the only embargo-cleared source.
CONTACT_FIELDS = (
    ("private_tracker_cc", 1, True),
    ("private_tracker_cc_component_override", 1, True),
    ("component_cc", 2, False),
    ("default_cc", 3, False),
)

# Upstream applies --expand-aliases when publishing, so a residual
# +alias means that broke. Warn rather than silently reporting no
# contacts.
DROP_RATE_WARN = 0.20


def _fetch_feeds():
    return ff


def _today() -> datetime.date:
    return datetime.datetime.now(datetime.UTC).date()


def norm_repo_url(url: str) -> str:
    """Canonical form for joining repo URLs across sources.

    Lowercases first, then strips any scheme, then folds scp-style
    `git@host:org/repo` onto `host/org/repo` so both spellings of the same
    remote collide.
    """
    u = (url or "").strip().rstrip("/").lower()
    u = re.sub(r"\.git$", "", u)
    if u.startswith("git@"):
        return u[4:].replace(":", "/", 1)
    return re.sub(r"^[a-z][a-z0-9+.-]*://", "", u)


def slugify(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


# --------------------------------------------------------------------------
# indexes
# --------------------------------------------------------------------------


def build_indexes(doc: dict) -> dict:
    products = doc.get("ps_products") or {}
    modules = doc.get("ps_modules") or {}
    streams = doc.get("ps_update_streams") or {}

    module_to_products = {}
    for pid, prod in products.items():
        for mid in prod.get("ps_modules") or []:
            module_to_products.setdefault(mid, []).append(pid)

    stream_to_modules = {}
    for mid, mod in modules.items():
        for sid in mod.get("ps_update_streams") or []:
            stream_to_modules.setdefault(sid, []).append(mid)

    repo_to_streams, repo_component = {}, {}
    for sid, stream in streams.items():
        for comp in stream.get("managed_service_components") or []:
            url = comp.get("git_repo_url")
            if not url:
                continue
            key = norm_repo_url(url)
            repo_to_streams.setdefault(key, []).append(sid)
            repo_component.setdefault(key, set()).add(comp.get("name"))

    slug_to_product = {}
    for pid, prod in products.items():
        for candidate in (pid, prod.get("name")):
            s = slugify(candidate)
            if s:
                slug_to_product.setdefault(s, pid)

    return {
        "products": products,
        "modules": modules,
        "streams": streams,
        "module_to_products": module_to_products,
        "stream_to_modules": stream_to_modules,
        "repo_to_streams": repo_to_streams,
        "repo_component": repo_component,
        "slug_to_product": slug_to_product,
    }


# --------------------------------------------------------------------------
# contacts
# --------------------------------------------------------------------------


def _raw_values(module: dict, field: str) -> list:
    """Flatten one contact field to a list of (value, component)."""
    val = module.get(field)
    if isinstance(val, list):
        return [(v, None) for v in val]
    if isinstance(val, dict):
        out = []
        for component, members in val.items():
            for v in members or []:
                out.append((v, component))
        return out
    return []


def collect_contacts(modules: dict, module_ids: list) -> tuple[list, list]:
    """Ladder-ordered, de-duplicated contacts plus what was dropped.

    A kerberos id present in more than one field keeps its best tier, so
    an embargo contact never gets demoted by also appearing in default_cc.
    """
    best, dropped = {}, []
    for mid in module_ids:
        module = modules.get(mid) or {}
        for field, tier, embargo in CONTACT_FIELDS:
            for value, component in _raw_values(module, field):
                if not isinstance(value, str):
                    continue
                ident = value.split("@")[0].strip()
                if not IDENTITY_RE.match(ident):
                    dropped.append(
                        {
                            "value": value,
                            "field": field,
                            "ps_module": mid,
                            "reason": (
                                "unexpanded_alias"
                                if value.startswith("+")
                                else "not_kerberos_shaped"
                            ),
                        }
                    )
                    continue
                prev = best.get(ident)
                if prev is None or tier < prev["tier"]:
                    best[ident] = {
                        "kerberos_id": ident,
                        "field": field,
                        "tier": tier,
                        "embargo_cleared": embargo,
                        "ps_module": mid,
                        **({"component": component} if component else {}),
                    }
    contacts = sorted(best.values(), key=lambda c: (c["tier"], c["kerberos_id"]))
    return contacts, dropped


def lifecycle_of(modules: dict, module_ids: list) -> dict:
    """Widest supported window across the matched modules, plus a state."""
    froms, untils, unknown_until = [], [], False
    for mid in module_ids:
        lc = (modules.get(mid) or {}).get("lifecycle") or {}
        if lc.get("supported_from"):
            froms.append(lc["supported_from"])
        if lc.get("supported_until"):
            untils.append(lc["supported_until"])
        else:
            unknown_until = True
    supported_from = min(froms) if froms else None
    supported_until = None if unknown_until else (max(untils) if untils else None)
    state = "unknown"
    today = _today().isoformat()
    if supported_from and supported_from > today:
        state = "unreleased"
    elif supported_until and supported_until < today:
        state = "eol"
    elif froms or untils or unknown_until:
        state = "supported"
    return {"supported_from": supported_from, "supported_until": supported_until, "state": state}


# --------------------------------------------------------------------------
# resolution
# --------------------------------------------------------------------------


def _bundle(idx: dict, tier: str, product_ids: list, module_ids: list, evidence: dict) -> dict:
    module_ids = sorted(set(module_ids))
    contacts, dropped = collect_contacts(idx["modules"], module_ids)
    embargo = any(c["embargo_cleared"] for c in contacts)
    return {
        "match_tier": tier,
        "ps_products": sorted(set(product_ids)),
        "ps_modules": module_ids,
        "lifecycle": lifecycle_of(idx["modules"], module_ids),
        "contacts": contacts,
        "embargo_cc": "present" if embargo else "absent",
        "dropped_contacts": dropped,
        "evidence": evidence,
    }


def _modules_for_products(idx: dict, product_ids: list) -> list:
    out = []
    for pid in product_ids:
        out.extend((idx["products"].get(pid) or {}).get("ps_modules") or [])
    return out


def resolve_repo_url(idx: dict, url: str) -> dict | None:
    key = norm_repo_url(url)
    streams = idx["repo_to_streams"].get(key)
    if not streams:
        return None
    module_ids, product_ids = [], []
    for sid in streams:
        for mid in idx["stream_to_modules"].get(sid, []):
            module_ids.append(mid)
            product_ids.extend(idx["module_to_products"].get(mid, []))
    return _bundle(
        idx,
        "repo-url",
        product_ids,
        module_ids,
        {
            "repo_url": url,
            "ps_update_streams": sorted(set(streams)),
            "components": sorted(c for c in idx["repo_component"].get(key, ()) if c),
        },
    )


def resolve_product(idx: dict, pid: str, tier: str = "mapped") -> dict | None:
    if pid not in idx["products"]:
        return None
    return _bundle(idx, tier, [pid], _modules_for_products(idx, [pid]), {"ps_product": pid})


def resolve_package(idx: dict, name: str, mappings: dict) -> dict:
    """mapped > repo-url is handled by the caller; here mapped > slug."""
    base = re.sub(r"-findings$", "", name)
    mapped = (mappings.get("packages") or {}).get(base) or (mappings.get("packages") or {}).get(
        name
    )
    if mapped:
        got = resolve_product(idx, mapped, "mapped")
        if got:
            got["evidence"]["mapped_from"] = base
            return got
        return {
            "match_tier": "none",
            "ps_products": [],
            "ps_modules": [],
            "lifecycle": lifecycle_of(idx["modules"], []),
            "contacts": [],
            "embargo_cc": "absent",
            "dropped_contacts": [],
            "evidence": {"error": f"mapped id {mapped!r} not in registry"},
        }
    pid = idx["slug_to_product"].get(slugify(base))
    if pid:
        got = resolve_product(idx, pid, "slug")
        got["evidence"]["slug"] = slugify(base)
        got["evidence"]["advisory_only"] = (
            "slug match is advisory — confirm into "
            "config/product-definitions-map.yaml before relying on it"
        )
        return got
    return {
        "match_tier": "none",
        "ps_products": [],
        "ps_modules": [],
        "lifecycle": lifecycle_of(idx["modules"], []),
        "contacts": [],
        "embargo_cc": "absent",
        "dropped_contacts": [],
        "evidence": {"package": base},
    }


# --------------------------------------------------------------------------
# map file
# --------------------------------------------------------------------------


def _cli_default_map_path() -> Path | None:
    """CLI ``--map`` default only — library callers pass an explicit path."""
    return optional_config_path("product-definitions-map.yaml")


def load_mappings(path: Path | None) -> tuple[dict, list]:
    if path is None or not path.is_file():
        return {}, []
    try:
        import yaml
    except ImportError:
        return {}, [f"PyYAML unavailable — ignoring {path}"]
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as e:
        return {}, [f"{path} unparseable ({e}) — ignoring"]
    m = doc.get("mappings") or {}
    return {"packages": m.get("packages") or {}, "repos": m.get("repos") or {}}, []


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------


def _source_block(cache: Path | None):
    """(source_status, source-metadata) for the cache as it stands."""
    if cache is None:
        return "unavailable", {"detail": "feeds cache not configured"}, None
    try:
        doc = _fetch_feeds().load_product_definitions(cache)
    except (OSError, ValueError, json.JSONDecodeError) as e:
        return "unavailable", {"detail": str(e)}, None
    st = _fetch_feeds().feed_status(cache).get("product-definitions") or {}
    meta = {
        "retrieved_at": st.get("retrieved_at"),
        "age_hours": st.get("age_hours"),
        "max_age_hours": st.get("max_age_hours"),
        "url": _fetch_feeds().FEEDS["product-definitions"]["url"],
    }
    return ("stale" if st.get("stale") else "ok"), meta, doc


def resolve_queries(
    *,
    packages: list[str] | None = None,
    repo_urls: list[str] | None = None,
    products: list[str] | None = None,
    all_packages: bool = False,
    map_path: Path | None = None,
    cache_dir: Path | None = None,
    json_only: bool = False,
    engine: HarnessEngine | None = None,
) -> int:
    packages = list(packages or [])
    repo_urls = list(repo_urls or [])
    products = list(products or [])
    map_path = map_path or _cli_default_map_path()

    if cache_dir is None and engine is not None:
        try:
            cache_dir = engine.models.feeds_cache()
        except DeploymentConfigMissing:
            cache_dir = None

    source_status, source, doc = _source_block(cache_dir)
    warnings: list[str] = []
    out = {"source_status": source_status, "source": source, "results": []}

    if doc is None:
        out["warnings"] = [
            "product-definitions cache unavailable — this source is "
            "optional; continue with the other ownership sources when "
            "the feed cache is unreachable."
        ]
        print(json.dumps(out, indent=2))
        return 0

    idx = build_indexes(doc)
    mappings, map_warnings = load_mappings(map_path)
    warnings.extend(map_warnings)

    if all_packages:
        packages_dir = _default_packages_dir()
        if packages_dir and packages_dir.is_dir():
            packages += sorted(
                p.name for p in packages_dir.iterdir() if p.is_dir() and not p.name.startswith(".")
            )
        else:
            warnings.append(f"{packages_dir} not found — --all resolved no packages")

    for name in packages:
        res = resolve_package(idx, name, mappings)
        res["query"] = {"kind": "package", "value": name}
        out["results"].append(res)
    for url in repo_urls:
        mapped = (mappings.get("repos") or {}).get(url) or (mappings.get("repos") or {}).get(
            norm_repo_url(url)
        )
        res = (
            (resolve_product(idx, mapped, "mapped") if mapped else None)
            or resolve_repo_url(idx, url)
            or {
                "match_tier": "none",
                "ps_products": [],
                "ps_modules": [],
                "lifecycle": lifecycle_of(idx["modules"], []),
                "contacts": [],
                "embargo_cc": "absent",
                "dropped_contacts": [],
                "evidence": {"repo_url": url},
            }
        )
        res["query"] = {"kind": "repo-url", "value": url}
        out["results"].append(res)
    for pid in products:
        res = resolve_product(idx, pid, "mapped") or {
            "match_tier": "none",
            "ps_products": [],
            "ps_modules": [],
            "lifecycle": lifecycle_of(idx["modules"], []),
            "contacts": [],
            "embargo_cc": "absent",
            "dropped_contacts": [],
            "evidence": {"error": f"{pid!r} not in registry"},
        }
        res["query"] = {"kind": "product", "value": pid}
        out["results"].append(res)

    kept = sum(len(r["contacts"]) for r in out["results"])
    lost = sum(len(r["dropped_contacts"]) for r in out["results"])
    if lost and kept + lost and lost / (kept + lost) > DROP_RATE_WARN:
        warnings.append(
            f"{lost} of {kept + lost} contact values failed the kerberos-id "
            f"shape gate. Upstream publishes with --expand-aliases, so a "
            f"high rate suggests that regressed — check the compile before "
            f"trusting an empty contact list."
        )
    if source_status == "stale":
        warnings.append(
            f"cache is {source.get('age_hours')}h old (threshold "
            f"{source.get('max_age_hours')}h) — refresh with "
            f"traust feeds fetch-products"
        )
    if warnings:
        out["warnings"] = warnings

    print(json.dumps(out, indent=2))
    if not json_only:
        _summarise(out)
    return 0


def _summarise(out: dict) -> None:
    lines = ["", f"# source_status={out['source_status']}"]
    for r in out["results"]:
        q = r["query"]
        lines.append(
            f"{q['kind']}={q['value']}  tier={r['match_tier']}  "
            f"lifecycle={r['lifecycle']['state']}  "
            f"embargo_cc={r['embargo_cc']}"
        )
        for c in r["contacts"]:
            flag = " [embargo-cleared]" if c["embargo_cleared"] else ""
            lines.append(f"    {c['kerberos_id']:14} tier{c['tier']} {c['field']}{flag}")
        if r["match_tier"] == "slug":
            lines.append("    (advisory slug match — confirm into the map)")
    for w in out.get("warnings") or []:
        lines.append(f"! {w}")
    print("\n".join(lines), file=sys.stderr)
