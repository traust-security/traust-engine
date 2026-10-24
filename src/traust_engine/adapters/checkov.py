"""Deterministic Kubernetes hardening & tenancy scanner.

Gives /secure-code-audit's configuration-hardening (CIS/DISA STIG/OWASP K8s)
and multi-tenant isolation sections a machine-verifiable evidence base:
instead of the model free-reading manifests, this script parses every
Kubernetes YAML document in a checkout (including ClusterServiceVersion-
embedded deployments), applies a fixed catalog of checks, and emits JSON
facts with exact file:line locations. The model's job shifts to what it is
good at — reachability, context, severity — while "what does the manifest
actually say" becomes reproducible.

Design rules:
- Facts, not findings. Each result is a true statement about a file
  (severity_hint is advisory); promotion to a report finding, deduping, and
  severity are the audit's job.
- Framework refs are bare IDs only (OWASP K8s K-IDs; CIS section numbers
  where the mapping is unambiguous) — never benchmark text (see
  docs/external-dependencies.md and traust.cli.check_content_licenses).
- Helm-templated files cannot be parsed as YAML; they are skipped and
  *counted* so the audit knows what still needs manual review. Silent
  truncation is the failure mode this repo's tooling culture forbids.
- Paths under test/example trees are still scanned but tagged
  `test_path: true` so the audit can down-weight them.

Output (JSON):
  {
    "tool": "scan_k8s_hardening", "version": "<harness VERSION>",
    "target": "<abs path>",
    "stats": {files_scanned, k8s_docs, templated_skipped, unparseable},
    "templated_files": [...], "unparseable_files": [...],
    "results": [ {check, title, severity_hint, frameworks[], kind, name,
                  file, line, detail, test_path} ],
    "summary": {"<check>": count},
    "tenancy_signals": {
       csv_install_modes, cluster_scoped_rbac, watch_scope_hints[],
       subject_access_review_usage[], insecure_skip_verify[],
       network_policies[], openshift_network_policies[],
       psa_labeled_namespaces, namespaces_total
    }
  }

Usage:
  traust adapters checkov <checkout> [-o out.json]
  traust adapters checkov <checkout> --summary   # human table
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

from traust_contracts.models import AdapterResult, Location

from traust_engine.adapters._contract_bridge import (
    build_scan_result,
    map_severity,
    utc_now,
)

try:
    import yaml
except ImportError:  # pragma: no cover
    print("pyyaml is required: pip install pyyaml", file=sys.stderr)
    sys.exit(2)

REPO = Path(__file__).resolve().parents[1]

EXCLUDE_DIRS = {"vendor", "node_modules", "third_party", "_output", ".git", "testdata"}
TEST_PATH_RE = re.compile(r"(^|/)(tests?|e2e|examples?|hack)(/|$)")
DANGEROUS_CAPS = {
    "SYS_ADMIN",
    "NET_ADMIN",
    "SYS_PTRACE",
    "SYS_MODULE",
    "DAC_OVERRIDE",
    "NET_RAW",
    "ALL",
}
WORKLOAD_KINDS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}

# check id -> (title, severity_hint, framework refs)
CATALOG = {
    "KHS-W01": ("Privileged container", "high", ["K01", "CIS 5.2"]),
    "KHS-W02": ("allowPrivilegeEscalation not disabled", "medium", ["K01", "CIS 5.2"]),
    "KHS-W03": ("Container may run as root", "medium", ["K01", "CIS 5.2"]),
    "KHS-W04": ("Dangerous capability added", "high", ["K01", "CIS 5.2"]),
    "KHS-W05": ("Root filesystem not read-only", "low", ["K01"]),
    "KHS-W06": ("Host namespace sharing enabled", "high", ["K01", "CIS 5.2"]),
    "KHS-W07": ("hostPath volume mounted", "medium", ["K01", "CIS 5.2"]),
    "KHS-W08": ("Missing resource limits", "low", ["K01"]),
    "KHS-W09": ("ServiceAccount token automounted", "low", ["K09", "CIS 5.1.6"]),
    "KHS-W10": ("Default ServiceAccount used", "low", ["K09", "CIS 5.1.5"]),
    "KHS-W11": ("Image not pinned by digest", "low", ["K07"]),
    "KHS-W12": ("No seccomp profile", "low", ["K01"]),
    "KHS-W13": ("Secret exposed via environment variable", "medium", ["K03"]),
    "KHS-R01": ("Wildcard in RBAC rule", "high", ["K02", "CIS 5.1.3"]),
    "KHS-R02": ("Binding to cluster-admin", "high", ["K02", "CIS 5.1.1"]),
    "KHS-R03": ("Read access to secrets", "medium", ["K02", "CIS 5.1.2"]),
    "KHS-R04": ("Privilege-escalation verb granted", "high", ["K02"]),
    "KHS-N01": ("Service exposed via NodePort/LoadBalancer", "medium", ["K05"]),
    "KHS-N02": ("No NetworkPolicy shipped for workloads", "low", ["K05"]),
    "KHS-N03": ("NetworkPolicy allows all traffic (permissive)", "medium", ["K05"]),
    "KHS-N04": ("Permissive OpenShift network policy (allow-all rule)", "medium", ["K05"]),
    "KHS-H01": ("Webhook failurePolicy Ignore", "medium", ["K04"]),
    "KHS-P01": ("Namespace without PSA enforce label", "low", ["K04"]),
    "KHS-A01": ("Insecure flag in container args", "high", ["K06"]),
}

INSECURE_ARG_RE = re.compile(
    r"--insecure-skip-tls-verify(?!=false)|--anonymous-auth=true"
    r"|--insecure-port=(?!0)\d|--insecure-bind-address"
    r"|--kubelet-https=false|--tls-private-key-file=\s*$"
)
ESCALATION_VERBS = {"escalate", "bind", "impersonate"}

# --- code-signal patterns (tenancy/interface evidence, not checks) ---------
CODE_SIGNALS = {
    "insecure_skip_verify": re.compile(r"InsecureSkipVerify\s*:\s*true"),
    "watch_scope": re.compile(
        r"WATCH_NAMESPACE|MultiNamespacedCacheBuilder"
        r"|DefaultNamespaces\s*:|cache\.Options\{"
    ),
    "subject_access_review": re.compile(r"SubjectAccessReview|TokenReview|SelfSubjectAccessReview"),
    # API-group string literals (GroupVersion{...}, GVK/GVR composites) —
    # consumption evidence for the portfolio graph's interface layer
    "api_group_literal": re.compile(r'Group:\s*"([a-z0-9][a-z0-9.\-]*\.[a-z]{2,})"'),
}
CODE_SIGNAL_KEYS = {
    "insecure_skip_verify": "insecure_skip_verify",
    "watch_scope": "watch_scope_hints",
    "subject_access_review": "subject_access_review_usage",
    "api_group_literal": "api_group_literals",
}
CODE_EXTS = {".go"}


class LineLoader(yaml.SafeLoader):
    """SafeLoader that records the source line of every mapping."""


def _construct_mapping(loader, node, deep=False):
    mapping = yaml.SafeLoader.construct_mapping(loader, node, deep=deep)
    mapping["__line__"] = node.start_mark.line + 1
    return mapping


LineLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def _line(obj, default=0) -> int:
    return obj.get("__line__", default) if isinstance(obj, dict) else default


def _get(obj, *path, default=None):
    for key in path:
        if not isinstance(obj, dict):
            return default
        obj = obj.get(key)
    return obj if obj is not None else default


def _bare_keys(obj) -> set:
    """Keys of a mapping minus the __line__ marker LineLoader injects."""
    return {k for k in obj if k != "__line__"} if isinstance(obj, dict) else set()


def _selector_matches_all(sel) -> bool:
    """True for label selectors that select everything: `{}`,
    `matchLabels: {}`, or `matchExpressions: []`."""
    if not isinstance(sel, dict):
        return False
    for key in _bare_keys(sel):
        val = sel[key]
        if isinstance(val, dict) and not _bare_keys(val):
            continue
        if val:
            return False
    return True


class Scanner:
    def __init__(self, root: Path):
        self.root = root
        self.results: list[dict] = []
        self.stats = {"files_scanned": 0, "k8s_docs": 0, "templated_skipped": 0, "unparseable": 0}
        self.templated_files: list[str] = []
        self.unparseable_files: list[str] = []
        self.signals = {
            "csv_install_modes": {},
            "cluster_scoped_rbac": [],
            "watch_scope_hints": [],
            "subject_access_review_usage": [],
            "insecure_skip_verify": [],
            "network_policies": [],
            # OpenShift-specific network objects (ANP/BANP/EgressFirewall/
            # EgressNetworkPolicy/MultiNetworkPolicy) — recorded separately:
            # none of them is pod-level primary-network default-deny, so
            # they never suppress KHS-N02.
            "openshift_network_policies": [],
            "psa_labeled_namespaces": 0,
            "namespaces_total": 0,
            # interface extraction (portfolio-graph Layer 2 + audit context)
            "crds_defined": [],
            "csv_owned_crds": [],
            "csv_required_crds": [],
            "webhooks": [],
            "rbac_grants": [],
            "api_group_literals": [],
        }
        self._workloads_seen = 0

    # -- emit ---------------------------------------------------------------
    def hit(self, check: str, rel: str, line: int, kind: str, name: str, detail: str):
        title, sev, frameworks = CATALOG[check]
        self.results.append(
            {
                "check": check,
                "title": title,
                "severity_hint": sev,
                "frameworks": frameworks,
                "kind": kind,
                "name": name,
                "file": rel,
                "line": line,
                "detail": detail,
                "test_path": bool(TEST_PATH_RE.search(rel)),
                # Kustomize patch overlays are partial manifests: a field absent
                # here may be set in the base, so absence-checks on these files
                # need the merged result verified before promotion to a finding.
                "patch_overlay": "patch" in Path(rel).name.lower(),
            }
        )

    # -- workload podspec ----------------------------------------------------
    def scan_podspec(self, spec: dict, rel: str, kind: str, name: str):
        if not isinstance(spec, dict):
            return
        self._workloads_seen += 1
        line = _line(spec)
        for field in ("hostNetwork", "hostPID", "hostIPC"):
            if spec.get(field) is True:
                self.hit("KHS-W06", rel, line, kind, name, f"{field}: true")
        for vol in spec.get("volumes") or []:
            if isinstance(vol, dict) and "hostPath" in vol:
                self.hit(
                    "KHS-W07",
                    rel,
                    _line(vol, line),
                    kind,
                    name,
                    f"volume '{vol.get('name')}' mounts hostPath {_get(vol, 'hostPath', 'path')!r}",
                )
        sa = spec.get("serviceAccountName") or spec.get("serviceAccount")
        if not sa or sa == "default":
            self.hit("KHS-W10", rel, line, kind, name, "serviceAccountName absent or 'default'")
        if spec.get("automountServiceAccountToken") is not False:
            self.hit(
                "KHS-W09", rel, line, kind, name, "automountServiceAccountToken not set to false"
            )
        pod_sc = spec.get("securityContext") or {}
        for c in (spec.get("containers") or []) + (spec.get("initContainers") or []):
            if isinstance(c, dict):
                self.scan_container(c, pod_sc, rel, kind, name)

    def scan_container(self, c: dict, pod_sc: dict, rel: str, kind: str, name: str):
        cname = c.get("name", "?")
        line = _line(c)
        ident = f"container '{cname}'"
        sc = c.get("securityContext") or {}

        if sc.get("privileged") is True:
            self.hit("KHS-W01", rel, _line(sc, line), kind, name, f"{ident}: privileged: true")
        if sc.get("allowPrivilegeEscalation") is not False:
            self.hit(
                "KHS-W02",
                rel,
                line,
                kind,
                name,
                f"{ident}: allowPrivilegeEscalation not set to false",
            )
        run_as_nonroot = sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot"))
        run_as_user = sc.get("runAsUser", pod_sc.get("runAsUser"))
        if run_as_nonroot is not True and (run_as_user in (None, 0)):
            self.hit(
                "KHS-W03",
                rel,
                line,
                kind,
                name,
                f"{ident}: runAsNonRoot/runAsUser leave root possible",
            )
        caps = _get(sc, "capabilities", default={}) or {}
        added = {str(x).upper() for x in caps.get("add") or []}
        bad = added & DANGEROUS_CAPS
        if bad:
            self.hit("KHS-W04", rel, _line(sc, line), kind, name, f"{ident}: adds {sorted(bad)}")
        if sc.get("readOnlyRootFilesystem") is not True:
            self.hit("KHS-W05", rel, line, kind, name, f"{ident}: readOnlyRootFilesystem not true")
        if not _get(c, "resources", "limits"):
            self.hit("KHS-W08", rel, line, kind, name, f"{ident}: no resources.limits")
        seccomp = sc.get("seccompProfile") or pod_sc.get("seccompProfile")
        if not seccomp:
            self.hit(
                "KHS-W12", rel, line, kind, name, f"{ident}: no seccompProfile (pod or container)"
            )
        image = c.get("image", "")
        if image and "@sha256:" not in image:
            tag = image.rsplit(":", 1)[-1] if ":" in image else "latest"
            self.hit(
                "KHS-W11",
                rel,
                line,
                kind,
                name,
                f"{ident}: image '{image}' pinned by tag '{tag}', not digest",
            )
        for env in c.get("env") or []:
            if _get(env, "valueFrom", "secretKeyRef"):
                self.hit(
                    "KHS-W13",
                    rel,
                    _line(env, line),
                    kind,
                    name,
                    f"{ident}: env '{env.get('name')}' from Secret (prefer volume mount)",
                )
        for ef in c.get("envFrom") or []:
            if isinstance(ef, dict) and "secretRef" in ef:
                self.hit(
                    "KHS-W13",
                    rel,
                    _line(ef, line),
                    kind,
                    name,
                    f"{ident}: envFrom secretRef '{_get(ef, 'secretRef', 'name')}'",
                )
        for arg in (c.get("args") or []) + (c.get("command") or []):
            m = INSECURE_ARG_RE.search(str(arg))
            if m:
                self.hit("KHS-A01", rel, line, kind, name, f"{ident}: arg '{m.group(0)}'")

    # -- rbac -----------------------------------------------------------------
    def scan_rbac(self, doc: dict, rel: str, kind: str, name: str):
        if kind in ("Role", "ClusterRole"):
            if kind == "ClusterRole":
                self.signals["cluster_scoped_rbac"].append({"file": rel, "name": name})
            for rule in doc.get("rules") or []:
                if not isinstance(rule, dict):
                    continue
                rline = _line(rule, _line(doc))
                verbs = [str(v) for v in rule.get("verbs") or []]
                resources = [str(r) for r in rule.get("resources") or []]
                groups = [str(g) for g in rule.get("apiGroups") or []]
                self.signals["rbac_grants"].append(
                    {
                        "file": rel,
                        "role_kind": kind,
                        "role_name": name,
                        "api_groups": groups,
                        "resources": resources,
                        "verbs": verbs,
                    }
                )
                wild = [
                    f
                    for f, vals in (
                        ("verbs", verbs),
                        ("resources", resources),
                        ("apiGroups", groups),
                    )
                    if "*" in vals
                ]
                if wild:
                    self.hit(
                        "KHS-R01",
                        rel,
                        rline,
                        kind,
                        name,
                        f"wildcard in {'+'.join(wild)} (verbs={verbs}, resources={resources})",
                    )
                if "secrets" in resources and ({"get", "list", "watch", "*"} & set(verbs)):
                    self.hit(
                        "KHS-R03", rel, rline, kind, name, f"secrets access with verbs {verbs}"
                    )
                esc = ESCALATION_VERBS & set(verbs)
                if esc:
                    self.hit(
                        "KHS-R04",
                        rel,
                        rline,
                        kind,
                        name,
                        f"grants {sorted(esc)} on {resources or groups}",
                    )
        elif kind in ("RoleBinding", "ClusterRoleBinding"):
            if _get(doc, "roleRef", "name") == "cluster-admin":
                self.hit("KHS-R02", rel, _line(doc), kind, name, "roleRef: cluster-admin")

    # -- network policy ---------------------------------------------------------
    def scan_network_policy(self, doc: dict, rel: str, name: str, kind: str = "NetworkPolicy"):
        """Flag allow-all shapes (KHS-N03). A policy with NO rules in a
        declared policyType is deny-all — correct, never flagged; the
        permissive shapes are an empty rule `{}`, a rule with ports but no
        peers, a match-all namespaceSelector peer, and a 0.0.0.0/0 ipBlock.
        MultiNetworkPolicy (k8s.cni.cncf.io, secondary networks) shares the
        NetworkPolicy spec verbatim, so it runs through the same logic."""
        line = _line(doc)
        spec = doc.get("spec") or {}
        before = len(self.results)
        for direction, peer_key in (("ingress", "from"), ("egress", "to")):
            for rule in spec.get(direction) or []:
                if not isinstance(rule, dict):
                    continue
                rline = _line(rule, line)
                keys = _bare_keys(rule)
                if not keys:
                    self.hit(
                        "KHS-N03",
                        rel,
                        rline,
                        kind,
                        name,
                        f"empty {direction} rule ({{}}) allows all "
                        f"{direction} traffic for selected pods",
                    )
                    continue
                if peer_key not in keys:
                    self.hit(
                        "KHS-N03",
                        rel,
                        rline,
                        kind,
                        name,
                        f"{direction} rule has no '{peer_key}' peers — "
                        f"any peer allowed on the listed ports",
                    )
                    continue
                for peer in rule.get(peer_key) or []:
                    if not isinstance(peer, dict):
                        continue
                    pline = _line(peer, rline)
                    pkeys = _bare_keys(peer)
                    if (
                        "namespaceSelector" in pkeys
                        and "podSelector" not in pkeys
                        and _selector_matches_all(peer["namespaceSelector"])
                    ):
                        self.hit(
                            "KHS-N03",
                            rel,
                            pline,
                            kind,
                            name,
                            f"{direction} peer namespaceSelector "
                            f"matches every namespace "
                            f"(cluster-wide allow)",
                        )
                    cidr = str(_get(peer, "ipBlock", "cidr", default=""))
                    if cidr in ("0.0.0.0/0", "::/0"):
                        exc = _get(peer, "ipBlock", "except")
                        self.hit(
                            "KHS-N03",
                            rel,
                            pline,
                            kind,
                            name,
                            f"{direction} peer ipBlock {cidr} allows "
                            f"the entire address space" + (f" (except {exc})" if exc else ""),
                        )
        entry = {"file": rel, "name": name, "permissive": len(self.results) > before}
        if kind == "NetworkPolicy":
            self.signals["network_policies"].append(entry)
        else:
            self.signals["openshift_network_policies"].append({"kind": kind, **entry})

    def scan_admin_network_policy(self, doc: dict, rel: str, kind: str, name: str):
        """AdminNetworkPolicy / BaselineAdminNetworkPolicy (KHS-N04).
        Only `action: Allow` rules can be permissive — Deny restricts and
        Pass merely delegates to namespace NetworkPolicies. An Allow whose
        peer matches every namespace (or every pod cluster-wide, or the
        whole address space via `networks`) is cluster-wide allow, and on
        an ANP it overrides namespace NetworkPolicy denies."""
        spec = doc.get("spec") or {}
        line = _line(doc)
        before = len(self.results)
        for direction, peer_key in (("ingress", "from"), ("egress", "to")):
            for rule in spec.get(direction) or []:
                if not isinstance(rule, dict):
                    continue
                if str(rule.get("action", "")).lower() != "allow":
                    continue
                rline = _line(rule, line)
                rname = rule.get("name", "?")
                for peer in rule.get(peer_key) or []:
                    if not isinstance(peer, dict):
                        continue
                    pline = _line(peer, rline)
                    if "namespaces" in _bare_keys(peer) and _selector_matches_all(
                        peer["namespaces"]
                    ):
                        self.hit(
                            "KHS-N04",
                            rel,
                            pline,
                            kind,
                            name,
                            f"{direction} rule '{rname}': Allow with "
                            f"match-all namespaces peer "
                            f"(cluster-wide allow)",
                        )
                    pods = peer.get("pods")
                    if (
                        isinstance(pods, dict)
                        and _selector_matches_all(pods.get("namespaceSelector"))
                        and _selector_matches_all(pods.get("podSelector"))
                    ):
                        self.hit(
                            "KHS-N04",
                            rel,
                            pline,
                            kind,
                            name,
                            f"{direction} rule '{rname}': Allow with "
                            f"match-all pods peer (every pod in "
                            f"every namespace)",
                        )
                    for net in peer.get("networks") or []:
                        if str(net) in ("0.0.0.0/0", "::/0"):
                            self.hit(
                                "KHS-N04",
                                rel,
                                pline,
                                kind,
                                name,
                                f"{direction} rule '{rname}': Allow "
                                f"to networks {net} (entire address "
                                f"space)",
                            )
        self.signals["openshift_network_policies"].append(
            {"kind": kind, "file": rel, "name": name, "permissive": len(self.results) > before}
        )

    def scan_egress_firewall(self, doc: dict, rel: str, kind: str, name: str):
        """EgressFirewall (OVN) / EgressNetworkPolicy (legacy SDN),
        KHS-N04. Rules are first-match; a trailing `Deny 0.0.0.0/0` is the
        correct default-deny pattern and never flagged — only an Allow of
        the entire address space is, since it makes the firewall a no-op
        for everything the preceding rules didn't already decide."""
        spec = doc.get("spec") or {}
        line = _line(doc)
        before = len(self.results)
        for rule in spec.get("egress") or []:
            if not isinstance(rule, dict):
                continue
            if str(rule.get("type", "")).lower() != "allow":
                continue
            cidr = str(_get(rule, "to", "cidrSelector", default=""))
            if cidr in ("0.0.0.0/0", "::/0"):
                self.hit(
                    "KHS-N04",
                    rel,
                    _line(rule, line),
                    kind,
                    name,
                    f"egress Allow to cidrSelector {cidr} — permits the entire address space",
                )
        self.signals["openshift_network_policies"].append(
            {"kind": kind, "file": rel, "name": name, "permissive": len(self.results) > before}
        )

    # -- other kinds -----------------------------------------------------------
    def scan_doc(self, doc: dict, rel: str):
        kind = doc.get("kind")
        name = _get(doc, "metadata", "name", default="?")
        line = _line(doc)
        self.stats["k8s_docs"] += 1

        if kind in WORKLOAD_KINDS:
            if kind == "Pod":
                self.scan_podspec(doc.get("spec"), rel, kind, name)
            elif kind == "CronJob":
                self.scan_podspec(
                    _get(doc, "spec", "jobTemplate", "spec", "template", "spec"), rel, kind, name
                )
            else:
                self.scan_podspec(_get(doc, "spec", "template", "spec"), rel, kind, name)
        elif kind in ("Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"):
            self.scan_rbac(doc, rel, kind, name)
        elif kind == "Service":
            stype = _get(doc, "spec", "type")
            if stype in ("NodePort", "LoadBalancer"):
                self.hit("KHS-N01", rel, line, kind, name, f"type: {stype}")
        elif kind == "NetworkPolicy":
            self.scan_network_policy(doc, rel, name)
        elif kind == "MultiNetworkPolicy":
            self.scan_network_policy(doc, rel, name, kind=kind)
        elif kind in ("AdminNetworkPolicy", "BaselineAdminNetworkPolicy"):
            self.scan_admin_network_policy(doc, rel, kind, name)
        elif kind in ("EgressFirewall", "EgressNetworkPolicy"):
            self.scan_egress_firewall(doc, rel, kind, name)
        elif kind in ("ValidatingWebhookConfiguration", "MutatingWebhookConfiguration"):
            for wh in doc.get("webhooks") or []:
                if not isinstance(wh, dict):
                    continue
                if wh.get("failurePolicy") == "Ignore":
                    self.hit(
                        "KHS-H01",
                        rel,
                        _line(wh, line),
                        kind,
                        name,
                        f"webhook '{wh.get('name')}': failurePolicy: Ignore",
                    )
                rules = [
                    {
                        "groups": r.get("apiGroups"),
                        "resources": r.get("resources"),
                        "operations": r.get("operations"),
                    }
                    for r in wh.get("rules") or []
                    if isinstance(r, dict)
                ]
                self.signals["webhooks"].append(
                    {
                        "file": rel,
                        "config": name,
                        "mutating": kind.startswith("Mutating"),
                        "name": wh.get("name"),
                        "failure_policy": wh.get("failurePolicy"),
                        "rules": rules,
                    }
                )
        elif kind == "CustomResourceDefinition":
            names = _get(doc, "spec", "names", default={}) or {}
            self.signals["crds_defined"].append(
                {
                    "file": rel,
                    "group": _get(doc, "spec", "group"),
                    "kind": names.get("kind"),
                    "plural": names.get("plural"),
                    "scope": _get(doc, "spec", "scope"),
                }
            )
        elif kind == "Namespace":
            self.signals["namespaces_total"] += 1
            labels = _get(doc, "metadata", "labels", default={}) or {}
            if any(str(k).startswith("pod-security.kubernetes.io/enforce") for k in labels):
                self.signals["psa_labeled_namespaces"] += 1
            else:
                self.hit(
                    "KHS-P01", rel, line, kind, name, "no pod-security.kubernetes.io/enforce label"
                )
        elif kind == "ClusterServiceVersion":
            for im in _get(doc, "spec", "installModes", default=[]) or []:
                if isinstance(im, dict) and "type" in im:
                    self.signals["csv_install_modes"][im["type"]] = bool(im.get("supported"))
            for key, sig in (("owned", "csv_owned_crds"), ("required", "csv_required_crds")):
                for c in _get(doc, "spec", "customresourcedefinitions", key, default=[]) or []:
                    if isinstance(c, dict):
                        self.signals[sig].append(
                            {
                                "file": rel,
                                "name": c.get("name"),
                                "kind": c.get("kind"),
                                "version": c.get("version"),
                            }
                        )
            for dep in _get(doc, "spec", "install", "spec", "deployments", default=[]) or []:
                if isinstance(dep, dict):
                    self.scan_podspec(
                        _get(dep, "spec", "template", "spec"),
                        rel,
                        "ClusterServiceVersion/Deployment",
                        dep.get("name", name),
                    )

    # -- file walkers ------------------------------------------------------------
    def scan_yaml_file(self, path: Path):
        rel = path.relative_to(self.root).as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return
        self.stats["files_scanned"] += 1
        if "{{" in text and "}}" in text:  # Helm/Go template — not YAML yet
            self.stats["templated_skipped"] += 1
            self.templated_files.append(rel)
            return
        try:
            docs = list(yaml.load_all(text, Loader=LineLoader))
        except yaml.YAMLError:
            self.stats["unparseable"] += 1
            self.unparseable_files.append(rel)
            return
        for doc in docs:
            if isinstance(doc, dict) and doc.get("apiVersion") and doc.get("kind"):
                self.scan_doc(doc, rel)

    def scan_code_file(self, path: Path):
        rel = path.relative_to(self.root).as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return
        for signal, rx in CODE_SIGNALS.items():
            for m in rx.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                entry = {"file": rel, "line": line, "match": m.group(0)}
                if m.groups():
                    entry["value"] = m.group(1)
                self.signals[CODE_SIGNAL_KEYS[signal]].append(entry)

    def run(self):
        for path in sorted(self.root.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            parts = set(path.relative_to(self.root).parts[:-1])
            if parts & EXCLUDE_DIRS:
                continue
            if path.suffix in (".yaml", ".yml"):
                self.scan_yaml_file(path)
            elif path.suffix in CODE_EXTS:
                self.scan_code_file(path)
        # repo-level: workloads shipped but zero NetworkPolicy manifests
        if self._workloads_seen and not self.signals["network_policies"]:
            self.hit(
                "KHS-N02",
                ".",
                0,
                "(repo)",
                "(repo)",
                f"{self._workloads_seen} workload manifest(s), 0 NetworkPolicy manifests",
            )

    def report(self) -> dict:
        summary: dict[str, int] = {}
        for r in self.results:
            summary[r["check"]] = summary.get(r["check"], 0) + 1
        version = "unknown"
        vf = REPO / "VERSION"
        if vf.is_file():
            version = vf.read_text().strip()
        return {
            "tool": "scan_k8s_hardening",
            "version": version,
            "target": str(self.root),
            "stats": self.stats,
            "templated_files": self.templated_files,
            "unparseable_files": self.unparseable_files,
            "results": self.results,
            "summary": dict(sorted(summary.items())),
            "tenancy_signals": self.signals,
        }


def _results_to_findings(results: list[dict]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for r in results:
        loc = (
            Location(
                path=r["file"],
                lines=str(r.get("line", "")),
                description=r.get("detail", ""),
            )
            if Location is not None
            else {
                "path": r["file"],
                "lines": str(r.get("line", "")),
                "description": r.get("detail", ""),
            }
        )
        findings.append(
            {
                "id": f"checkov/{r['check']}",
                "title": r.get("title", r["check"]),
                "severity": map_severity(r.get("severity_hint", "low")),
                "locations": [loc],
                "description": r.get("detail", ""),
                "category": r.get("check", ""),
            }
        )
    return findings


def scan(
    target: Path,
    framework: str | None = None,
    timeout: int = 600,
) -> AdapterResult:
    """Run K8s hardening scan and return typed scan result."""
    del framework, timeout  # reserved for future framework filtering
    root = target.resolve()
    if not root.is_dir():
        raise ValueError(f"not a directory: {root}")
    scanner = Scanner(root)
    scanner.run()
    report = scanner.report()
    return build_scan_result(
        str(root),
        "checkov",
        _results_to_findings(report["results"]),
        scanned_at=utc_now(),
        scanner_version=report.get("version", ""),
        focus_areas=["kubernetes"],
    )
