"""CVE impact analysis across the portfolio graph.

Queries the portfolio graph for blast radius, then runs language-specific
analysis to determine per-repo affectedness.

Go analysis path:
  1. govulncheck source mode  → symbol reachability
  2. govulncheck binary mode  → binary-level confirmation
  3. ELF string scan          → package path presence in shipped images
  4. If inconclusive (unsafe/reflect/cgo) → flagged for manual trace

Usage:
    python3 run_impact_analysis.py CVE-2026-33186 \\
        --module google.golang.org/grpc \\
        --packages google.golang.org/grpc/authz \\
        --vulnerable-range '< v1.64.1' --fixed-version v1.64.1 \\
        --feature-desc 'gRPC path-based authorization' \\
        [--db portfolio-graph.db] [--out <file>] [--jobs 4]

Exit 0 on success; 1 on failure; 2 on usage errors.
"""

from __future__ import annotations

import abc
import datetime
import json
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from traust_contracts.models import ImpactAnalysis

from traust_engine._util.elf import ElfAnalyzer
from traust_engine._util.versions import parse_semver as parse_semver  # re-exported
from traust_engine._util.versions import parse_version
from traust_engine.adapters.govulncheck import parse_stream
from traust_engine.assets import harness_version as engine_harness_version
from traust_engine.impact.advisory import ResolvedAdvisory
from traust_engine.portfolio import parsers as MP
from traust_engine.portfolio.graph import db_connect, q_blast_radius, q_imports_package


def emit_impact_analysis(doc: dict) -> dict:
    """Validate and normalize impact output through the contract model."""
    return ImpactAnalysis.from_dict(doc).to_dict()


# Advisory ids accepted as the positional argument. The value becomes both
# an argv positional and a filename component (<id>-impact-analysis.json),
# so the charset is deliberately restricted to a known advisory prefix plus
# alnum/dash, bounded in length — no slashes, dots, spaces, or shell
# metacharacters can ever appear. CVE-YYYY-NNNN (the only form the legacy
# gate accepted) remains valid: this pattern is a strict superset of it.
ADVISORY_ID_RX = re.compile(
    r"^(?:CVE|GHSA|MAL|PYSEC|GO|RUSTSEC|OSV)-[A-Za-z0-9][A-Za-z0-9-]{0,63}$"
)

# Manifest-surface ecosystems: GitHub Actions, Docker base images, Helm
# charts. They carry depends_on edges in the portfolio graph (so the graph
# blast-radius query is meaningful) but have no language deep-scanner and
# no call-graph reachability tier. detect_language() cannot return them —
# analyze_repo routes them to SurfaceAnalyzer instead (manifest-level
# confirmation only; ceiling likely_affected).
SURFACE_ECOSYSTEMS = ("actions", "docker", "helm")


def valid_advisory_id(advisory_id: str) -> bool:
    """True iff `advisory_id` is a recognized, argv/filename-safe OSV id."""
    return bool(ADVISORY_ID_RX.match(advisory_id or ""))


TIER_MAP = {
    "govulncheck_source": "govulncheck",
    "elf_string_scan": "binary_scan",
    "manifest_scan": "manifest_scan",
    "source_import_scan": "source_scan",
    "symbol_usage_scan": "source_scan",
    "sbom_cross_check": "sbom_cross_check",
    "elf_linked_library_scan": "binary_scan",
}


# Every comparison bound in a `vulnerable_range` string, e.g. '>=2.5.3 <2.8.0'
# yields [('>=', '2.5.3'), ('<', '2.8.0')]. The version token stops at
# whitespace, comma, or the next operator so multiple bounds parse cleanly.
_RANGE_BOUND_RX = re.compile(r"(<=|>=|<|>)\s*([^\s,<>=]+)")


def version_in_range(
    version: str,
    vulnerable_range: str,
    fixed_version: str | None,
    ecosystem: str = "go",
) -> bool | None:
    """True iff `version` falls inside the vulnerable range.

    Honors every decidable constraint, ANDed together:
      * `fixed_version` as an upper bound (ver < fix);
      * an upper bound (`<`/`<=`) parsed from `vulnerable_range`;
      * a LOWER bound (`>=`/`>`) parsed from `vulnerable_range` — a version
        below the lower bound is NOT in range even when it is below the fix.
    A range may carry both bounds (e.g. '>=2.5.3 <2.8.0').

    Returns None when the version is unparseable, or when no constraint at
    all is decidable — callers treat None as "cannot decide": the repo stays
    inconclusive and is still deep-scanned, so a garbage version never
    becomes a false `version_not_in_range`/`safe`.

    Regression-safe for the Go/default path: a bare `fixed_version` or a
    single `<`/`<=` upper bound reduces to the previous `ver < fix` /
    single-bound comparison.
    """
    ver = parse_version(version, ecosystem)
    if ver is None:
        return None

    constraints: list[bool] = []

    if fixed_version:
        fix = parse_version(fixed_version, ecosystem)
        if fix is not None:
            constraints.append(ver < fix)

    ops = {
        "<": ver.__lt__,
        "<=": ver.__le__,
        ">=": ver.__ge__,
        ">": ver.__gt__,
    }
    for op, raw in _RANGE_BOUND_RX.findall(vulnerable_range or ""):
        bound = parse_version(raw, ecosystem)
        if bound is not None:
            constraints.append(ops[op](bound))

    if not constraints:
        return None
    return all(constraints)


# -------------------------------------------------------------- evidence


@dataclass
class RepoEvidence:
    """Accumulated evidence for one repo. Each analyzer fills its fields."""

    l1_depends_on: bool = True
    l1_version_in_range: bool | None = None
    l4_package_imported: bool | None = None
    l4_packages_found: list[str] | None = None
    govulncheck: str | None = None
    govulncheck_trace: list[str] | None = None
    feature_pattern_matches: int | None = None
    binary_string_scan: str | None = None
    manifest_scan: str | None = None
    manifest_version: str | None = None
    source_import_scan: str | None = None
    symbol_usage_scan: str | None = None
    binary_linked_library: str | None = None
    binary_symbol_scan: str | None = None
    sbom_scan: str | None = None
    sbom_shipped_version: str | None = None
    joern_reachability: str | None = None
    joern_witness: dict | None = None
    evidence_level: str | None = None
    needs_manual_trace: bool = False
    notes: str | None = None

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v is not None}


def _run_joern_tier(
    clone_path: Path, evidence: RepoEvidence, ctx: AnalysisContext, language: str
) -> bool:
    """Joern call-site reachability — the analogue of govulncheck's
    symbol tier for Java and C/C++
    (traust adapters joern; validated on representative
    Java/C++ corpora).

    EVIDENCE ASYMMETRY: a resolved call site to a vulnerable symbol
    PROMOTES the evidence level to "symbol"; an absent path never
    demotes anything (Java DI/reflection — and C function pointers —
    hide edges from static analysis). Line numbers in the witness are
    approximate; the caller method is the authoritative anchor."""
    if shutil.which("joern") is None:
        evidence.joern_reachability = "skipped: joern not on PATH"
        return False
    out = clone_path.parent / f"{clone_path.name}-joern-reachability.json"
    cmd = [
        sys.executable,
        "-m",
        "traust_engine.adapters.joern",
        "--repo",
        str(clone_path),
        "--out",
        str(out),
        "--language",
        language,
        "--module",
        ctx.module,
        "--packages",
        ",".join(ctx.packages or []),
    ]
    for s in ctx.symbols or []:
        cmd += ["--symbols", s]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=1800, check=False)
        doc = json.loads(out.read_text(encoding="utf-8"))
    except (subprocess.SubprocessError, OSError, json.JSONDecodeError) as e:
        evidence.joern_reachability = f"error: {e}"[:120]
        return False
    if doc.get("status") != "ran":
        evidence.joern_reachability = str(doc.get("status"))[:120]
        return True
    targets = doc.get("targets") or []
    sym_hits = [t for t in targets if t["kind"] == "symbol" and t.get("referenced")]
    pkg_hits = [t for t in targets if t["kind"] != "symbol" and t.get("referenced")]
    if sym_hits:
        evidence.joern_reachability = "vulnerable_symbol_called"
        evidence.joern_witness = sym_hits[0]["call_sites"][0]
        evidence.evidence_level = "symbol"
    elif pkg_hits:
        evidence.joern_reachability = "package_api_called"
        evidence.joern_witness = pkg_hits[0]["call_sites"][0]
        if evidence.evidence_level == "manifest":
            evidence.evidence_level = "symbol-usage"
    else:
        # absent path: record honestly, demote NOTHING
        evidence.joern_reachability = "no_call_sites_found"
    return True


# ------------------------------------------------------------ analyzers


class LanguageAnalyzer(abc.ABC):
    """Per-language analysis strategy. Subclass for each ecosystem."""

    @abc.abstractmethod
    def analyze(
        self,
        clone_path: Path,
        repo_id: str,
        evidence: RepoEvidence,
        ctx: AnalysisContext,
    ) -> list[str]:
        """Run all analysis tiers, mutating evidence in place.
        Returns names of tiers actually executed."""

    @property
    @abc.abstractmethod
    def name(self) -> str: ...


@dataclass
class AnalysisContext:
    """Shared state passed to every analyzer."""

    cve: str
    module: str
    packages: list[str]
    symbols: list[str]
    vulnerable_range: str
    fixed_version: str | None
    feature_desc: str | None
    db_path: Path
    con: sqlite3.Connection
    ecosystem: str = "go"
    results_loc: str | None = None
    # The fetched record; when set it decides every range question, and the two
    # strings above are its rendering for the artifact.
    advisory: ResolvedAdvisory | None = None

    def in_range(self, version: str | None) -> bool | None:
        if self.advisory is not None:
            return self.advisory.in_range(version)
        return version_in_range(
            version or "", self.vulnerable_range, self.fixed_version, self.ecosystem
        )


# ---- Go analyzer


class GoAnalyzer(LanguageAnalyzer):
    name = "go"

    def analyze(
        self,
        clone_path: Path,
        repo_id: str,
        evidence: RepoEvidence,
        ctx: AnalysisContext,
    ) -> list[str]:
        tiers_run: list[str] = []
        if not (clone_path / "go.mod").exists():
            evidence.notes = "no go.mod — skipped"
            return tiers_run
        if self._govulncheck_source(clone_path, repo_id, evidence, ctx):
            tiers_run.append("govulncheck_source")
        if evidence.govulncheck == "symbol_reachable":
            evidence.evidence_level = "symbol"
            return tiers_run
        if self._elf_scan(repo_id, evidence, ctx):
            tiers_run.append("elf_string_scan")
        self._check_needs_manual(clone_path, evidence)
        evidence.evidence_level = (
            "symbol"
            if evidence.govulncheck
            else ("binary" if evidence.binary_string_scan else "none")
        )
        return tiers_run

    def _govulncheck_source(
        self,
        clone_path: Path,
        repo_id: str,
        evidence: RepoEvidence,
        ctx: AnalysisContext,
    ) -> bool:
        """Returns True if the tier actually executed."""
        govulncheck = shutil.which("govulncheck")
        if not govulncheck:
            evidence.notes = (evidence.notes or "") + "; govulncheck not found"
            return False
        try:
            proc = subprocess.run(
                [govulncheck, "-json", "-C", str(clone_path), "./..."],
                capture_output=True,
                text=True,
                timeout=900,
            )
        except subprocess.TimeoutExpired:
            evidence.notes = (evidence.notes or "") + "; govulncheck timeout"
            return False

        tool, candidates = parse_stream(proc.stdout)

        if not tool and proc.returncode != 0:
            evidence.notes = (
                (evidence.notes or "")
                + f"; govulncheck failed (exit {proc.returncode}): "
                + (proc.stderr.strip()[:300] or "no stderr")
            )
            return False

        best_reach = "module_required_not_observed"
        best_trace: list[str] = []
        reach_order = [
            "module_required_not_observed",
            "package_imported_not_observed",
            "symbol_reachable",
        ]
        for cand in candidates:
            aliases = cand.get("aliases", [])
            if ctx.cve not in aliases and cand.get("module") != ctx.module:
                continue
            reach = cand.get("reachability", "module_required_not_observed")
            if reach in reach_order and reach_order.index(reach) > reach_order.index(best_reach):
                best_reach = reach
                best_trace = cand.get("example_trace", [])

        evidence.govulncheck = best_reach
        evidence.govulncheck_trace = best_trace or None
        return True

    def _elf_scan(self, repo_id: str, evidence: RepoEvidence, ctx: AnalysisContext) -> bool:
        """Scan container images shipped from this repo for package paths.
        Returns True if the tier actually executed."""
        try:
            con = sqlite3.connect(f"file:{ctx.db_path}?mode=ro", uri=True, check_same_thread=False)
            try:
                images = con.execute(
                    """
                    SELECT DISTINCT n.label FROM edges e
                    JOIN nodes n ON n.id = e.src
                    WHERE e.rel = 'built_from' AND e.dst = ?
                      AND n.kind = 'image'
                """,
                    (repo_id,),
                ).fetchall()
            finally:
                con.close()
        except sqlite3.Error:
            return False

        if not images or not ctx.packages:
            return False

        patterns = [
            (f"pkg:{pkg}", re.compile(re.escape(pkg.encode("ascii")))) for pkg in ctx.packages
        ]

        scanned = False
        for (image_ref,) in images:
            binary_path = self._resolve_image_binary(image_ref, ctx.results_loc)
            if not binary_path:
                continue
            scanned = True
            matches = ElfAnalyzer(binary_path).scan_strings(patterns)
            if matches:
                evidence.binary_string_scan = "package_path_present"
                return True

        if scanned:
            evidence.binary_string_scan = "package_path_absent"
        return scanned

    @staticmethod
    def _resolve_image_binary(image_ref: str, results_loc: str | None = None) -> Path | None:
        """Resolve a container image ref to a local binary path.

        Requires the image to have been pulled and extracted by the
        container audit pipeline. Returns None if not available locally.
        """
        results = _results_dir(results_loc)
        if results is None:
            return None
        artifacts = results / "images"
        slug = re.sub(r"[^a-zA-Z0-9_.-]", "-", image_ref)
        candidate = artifacts / slug / "usr" / "bin"
        if candidate.is_dir():
            for f in candidate.iterdir():
                if f.is_file() and ElfAnalyzer.is_elf(f.read_bytes()[:16]):
                    return f
        return None

    @staticmethod
    def _check_needs_manual(clone_path: Path, evidence: RepoEvidence) -> None:
        """Flag repos with unsafe/reflect/cgo that may hide reachability."""
        if evidence.govulncheck == "symbol_reachable":
            return
        try:
            result = subprocess.run(
                [
                    "rg",
                    "-l",
                    r'unsafe\.Pointer|reflect\.(Value|Type|DeepEqual|ValueOf|TypeOf)|import\s+"C"',
                    "--type",
                    "go",
                    str(clone_path),
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.stdout.strip():
                evidence.needs_manual_trace = True
                evidence.notes = (
                    evidence.notes or ""
                ) + "; unsafe/reflect/cgo usage detected — manual trace advised"
        except (subprocess.SubprocessError, OSError):
            pass


# ---- manifest-level analyzers (Python, Rust, JavaScript, Java)
#
# These ecosystems have no govulncheck-equivalent reachability tool wired
# in, so their ceiling is deliberately lower: manifest/lockfile evidence
# plus a source import scan can classify a repo `likely_affected` or
# `not_observed` (at manifest level) — never `affected`. The
# evidence_level field records the tier so downstream consumers can
# weigh a symbol-reachability verdict above a lockfile pin.


class LockfileAnalyzer(LanguageAnalyzer):
    """Shared manifest+source analysis for ecosystems without a
    reachability tool. Subclasses supply manifest globs, a pin
    extractor, and import-statement patterns."""

    manifest_globs: tuple[str, ...] = ()

    def extract_pins(self, filename: str, text: str) -> dict[str, str]:
        """Return {package_name: pinned_version} found in one manifest."""
        raise NotImplementedError

    def import_regex(self, module: str) -> re.Pattern:
        raise NotImplementedError

    def module_names(self, ctx: AnalysisContext) -> list[str]:
        """Candidate package names for this ecosystem (module + packages)."""
        return [ctx.module, *(ctx.packages or [])]

    def analyze(
        self,
        clone_path: Path,
        repo_id: str,
        evidence: RepoEvidence,
        ctx: AnalysisContext,
    ) -> list[str]:
        tiers_run: list[str] = []
        names = {n.lower() for n in self.module_names(ctx) if n}

        pins: dict[str, str] = {}
        saw_manifest = False
        for glob in self.manifest_globs:
            for mf in sorted(clone_path.rglob(glob)):
                if any(p in ("vendor", "node_modules", ".git") for p in mf.parts):
                    continue
                saw_manifest = True
                try:
                    text = mf.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                for name, ver in self.extract_pins(mf.name, text).items():
                    if name.lower() in names:
                        pins[name] = ver

        if saw_manifest:
            tiers_run.append("manifest_scan")
            if pins:
                ver = next(iter(pins.values()))
                evidence.manifest_version = ver
                in_range = ctx.in_range(ver)
                if in_range is False:
                    evidence.manifest_scan = "module_pinned_out_of_range"
                else:
                    evidence.manifest_scan = "module_pinned_in_range"
            else:
                evidence.manifest_scan = "module_not_in_manifests"
        else:
            evidence.manifest_scan = "no_manifests_found"

        if self._source_scan(clone_path, evidence, ctx):
            tiers_run.append("source_import_scan")

        if self._symbol_usage_scan(clone_path, evidence, ctx):
            tiers_run.append("symbol_usage_scan")

        if evidence.symbol_usage_scan == "symbols_used":
            evidence.evidence_level = "symbol-usage"
        elif saw_manifest:
            evidence.evidence_level = "manifest"
        else:
            evidence.evidence_level = "none"
        return tiers_run

    def _symbol_usage_scan(
        self, clone_path: Path, evidence: RepoEvidence, ctx: AnalysisContext
    ) -> bool:
        """Grep source for the advisory's vulnerable symbol names. Textual
        usage of the vulnerable API is stronger than a lockfile pin but
        weaker than call-graph reachability — it earns the 'symbol-usage'
        evidence level, not an 'affected' verdict."""
        symbols = [s for s in (ctx.symbols or []) if s]
        if not symbols:
            return False
        # match the bare callable name: Foo.bar / foo::bar / pkg.bar → bar
        names = sorted({re.escape(s.split(".")[-1].split("::")[-1]) for s in symbols})
        pattern = r"\b(" + "|".join(names) + r")\s*\("
        try:
            result = subprocess.run(
                ["rg", "-l", "--max-count", "1", pattern, str(clone_path)],
                capture_output=True,
                text=True,
                timeout=60,
            )
        except (subprocess.SubprocessError, OSError, FileNotFoundError):
            return False
        evidence.symbol_usage_scan = (
            "symbols_used" if result.stdout.strip() else "symbols_not_found"
        )
        return True

    def _source_scan(self, clone_path: Path, evidence: RepoEvidence, ctx: AnalysisContext) -> bool:
        rx = self.import_regex(ctx.module)
        try:
            result = subprocess.run(
                ["rg", "-l", "--max-count", "1", rx.pattern, str(clone_path)],
                capture_output=True,
                text=True,
                timeout=60,
            )
        except (subprocess.SubprocessError, OSError, FileNotFoundError):
            return False
        evidence.source_import_scan = (
            "imports_found" if result.stdout.strip() else "imports_not_found"
        )
        return True


class PythonAnalyzer(LockfileAnalyzer):
    name = "python"
    manifest_globs = (
        "requirements*.txt",
        "Pipfile.lock",
        "poetry.lock",
        "pyproject.toml",
    )

    _REQ_RX = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*[=<>~!]=+\s*([0-9][\w.+-]*)", re.M)
    _LOCK_RX = re.compile(r'name\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"')

    def extract_pins(self, filename: str, text: str) -> dict[str, str]:
        pins: dict[str, str] = {}
        if filename == "Pipfile.lock":
            try:
                data = json.loads(text)
                for sect in ("default", "develop"):
                    for name, spec in (data.get(sect) or {}).items():
                        v = (spec.get("version") or "").lstrip("=")
                        if v:
                            pins[name] = v
            except (json.JSONDecodeError, AttributeError):
                pass
            return pins
        if filename in ("poetry.lock", "pyproject.toml"):
            pins.update({m.group(1): m.group(2) for m in self._LOCK_RX.finditer(text)})
        pins.update({m.group(1): m.group(2) for m in self._REQ_RX.finditer(text)})
        return pins

    def import_regex(self, module: str) -> re.Pattern:
        top = re.escape(module.split(".")[0].replace("-", "_"))
        return re.compile(rf"^\s*(from|import)\s+{top}\b")


class RustAnalyzer(LockfileAnalyzer):
    name = "rust"
    manifest_globs = ("Cargo.lock",)

    _LOCK_RX = re.compile(r'name\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"')

    def extract_pins(self, filename: str, text: str) -> dict[str, str]:
        return {m.group(1): m.group(2) for m in self._LOCK_RX.finditer(text)}

    def import_regex(self, module: str) -> re.Pattern:
        crate = re.escape(module.replace("-", "_"))
        return re.compile(rf"\buse\s+{crate}(::|\s|;)")


class JavaScriptAnalyzer(LockfileAnalyzer):
    name = "javascript"
    manifest_globs = ("package-lock.json", "yarn.lock", "package.json")

    def extract_pins(self, filename: str, text: str) -> dict[str, str]:
        pins: dict[str, str] = {}
        if filename in ("package-lock.json", "package.json"):
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                return pins
            # package-lock v2/v3: packages/{node_modules/<name>: {version}}
            for path, spec in (data.get("packages") or {}).items():
                name = path.rpartition("node_modules/")[2]
                if name and isinstance(spec, dict) and spec.get("version"):
                    pins[name] = spec["version"]
            for sect in ("dependencies", "devDependencies"):
                for name, v in (data.get(sect) or {}).items():
                    if isinstance(v, str):
                        pins.setdefault(name, v.lstrip("^~"))
                    elif isinstance(v, dict) and v.get("version"):
                        pins.setdefault(name, v["version"])
            return pins
        # yarn.lock: "<name>@<range>":\n  version "<v>"
        for m in re.finditer(
            r'^"?([^@"\n][^@"\n]*)@[^\n]*:\n(?:[^\n]*\n)*?\s+version\s+"([^"]+)"',
            text,
            re.M,
        ):
            pins[m.group(1)] = m.group(2)
        return pins

    def import_regex(self, module: str) -> re.Pattern:
        mod = re.escape(module)
        return re.compile(rf"(require\(['\"]{mod}|from\s+['\"]{mod})")


class JavaAnalyzer(LockfileAnalyzer):
    name = "java"
    manifest_globs = ("pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile")

    def module_names(self, ctx: AnalysisContext) -> list[str]:
        # Maven coordinates arrive as group:artifact — match on the artifactId
        names = []
        for n in [ctx.module, *(ctx.packages or [])]:
            if n:
                names.append(n.rpartition(":")[2])
        return names

    def extract_pins(self, filename: str, text: str) -> dict[str, str]:
        pins: dict[str, str] = {}
        if filename == "pom.xml":
            for m in re.finditer(
                r"<artifactId>([^<]+)</artifactId>\s*<version>([^<$]+)</version>",
                text,
            ):
                pins[m.group(1)] = m.group(2).strip()
            return pins
        # gradle: group:artifact:version literals
        for m in re.finditer(r"['\"][\w.-]+:([\w.-]+):([0-9][\w.-]*)['\"]", text):
            pins[m.group(1)] = m.group(2)
        return pins

    def import_regex(self, module: str) -> re.Pattern:
        pkg = re.escape(module.rpartition(":")[0] or module)
        return re.compile(rf"^\s*import\s+{pkg}")

    def analyze(
        self,
        clone_path: Path,
        repo_id: str,
        evidence: RepoEvidence,
        ctx: AnalysisContext,
    ) -> list[str]:
        # The Java joern tier was REMOVED 2026-08-14. It never promoted a
        # single finding: 0 of 120 in-range pairs across the first full Maven
        # sweep, and still 0 after three real defects in it were fixed (wrong
        # frontend, wrong package prefix, missing --symbols). Its only output
        # was `package_api_called` -> evidence_level `symbol-usage`, which the
        # cheap textual scan above already reaches and which shares the
        # `likely_affected` ceiling with `manifest` — so it changed no
        # classification, no SLA clock and no routing.
        #
        # The blocker is INTERFACE DISPATCH, not scope or tuning: advisories
        # name library-internal methods, applications call interfaces, and the
        # concrete implementation is bound at runtime. A 5-JAR Spring closure
        # links fine (732 cross-JAR edges, DataBinder present) and the path
        # still does not resolve -- `CALLS_TO BeanWrapperImpl.getPropertyDescriptor = 0`
        # vs `CALLS_TO BeanWrapper.getPropertyDescriptor = 5`. Fixing it needs
        # devirtualization (CHA/VTA), which joern has no pass for and which
        # would make precision worse.
        #
        # Full finding, including the four eliminated hypotheses and the
        # questions to answer before re-adopting:
        # the harness's docs/reachability.md (the Joern finding is recorded there)
        #
        # The C/C++ tier is KEPT: measured 6/6 direct-call resolutions against
        # human-audited ground truth (lz4-java, netty), because C has no
        # interface dispatch. Only function-pointer dispatch hides edges there.
        return super().analyze(clone_path, repo_id, evidence, ctx)


class RubyAnalyzer(LockfileAnalyzer):
    name = "ruby"
    manifest_globs = ("Gemfile.lock", "*.gemspec", "Gemfile")

    # Gemfile.lock: inside the `specs:` block, top-level resolved specs are
    # indented exactly 4 spaces as `name (x.y.z)`. Deeper (6-space) lines are
    # sub-dependency constraints like `(>= 1.0)` — the 4-space anchor and the
    # leading-digit version guard both exclude them, so only concrete pins
    # are captured.
    _LOCK_SPEC_RX = re.compile(r"^\s{4}([A-Za-z0-9_.-]+) \(([0-9][^()\n]*)\)\s*$", re.M)
    # gemspec / Gemfile: `gem "name", "constraint"` and
    # `add[_runtime|_development]_dependency 'name', 'constraint'`. The
    # version arg is optional (a bare `gem "name"` pins nothing); these are
    # range constraints, not concrete pins, so the value is recorded
    # best-effort and the name presence is what matters downstream.
    _GEM_RX = re.compile(
        r"""(?:\bgem\b|\.add(?:_runtime|_development)?_dependency)\s*\(?\s*"""
        r"""['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?"""
    )

    def extract_pins(self, filename: str, text: str) -> dict[str, str]:
        pins: dict[str, str] = {}
        if filename == "Gemfile.lock":
            for m in self._LOCK_SPEC_RX.finditer(text):
                pins[m.group(1)] = m.group(2)
            return pins
        # *.gemspec / Gemfile
        for m in self._GEM_RX.finditer(text):
            pins[m.group(1)] = m.group(2) or ""
        return pins

    def import_regex(self, module: str) -> re.Pattern:
        # Best-effort: `require 'name'` / `require "name"`. Ruby require
        # paths often diverge from the gem name (a gem may be required under
        # a different path), so this is a weak signal, not authoritative.
        mod = re.escape(module)
        return re.compile(rf"require\s+['\"]{mod}")


class NuGetAnalyzer(LockfileAnalyzer):
    name = "nuget"
    manifest_globs = ("packages.lock.json", "*.csproj", "packages.config")

    # <PackageReference Include="Name" Version="x.y.z" /> — attribute order
    # is not guaranteed, so match Include then Version anywhere within the
    # element. (Version-as-child-element and packages.config `id`/`version`
    # attributes are a known gap; the lockfile tier below is authoritative.)
    _CSPROJ_RX = re.compile(
        r"""<PackageReference\b[^>]*?Include\s*=\s*["']([^"']+)["']"""
        r"""[^>]*?Version\s*=\s*["']([^"']+)["']""",
        re.I | re.S,
    )

    def extract_pins(self, filename: str, text: str) -> dict[str, str]:
        pins: dict[str, str] = {}
        if filename == "packages.lock.json":
            try:
                data = json.loads(text)
            except (json.JSONDecodeError, ValueError):
                return pins
            frameworks = data.get("dependencies") if isinstance(data, dict) else None
            if isinstance(frameworks, dict):
                for pkgs in frameworks.values():  # keyed per target framework
                    if not isinstance(pkgs, dict):
                        continue
                    for name, spec in pkgs.items():
                        if isinstance(spec, dict) and spec.get("resolved"):
                            pins[name] = spec["resolved"]
            return pins
        # *.csproj / packages.config
        for m in self._CSPROJ_RX.finditer(text):
            pins[m.group(1)] = m.group(2)
        return pins

    def import_regex(self, module: str) -> re.Pattern:
        # Never called — _source_scan is a no-op for nuget (see below).
        # Provided for interface completeness only.
        return re.compile(r"(?!x)x")  # matches nothing

    def _source_scan(self, clone_path: Path, evidence: RepoEvidence, ctx: AnalysisContext) -> bool:
        # A NuGet package name does not map to a predictable C#
        # `using <Namespace>` — one package can expose arbitrarily-named
        # namespaces, and package id != namespace in the general case. A
        # source-import grep would therefore be noise, not signal, so it is
        # a deliberate no-op: source_import_scan stays None and the tier is
        # not recorded. Lockfile/manifest evidence is authoritative for
        # nuget, and the language-agnostic symbol_usage_scan (bare vulnerable
        # symbol names) still runs from the base analyzer.
        return False


class CAnalyzer(LanguageAnalyzer):
    """C/C++ — no manifest ecosystem. Evidence: header-include grep in
    source, plus DT_NEEDED linked-library scan of shipped image binaries
    (traust_engine._util.elf). The module is treated as a library name (e.g.
    'openssl' matches '#include <openssl/…>' and 'libssl/libcrypto' via
    the packages list)."""

    name = "c"

    def analyze(
        self,
        clone_path: Path,
        repo_id: str,
        evidence: RepoEvidence,
        ctx: AnalysisContext,
    ) -> list[str]:
        tiers_run: list[str] = []
        lib = ctx.module.rpartition("/")[2]  # tolerate repo-style module ids

        try:
            result = subprocess.run(
                [
                    "rg",
                    "-l",
                    "--max-count",
                    "1",
                    rf"#\s*include\s*[<\"]{re.escape(lib)}[/.]",
                    "-g",
                    "*.c",
                    "-g",
                    "*.h",
                    "-g",
                    "*.cc",
                    "-g",
                    "*.cpp",
                    "-g",
                    "*.hpp",
                    str(clone_path),
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )
            tiers_run.append("source_import_scan")
            evidence.source_import_scan = (
                "imports_found" if result.stdout.strip() else "imports_not_found"
            )
        except (subprocess.SubprocessError, OSError, FileNotFoundError):
            pass

        if self._linked_library_scan(repo_id, lib, evidence, ctx):
            tiers_run.append("elf_linked_library_scan")

        evidence.evidence_level = (
            "symbol-usage"
            if evidence.binary_symbol_scan == "symbols_present"
            else (
                "binary"
                if evidence.binary_linked_library
                else ("manifest" if evidence.source_import_scan else "none")
            )
        )

        # joern C tier: only when the library is plausibly present
        # (includes found or linked) and the advisory names symbols —
        # exact-name matching needs them; a bare library name would
        # over-match short C identifiers
        if (
            (
                evidence.source_import_scan == "imports_found"
                or evidence.binary_linked_library == "linked"
            )
            and (ctx.symbols or [])
            and _run_joern_tier(clone_path, evidence, ctx, "c")
        ):
            tiers_run.append("joern_reachability")
        return tiers_run

    def _linked_library_scan(
        self, repo_id: str, lib: str, evidence: RepoEvidence, ctx: AnalysisContext
    ) -> bool:
        try:
            con = sqlite3.connect(f"file:{ctx.db_path}?mode=ro", uri=True, check_same_thread=False)
            try:
                images = con.execute(
                    """
                    SELECT DISTINCT n.label FROM edges e
                    JOIN nodes n ON n.id = e.src
                    WHERE e.rel = 'built_from' AND e.dst = ?
                      AND n.kind = 'image'
                """,
                    (repo_id,),
                ).fetchall()
            finally:
                con.close()
        except sqlite3.Error:
            return False
        if not images:
            return False

        lib_names = {lib, *(p.rpartition("/")[2] for p in ctx.packages or [])}
        scanned = False
        for (image_ref,) in images:
            binary_path = GoAnalyzer._resolve_image_binary(image_ref, ctx.results_loc)
            if not binary_path:
                continue
            scanned = True
            try:
                needed = ElfAnalyzer(binary_path).linked_libraries()
            except Exception:
                continue
            for so in needed:
                if any(f"lib{n}" in so.name or n in so.name for n in lib_names):
                    evidence.binary_linked_library = "linked"
                    # linked → check whether the vulnerable SYMBOLS are
                    # referenced (.dynstr names appear as strings in the
                    # binary) — imports of the vulnerable function are a
                    # tier above "links the library"
                    self._symbol_name_scan(binary_path, evidence, ctx)
                    return True
        if scanned:
            evidence.binary_linked_library = "not_linked"
        return scanned

    @staticmethod
    def _symbol_name_scan(binary_path: Path, evidence: RepoEvidence, ctx: AnalysisContext) -> None:
        symbols = [s for s in (ctx.symbols or []) if s]
        if not symbols:
            return
        patterns = [(f"sym:{s}", re.compile(re.escape(s.encode("ascii")))) for s in symbols]
        try:
            matches = ElfAnalyzer(binary_path).scan_strings(patterns)
        except Exception:
            return
        evidence.binary_symbol_scan = "symbols_present" if matches else "symbols_absent"


class SurfaceAnalyzer(LanguageAnalyzer):
    """Manifest-surface ecosystems (GitHub Actions, Docker base images,
    Helm charts). These dependency SURFACES have no package-manifest
    language, no lockfile ecosystem, and no call-graph reachability tool,
    so there is nothing to deep-scan the way govulncheck/joern scan Go/
    Java. Affectedness rests entirely on the graph blast-radius plus a
    manifest-level re-check of the clone: is the vulnerable action / base
    image / chart declared in the relevant manifest(s), and — when a range
    is given — is the declared version in range.

    The re-check reuses the graph builder's own parsers via
    manifest_parsers.parser_for_path (parse_github_workflow for
    .github/workflows/*.y{,a}ml, parse_dockerfile for Dockerfile*, and
    parse_helm_chart for Chart.yaml / requirements.yaml), so the presence
    check here matches exactly what put the depends_on edge in the graph.

    Ceiling is likely_affected: a manifest edge is graph-dependency
    evidence, never reachability, so these surfaces can never reach
    `affected`. Results are mapped onto the existing manifest_scan evidence
    states so classify() needs no new branch:
        present, in range (or unparseable range) -> module_pinned_in_range
                                                     -> likely_affected
        present, out of range -> module_pinned_out_of_range
                                  -> version_not_in_range
        absent from present manifests -> module_not_in_manifests
                                         -> not_observed
        no manifests / clone failure -> no_manifests_found -> inconclusive
    """

    def __init__(self, ecosystem: str):
        self._ecosystem = ecosystem

    @property
    def name(self) -> str:
        return self._ecosystem

    def analyze(
        self,
        clone_path: Path,
        repo_id: str,
        evidence: RepoEvidence,
        ctx: AnalysisContext,
    ) -> list[str]:
        tiers_run: list[str] = []
        names = {n.lower() for n in [ctx.module, *(ctx.packages or [])] if n}
        globs = MP.PATH_GLOB_ECOSYSTEMS.get(self._ecosystem, [])

        pins: dict[str, str] = {}
        saw_manifest = False
        for glob in globs:
            for mf in sorted(clone_path.glob(glob)):
                if any(p in ("vendor", "node_modules", ".git") for p in mf.parts):
                    continue
                if not mf.is_file():
                    continue
                parsed = MP.parser_for_path(str(mf))
                if not parsed or parsed[0] != self._ecosystem:
                    continue
                saw_manifest = True
                try:
                    text = mf.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                _declared, deps = parsed[1](text)
                for dep_name, ver, _indirect in deps:
                    if dep_name.lower() in names:
                        pins[dep_name] = ver

        if saw_manifest:
            tiers_run.append("manifest_scan")
            if pins:
                ver = next(iter(pins.values()))
                evidence.manifest_version = ver
                in_range = ctx.in_range(ver)
                evidence.manifest_scan = (
                    "module_pinned_out_of_range" if in_range is False else "module_pinned_in_range"
                )
            else:
                evidence.manifest_scan = "module_not_in_manifests"
            evidence.evidence_level = "manifest"
        else:
            evidence.manifest_scan = "no_manifests_found"
            evidence.evidence_level = "none"

        evidence.notes = (evidence.notes or "") + (
            f"; {self._ecosystem} surface: graph-dependency edge; manifest-level, no reachability"
        )
        return tiers_run


ANALYZERS: dict[str, type[LanguageAnalyzer]] = {
    "go": GoAnalyzer,
    "python": PythonAnalyzer,
    "rust": RustAnalyzer,
    "javascript": JavaScriptAnalyzer,
    "java": JavaAnalyzer,
    "ruby": RubyAnalyzer,
    "nuget": NuGetAnalyzer,
    "c": CAnalyzer,
}


# Advisory --ecosystem -> analyzer. Keyed by the CLI ecosystem name (the
# ecosystem the advisory was raised against), NOT by detect_language's
# single-language guess. This is what makes analysis per-ecosystem: a Go
# module that also ships a JS UI subdir, analyzed with --ecosystem npm,
# runs the JavaScript analyzer (whose rglob finds web/ui/react-app/
# package.json) instead of being misrouted to GoAnalyzer by go.mod-wins
# language precedence. The blast-radius seed is already per-ecosystem
# (see blast_radius_seed), so the analyzer must be too.
ECOSYSTEM_ANALYZERS: dict[str, type[LanguageAnalyzer]] = {
    "go": GoAnalyzer,
    "npm": JavaScriptAnalyzer,
    "pypi": PythonAnalyzer,
    "cargo": RustAnalyzer,
    "maven": JavaAnalyzer,
    "ruby": RubyAnalyzer,
    "nuget": NuGetAnalyzer,
}


def analyzer_for_ecosystem(ecosystem: str) -> LanguageAnalyzer:
    """Return the analyzer instance for a specific --ecosystem.

    actions/docker/helm map to a SurfaceAnalyzer bound to that surface;
    every other ecosystem maps through ECOSYSTEM_ANALYZERS. The CLI
    `choices` list constrains the input, so a valid --ecosystem always
    resolves; an unrecognized ecosystem raises KeyError (fail-loud, never
    a silent wrong-analyzer dispatch)."""
    if ecosystem in SURFACE_ECOSYSTEMS:
        return SurfaceAnalyzer(ecosystem)
    return ECOSYSTEM_ANALYZERS[ecosystem]()


# --------------------------------------------------------------- classify


def classify(evidence: RepoEvidence, ecosystem: str = "go") -> str:
    """Classify one repo from its accumulated evidence.

    The L4 package-import tier is Go-only evidence of absence: an
    unimported Go package is not compiled into the binary. In a manifest
    ecosystem (PyPI, npm, ...) an installed dependency is loaded by other
    libraries without a first-party import (urllib3 decodes `br` through
    whatever `brotli` is installed), so there a missing import never
    demotes, and an observed import counts as source-import evidence.
    """
    go_import_tier = ecosystem == "go"
    if evidence.l1_version_in_range is False:
        return "version_not_in_range"
    if evidence.govulncheck == "symbol_reachable":
        return "affected"
    # Java analogue (joern call-site tier): a resolved first-party call
    # to the vulnerable symbol itself promotes to affected. The tier is
    # promotion-only — no joern state ever demotes (DI/reflection hide
    # edges from static analysis).
    if evidence.joern_reachability == "vulnerable_symbol_called":
        return "affected"

    has_feature_match = (evidence.feature_pattern_matches or 0) > 0
    govulncheck_negative = evidence.govulncheck in (
        "package_imported_not_observed",
        "module_required_not_observed",
    )

    if has_feature_match:
        return "likely_affected" if govulncheck_negative else "affected"

    if govulncheck_negative:
        return "not_observed"
    if evidence.binary_string_scan == "package_path_absent":
        return "not_observed"
    if go_import_tier and evidence.l4_package_imported is False:
        return "not_observed"

    if (
        evidence.binary_string_scan == "package_path_present"
        and evidence.l4_package_imported is not False
    ):
        return "likely_affected"

    if go_import_tier and evidence.l4_package_imported is True:
        if evidence.govulncheck is None and evidence.feature_pattern_matches is None:
            return "likely_affected"
        return "not_observed"

    # Manifest-level ecosystems (no reachability tooling): evidence can
    # confirm presence/version of the dependency, never symbol
    # reachability — the ceiling is likely_affected.
    if evidence.symbol_usage_scan == "symbols_used":
        return "likely_affected"  # vulnerable API textually used
    if evidence.manifest_scan == "module_pinned_out_of_range":
        return "version_not_in_range"
    if evidence.manifest_scan == "module_pinned_in_range":
        return "likely_affected"
    if evidence.binary_linked_library == "linked":
        return "likely_affected"
    imported = evidence.source_import_scan == "imports_found" or (
        not go_import_tier and evidence.l4_package_imported is True
    )
    if evidence.manifest_scan == "module_not_in_manifests" and not imported:
        return "not_observed"
    if evidence.binary_linked_library == "not_linked" and not imported:
        return "not_observed"
    if imported:
        return "likely_affected"

    return "inconclusive"


# -------------------------------------------------------------- helpers


def harness_version() -> str:
    return engine_harness_version()


def repo_url_from_id(repo_id: str) -> str | None:
    if repo_id.startswith("repo:"):
        return f"https://{repo_id[5:]}"
    return None


def repo_slug_from_id(repo_id: str) -> str:
    path = repo_id.removeprefix("repo:").removeprefix("github.com/")
    return re.sub(r"[^a-zA-Z0-9_-]", "-", path).strip("-")


def blast_radius_seed(module: str, ecosystem: str) -> str:
    """Portfolio-graph node id to seed the blast-radius query from.

    Go keeps the `module:<path>` shape (byte-identical to the legacy bare-
    module call, which q_blast_radius wraps to the same node id). Every
    other ecosystem addresses the package node directly as
    `pkg:<ecosystem>/<name>`, which is what unblocks non-Go analyzers at
    fleet scale: with non-Go edges in the graph, a non-Go --module now
    returns a real requiring-repos set instead of an empty one.
    """
    if ecosystem == "go":
        return f"module:{module}"
    return f"pkg:{ecosystem}/{module}"


def query_products(con: sqlite3.Connection, repo_id: str) -> list[str]:
    rows = con.execute(
        """
        SELECT DISTINCT p.label FROM edges ship
        JOIN nodes p ON p.id = ship.src
        WHERE ship.dst = ? AND ship.rel IN ('ships','contains','includes')
    """,
        (repo_id,),
    ).fetchall()
    return sorted(r[0] for r in rows)


def detect_language(clone_path: Path) -> str | None:
    """Detect primary language from manifest files."""
    if (clone_path / "go.mod").exists():
        return "go"
    if (clone_path / "Cargo.toml").exists():
        return "rust"
    if (clone_path / "pom.xml").exists() or (clone_path / "build.gradle").exists():
        return "java"
    if (clone_path / "package.json").exists():
        return "javascript"
    if (clone_path / "requirements.txt").exists() or (clone_path / "pyproject.toml").exists():
        return "python"
    # C/C++: no manifest ecosystem — detect via build system + sources
    if any(
        (clone_path / f).exists()
        for f in ("CMakeLists.txt", "configure.ac", "configure", "meson.build", "Makefile")
    ):
        try:
            for p in clone_path.iterdir():
                if p.suffix in (".c", ".cc", ".cpp", ".h"):
                    return "c"
            for sub in ("src", "lib", "source"):
                d = clone_path / sub
                if d.is_dir() and any(p.suffix in (".c", ".cc", ".cpp", ".h") for p in d.iterdir()):
                    return "c"
        except OSError:
            pass
    # Ruby / C#(.NET) come AFTER the established checks so a polyglot repo
    # keeps its current classification (e.g. a Go repo with a bundled
    # Gemfile still resolves to 'go').
    if (
        (clone_path / "Gemfile").exists()
        or (clone_path / "Gemfile.lock").exists()
        or any(clone_path.glob("*.gemspec"))
    ):
        return "ruby"
    if (
        (clone_path / "packages.config").exists()
        or (clone_path / "packages.lock.json").exists()
        or any(clone_path.glob("*.csproj"))
        or any(clone_path.glob("*.sln"))
    ):
        return "nuget"
    return None


def _results_dir(results_loc: str | None = None) -> Path | None:
    """A LOCAL path for the results location, or None when unconfigured.

    Resolves `ANALYSIS_RESULTS_URI` / `ANALYSIS_RESULTS_DIR` through
    traust_engine.storage, so an object-store location is materialized to
    the local cache and every call site below keeps working with a Path.

    config types this `Path | None` on purpose — it is set by the consumer
    (harness, CI, tests) and there is no defensible default, since guessing
    would write a stray tree into whatever directory the caller happened to
    stand in. Every use site therefore has to handle None.

    It did not. `ANALYSIS_RESULTS_DIR / "graph" / "sboms"` raised TypeError
    on an unconfigured environment, `analyze_repo`'s executor caught it
    per-repo, and the repo fell through to `inconclusive` with no signal
    that a whole evidence tier had failed rather than found nothing.
    Measured 2026-08-26: a 265-advisory sweep produced 5,710 changed
    classifications that way, 743 of them dropping out of `affected` — a
    result indistinguishable from a real finding at a glance.

    When ``results_loc`` is injected (via ``AnalysisContext`` from
    ``HarnessEngine.impact``), config is not re-read.
    """
    from traust_engine import storage

    if results_loc is None:
        return None
    try:
        return storage.localize(results_loc)
    except storage.StorageError as e:
        # A misconfigured or unreachable remote must not masquerade as
        # "this tier found nothing" — that is the exact failure this
        # function was added to stop. Say so, then skip honestly.
        print(f"  results location unusable ({e}) — SBOM/image tiers skipped", file=sys.stderr)
        return None


def sbom_cross_check(repo_id: str, evidence: RepoEvidence, ctx: AnalysisContext) -> bool:
    """Cross-check the SHIPPED artifact: syft SBOMs persisted by
    /secure-container-audit (analysis-results/graph/sboms/<digest>.cdx.json)
    say what the delivered image actually contains — a lockfile says only
    what the build intended. Evidence, never a verdict on its own."""
    results = _results_dir(ctx.results_loc)
    if results is None:
        # Skip honestly rather than crash: record WHY the tier did not run,
        # so a reader can tell "no SBOM matched" from "SBOMs were never
        # consulted". Silent absence is what made this bug expensive.
        evidence.sbom_scan = "skipped: ANALYSIS_RESULTS_DIR unset"
        return False
    sbom_dir = results / "graph" / "sboms"
    if not sbom_dir.is_dir():
        evidence.sbom_scan = "skipped: no SBOM directory"
        return False
    try:
        con = sqlite3.connect(f"file:{ctx.db_path}?mode=ro", uri=True, check_same_thread=False)
        try:
            images = con.execute(
                """
                SELECT DISTINCT n.label FROM edges e
                JOIN nodes n ON n.id = e.src
                WHERE e.rel = 'built_from' AND e.dst = ?
                  AND n.kind = 'image'
            """,
                (repo_id,),
            ).fetchall()
        finally:
            con.close()
    except sqlite3.Error:
        return False

    module_l = ctx.module.lower()
    checked = False
    for (image_ref,) in images:
        if "@sha256:" not in image_ref:
            continue
        digest = image_ref.rsplit("@sha256:", 1)[1]
        candidates = list(sbom_dir.glob(f"{digest[:7]}*.cdx.json"))
        for sbom_file in candidates:
            try:
                sbom = json.loads(sbom_file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            checked = True
            for comp in sbom.get("components") or []:
                name = (comp.get("name") or "").lower()
                purl = (comp.get("purl") or "").lower()
                if module_l == name or module_l in purl:
                    ver = comp.get("version") or ""
                    evidence.sbom_shipped_version = ver
                    in_range = ctx.in_range(ver)
                    evidence.sbom_scan = (
                        "shipped_out_of_range" if in_range is False else "shipped_in_range"
                    )
                    return True
    if checked:
        evidence.sbom_scan = "module_not_in_sbom"
    return checked


# ----------------------------------------- clone + analyze one repo


def analyze_repo(
    repo_id: str,
    repo_url: str,
    ctx: AnalysisContext,
    evidence: RepoEvidence | None = None,
) -> dict:
    """Clone, detect language, run the right analyzer, classify."""
    slug = repo_slug_from_id(repo_id)
    tmpdir = Path(tempfile.mkdtemp(prefix=f"impact-{slug}-"))
    if evidence is None:
        evidence = RepoEvidence()

    try:
        proc = subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", repo_url, str(tmpdir / "repo")],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if proc.returncode != 0:
            evidence.notes = f"clone failed: {proc.stderr.strip()[:200]}"
            return {
                "evidence": evidence,
                "classification": "inconclusive",
                "tiers_run": [],
            }

        clone = tmpdir / "repo"
        tiers_run: list[str] = []

        if ctx.ecosystem != "go":
            # Per-ecosystem dispatch: a specific non-Go --ecosystem forces the
            # matching analyzer regardless of detect_language. detect_language
            # is single-language with go.mod-wins precedence, so a polyglot Go
            # module that ALSO ships a JS UI subdir would be routed to
            # GoAnalyzer and its package.json never scanned (the observed
            # openshift/prometheus + stolostron/prometheus false-negative on
            # MAL-2026-4136). The advisory's ecosystem — not a heuristic
            # language guess — decides the analyzer. This also subsumes the
            # manifest-surface ecosystems (actions/docker/helm), which
            # detect_language could never return and which resolve to a
            # SurfaceAnalyzer via analyzer_for_ecosystem.
            tiers_run = analyzer_for_ecosystem(ctx.ecosystem).analyze(clone, repo_id, evidence, ctx)
        else:
            # Legacy path — default/unspecified ecosystem 'go'. Byte-identical
            # to the pre-fix behavior: a Go repo detects 'go' and runs
            # GoAnalyzer, exactly as the ecosystem map would route it, while
            # detect_language's notes for a non-Go or undetectable repo are
            # preserved unchanged.
            lang = detect_language(clone)
            if lang and lang in ANALYZERS:
                analyzer = ANALYZERS[lang]()
                tiers_run = analyzer.analyze(clone, repo_id, evidence, ctx)
            elif lang:
                evidence.notes = f"no analyzer for {lang} yet"
            else:
                evidence.notes = "language not detected"

        if sbom_cross_check(repo_id, evidence, ctx):
            tiers_run.append("sbom_cross_check")

        return {
            "evidence": evidence,
            "classification": classify(evidence, ctx.ecosystem),
            "tiers_run": tiers_run,
        }
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ------------------------------------------------------------------ main


@dataclass
class ImpactParams:
    cve: str
    module: str
    ecosystem: str = "go"
    advisory: ResolvedAdvisory | None = None
    symbols: str = ""
    packages: str = ""
    feature_desc: str | None = None
    out: str | None = None
    jobs: int = 4
    skip_scan: bool = False


def _execute(params: ImpactParams, db_path: Path, results_loc: str | None = None) -> int:
    advisory = params.advisory
    if advisory is None:
        raise ValueError("impact analysis needs the fetched advisory record (advisory.resolve)")
    vuln_symbols = [s.strip() for s in params.symbols.split(",") if s.strip()]
    vuln_packages = [p.strip() for p in params.packages.split(",") if p.strip()]
    out_path = (
        Path(params.out) if params.out else Path(f"{params.cve.lower()}-impact-analysis.json")
    )

    con = db_connect(db_path)

    ctx = AnalysisContext(
        cve=params.cve,
        module=params.module,
        packages=vuln_packages,
        symbols=vuln_symbols,
        vulnerable_range=advisory.vulnerable_range,
        fixed_version=advisory.fixed_version,
        feature_desc=params.feature_desc,
        db_path=db_path,
        con=con,
        ecosystem=params.ecosystem,
        results_loc=results_loc,
        advisory=advisory,
    )

    # --- Blast radius from portfolio graph
    print(f"Querying blast radius for {params.module}...")
    seed = blast_radius_seed(params.module, params.ecosystem)
    blast = q_blast_radius(con, seed)
    product_surfaces = blast.get("product_surfaces", [])
    repos_raw = blast.get("requiring_repos", [])
    print(f"  {len(repos_raw)} repos depend on {params.module}")

    # --- L4 package imports (only if L4 data was built into the graph)
    l4_data: dict[str, list[str]] = {}
    has_l4_data = False
    if vuln_packages:
        try:
            has_l4_data = (
                con.execute("SELECT 1 FROM edges WHERE rel = 'imports_package' LIMIT 1").fetchone()
                is not None
            )
        except sqlite3.Error:
            has_l4_data = False

        if has_l4_data:
            print(f"Querying L4 imports for {len(vuln_packages)} package(s)...")
            for pkg in vuln_packages:
                result = q_imports_package(con, pkg)
                for entry in result.get("importing_repos", []):
                    l4_data.setdefault(entry["repo"], []).append(pkg)
            print(f"  {len(l4_data)} repos import vulnerable package(s)")
        else:
            print(
                "  L4 symbol data not present in graph — skipping package-import queries",
                file=sys.stderr,
            )

    # --- Classify each repo (graph-only pass first)
    tiers_executed: set[str] = {"L1"}
    if has_l4_data:
        tiers_executed.add("L4")

    repos_to_scan: list[tuple[str, str, str, RepoEvidence]] = []
    repos_result: list[dict] = []

    for entry in repos_raw:
        repo_id = entry["repo"]
        version = entry.get("version")
        indirect = entry.get("indirect", False)

        ev = RepoEvidence()
        ev.l1_version_in_range = ctx.in_range(version)

        if repo_id in l4_data:
            ev.l4_package_imported = True
            ev.l4_packages_found = l4_data[repo_id]
        elif has_l4_data:
            ev.l4_package_imported = False

        classification = classify(ev, params.ecosystem)
        products = query_products(con, repo_id)
        repo_url = repo_url_from_id(repo_id)

        repo_entry = {
            "repo": repo_id,
            "products": products,
            "classification": classification,
            "version": version,
            "direct": not indirect,
            "evidence": ev.to_dict(),
        }
        repos_result.append(repo_entry)

        if (
            not params.skip_scan
            and classification in ("likely_affected", "inconclusive")
            and repo_url
        ):
            slug = repo_slug_from_id(repo_id)
            repos_to_scan.append((repo_id, repo_url, slug, ev))

    # --- Deep scan phase: clone + language-specific analysis
    scan_errors: list[str] = []
    if repos_to_scan:
        print(f"Scanning {len(repos_to_scan)} repo(s) (likely_affected/inconclusive)...")
        with ThreadPoolExecutor(max_workers=params.jobs) as pool:
            futures = {
                pool.submit(analyze_repo, rid, url, ctx, ev): rid
                for rid, url, slug, ev in repos_to_scan
            }
            for future in as_completed(futures):
                rid = futures[future]
                try:
                    result = future.result()
                except Exception as exc:
                    print(f"  {rid}: error — {exc}", file=sys.stderr)
                    scan_errors.append(f"{rid}: {exc}")
                    continue

                for t in result.get("tiers_run", []):
                    tiers_executed.add(t)

                for repo_entry in repos_result:
                    if repo_entry["repo"] == rid:
                        repo_entry["evidence"] = result["evidence"].to_dict()
                        repo_entry["classification"] = result["classification"]
                        break
                print(f"  {rid}: {result['classification']}")

    con.close()

    # A scan tier that fails for EVERY repo is a broken run, not a finding.
    # Each failure was already caught per-repo and the repo fell through to
    # `inconclusive`, which is indistinguishable from "scanned and found
    # nothing" in the artifact. Measured 2026-08-26: an unset
    # ANALYSIS_RESULTS_DIR crashed sbom_cross_check on all 265 advisories of
    # a sweep, moving 743 repos out of `affected` and reporting ok=265,
    # failed=0. Refuse to write an artifact whose evidence is uniformly
    # absent for a reason that is not about the code being analysed.
    if repos_to_scan and len(scan_errors) == len(repos_to_scan):
        print(
            f"FATAL: every scanned repo ({len(scan_errors)}) raised during "
            f"analysis — this is an environment or code fault, not a result. "
            f"First: {scan_errors[0][:200]}",
            file=sys.stderr,
        )
        return 2

    # --- Emit artifact
    counts = Counter(r["classification"] for r in repos_result)
    in_range = sum(
        1
        for r in repos_result
        if r["classification"] not in ("version_not_in_range", "not_imported")
    )

    doc = {
        "metadata": {
            "cve": params.cve,
            "module": params.module,
            "ecosystem": params.ecosystem,
            "vulnerable_range": advisory.vulnerable_range,
            "fixed_version": advisory.fixed_version,
            "vulnerable_symbols": vuln_symbols,
            "vulnerable_packages": vuln_packages,
            "feature_description": params.feature_desc,
            "advisory_sources": list(advisory.sources),
            "portfolio_graph_db": str(db_path),
            "portfolio_graph_version": None,
            "harness_version": harness_version(),
            "generated_at": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tiers_executed": sorted(TIER_MAP.get(t, t) for t in tiers_executed),
            "options": {
                "govulncheck": "govulncheck_source" in tiers_executed,
                "binary_scan": "elf_string_scan" in tiers_executed,
                "sweep": False,
            },
        },
        "summary": {
            "repos_in_blast_radius": len(repos_result),
            "version_in_range": in_range,
            "affected": counts.get("affected", 0),
            "likely_affected": counts.get("likely_affected", 0),
            "not_observed": counts.get("not_observed", 0),
            "version_not_in_range": counts.get("version_not_in_range", 0),
            "not_imported": counts.get("not_imported", 0),
            "inconclusive": counts.get("inconclusive", 0),
            "product_surfaces": product_surfaces,
        },
        "repos": repos_result,
    }

    doc = emit_impact_analysis(doc)

    out_path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")

    print(f"\nWrote {out_path}")
    print(f"  {len(repos_result)} repos, {in_range} in vulnerable range")
    for cls in (
        "affected",
        "likely_affected",
        "not_observed",
        "version_not_in_range",
        "inconclusive",
    ):
        c = counts.get(cls, 0)
        if c:
            print(f"  {cls}: {c}")
    return 0
