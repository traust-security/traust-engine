"""Joern call-site reachability facts for JVM and C/C++ code — the
analogue of govulncheck's symbol tier in /impact-analysis.

Builds a code property graph of the repo's first-party sources
(joern-parse: javasrc2cpg for Java, c2cpg for C/C++) and reports every
call site whose resolved callee matches the vulnerable symbols
(Java `class#method`, C function names) or package prefixes under
investigation. Facts only — the wrapper never
classifies; /impact-analysis judges the output.

EVIDENCE ASYMMETRY (by design, stated in every artifact): a found call
path is PROMOTING evidence (first-party code demonstrably invokes the
vulnerable API — cite the site). An absent path is NEVER proof of
safety: Java dependency injection (Spring/CDI), reflection, and
MethodHandles hide edges from any static analyzer, Joern included. The
tier can upgrade a classification; it must never downgrade one.

Usage:
    traust adapters joern --repo DIR --out FILE \
        [--language java|c] \
        [--symbols 'com.foo.Bar#method' | 'EVP_EncryptUpdate' ...] \
        [--packages com.foo,com.bar] [--module group:artifact] \
        [--timeout 900] [--max-sites 200]

C symbol matching is exact-name (c2cpg methodFullName is the bare
function name; prefix matching on short C names would over-match).

Exit 0 always writes the artifact: status "ran", "skipped: <reason>"
(joern absent, no Java sources, no patterns derivable), or
"error: <reason>" (CPG build/query failure) — mirroring the
deterministic_steps convention so callers record honesty, not crashes.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from traust_contracts.models import AdapterResult, Location

from traust_engine.adapters._contract_bridge import (
    build_scan_result,
    map_severity,
    utc_now,
)

# Query script executed inside joern. TSV out (SITE/COUNT rows) so the
# Scala side needs no JSON library; Python parses and structures.
QUERY_SC = r"""
@main def exec(cpgFile: String, symbolsFile: String, outFile: String) = {
  importCpg(cpgFile)
  val patterns = scala.io.Source.fromFile(symbolsFile).getLines().filter(_.nonEmpty).toList
  val sb = new StringBuilder
  for (p <- patterns) {
    val exact = p.startsWith("=")
    val contains = p.startsWith("~")
    val q = if (exact || contains) p.drop(1) else p
    // Exact mode compares the CALLEE NAME, not the whole methodFullName.
    // c2cpg emits "<unresolvedNamespace>.ConsumeFieldMessage:<unresolvedSig>"
    // for C++ member calls and never qualifies with "::", so comparing the
    // whole string made every C++ member query fail by construction, while
    // still matching plain C where the name IS the whole prefix. Measured
    // 2026-08-14 on protobuf text_format.cc: 3325 calls, 0 matches.
    def calleeName(fn: String): String = {
      val base = fn.split(":").headOption.getOrElse(fn)
      base.split('.').lastOption.getOrElse(base)
    }
    val calls = (if (exact) cpg.call.filter(c => calleeName(c.methodFullName) == q)
                 else if (contains) cpg.call.filter(_.methodFullName.contains(q))
                 else cpg.call.filter(_.methodFullName.startsWith(q))).l
    for (c <- calls.take(500)) {
      val file = c.location.filename
      val line = Option(c.lineNumber).flatten.map(_.toString).getOrElse("-1")
      sb.append(List("SITE", p, file, line, c.method.fullName, c.methodFullName)
        .mkString("\t")).append("\n")
    }
    sb.append(List("COUNT", p, calls.size.toString).mkString("\t")).append("\n")
  }
  val w = new java.io.PrintWriter(outFile)
  w.write(sb.toString)
  w.close()
}
"""

_TEST_PATH = re.compile(r"(^|/)(src/test|tests?|testdata|it)(/|$)", re.I)

# joern-parse frontend, passed EXPLICITLY per --language. Never rely on
# auto-detection: for a Java tree it reports `language: JAVA` and invokes
# **jimple2cpg** (the BYTECODE frontend) whenever compiled artifacts are
# present, not javasrc2cpg.
_FRONTEND = {"java": "JAVASRC", "c": "NEWC"}

# Coordinate tokens that carry no package-identity information — they
# appear in half of all Maven artifact ids and would match any import.
_GENERIC_TOKENS = frozenset(
    {
        "core",
        "api",
        "apis",
        "starter",
        "common",
        "commons",
        "util",
        "utils",
        "client",
        "server",
        "impl",
        "lib",
        "libs",
        "java",
        "javax",
        "base",
        "bom",
        "parent",
        "all",
        "main",
        "runtime",
        "support",
        "extension",
        "extensions",
        "plugin",
        "plugins",
        "module",
        "modules",
        "spi",
        "sdk",
        "com",
        "org",
        "io",
        "net",
        "ch",
        "me",
    }
)
_IMPORT_RX = re.compile(r"^\s*import\s+(?:static\s+)?([\w.]+)\s*;", re.M)


def derive_packages_from_imports(repo: Path, module: str, max_files: int = 4000) -> list[dict]:
    """Package prefixes the repo ACTUALLY imports that plausibly belong to
    `module`, each with the file that evidences it."""
    group, _, artifact = module.partition(":")
    toks = {
        t.lower()
        for t in re.split(r"[.\-_]", group + "-" + artifact)
        if len(t) > 2 and t.lower() not in _GENERIC_TOKENS
    }
    if not toks:
        return []
    hits: dict[str, str] = {}
    score: dict[str, int] = {}
    scanned = 0
    for f in repo.rglob("*.java"):
        if scanned >= max_files:
            break
        scanned += 1
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _IMPORT_RX.finditer(text):
            fqn = m.group(1)
            parts = fqn.split(".")
            low = [p.lower() for p in parts]
            idxs = [i for i, p in enumerate(low) if p in toks]
            if not idxs:
                continue
            pkg = ".".join(parts[: max(idxs) + 1])
            if pkg.count(".") < 1:
                continue
            hits.setdefault(pkg, str(f.relative_to(repo)))
            score[pkg] = max(
                score.get(pkg, 0),
                len({p for p in low[: max(idxs) + 1]} & toks),
            )
    if not hits:
        return []
    best = max(score.values())
    out = []
    for pkg, ev in sorted(hits.items()):
        if score.get(pkg, 0) < best:
            continue
        if any(o != pkg and o.startswith(pkg + ".") and score.get(o, 0) >= best for o in hits):
            continue
        out.append(
            {
                "pattern": pkg + ".",
                "kind": "package",
                "source": f"import-derived:{pkg}",
                "evidence_file": ev,
                "tokens_matched": score.get(pkg, 0),
            }
        )
    return out[:12]


@dataclass
class PatternInput:
    symbols: list[str] | None = None
    packages: str = ""
    module: str | None = None
    language: str = "java"
    repo: Path | None = None


def patterns_from(inp: PatternInput) -> list[dict]:
    """Derive methodFullName patterns. Symbol patterns are strongest
    (the vulnerable method/function itself); package prefixes weaker
    (any call into the library's API); a bare Maven group is weakest
    (group id only approximates the package root — recorded as
    heuristic). A leading '=' marks an exact-match pattern for the
    query layer (used for C function names)."""
    pats: list[dict] = []
    for s in inp.symbols or []:
        if inp.language == "c":
            # c2cpg methodFullName is the bare function name — exact
            # match only; prefix matching on short C names over-matches
            pats.append({"pattern": "=" + s, "kind": "symbol", "source": s})
        elif "#" in s:
            cls, _, meth = s.partition("#")
            if "." in cls:
                pats.append({"pattern": f"{cls}.{meth}:", "kind": "symbol", "source": s})
            else:
                pats.append(
                    {
                        "pattern": f"~.{cls}.{meth}:",
                        "kind": "symbol",
                        "source": s,
                        "match": "contains (class not fully qualified)",
                    }
                )
        else:
            pats.append(
                {"pattern": s if s.endswith(".") else s + ".", "kind": "package", "source": s}
            )
    for p in inp.packages.split(",") if inp.packages else []:
        p = p.strip()
        if p:
            pats.append(
                {"pattern": p if p.endswith(".") else p + ".", "kind": "package", "source": p}
            )
    if not pats and inp.module:
        if inp.language == "java":
            with contextlib.suppress(OSError, AttributeError, TypeError):
                pats.extend(derive_packages_from_imports(inp.repo, inp.module))
        if not pats:
            group = inp.module.partition(":")[0]
            if "." in group:
                pats.append(
                    {
                        "pattern": group + ".",
                        "kind": "group-heuristic",
                        "source": inp.module,
                        "match": "group id only approximates the "
                        "package root; no matching import "
                        "found in the tree",
                    }
                )
    # de-dup, deterministic order
    seen, out = set(), []
    for p in pats:
        if p["pattern"] not in seen:
            seen.add(p["pattern"])
            out.append(p)
    return out


def emit(out: Path, doc: dict) -> None:
    doc.setdefault(
        "soundness",
        {
            "found_path": "promoting evidence — first-party code invokes the "
            "matched API; cite the call site",
            "absent_path": "NEVER proof of safety — Java DI/reflection hide "
            "edges from static analysis; this tier upgrades "
            "classifications, never downgrades them",
            "line_numbers": "APPROXIMATE — javasrc2cpg line attribution "
            "drifts on some constructs; the "
            "file + caller method are authoritative. Anyone "
            "citing a site must verify the exact line by "
            "reading the file (citation-gate discipline).",
        },
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
    print(f"joern-reachability: {doc['status']} → {out}")


def _run_joern_scan(
    repo: Path,
    *,
    symbols: list[str] | None,
    timeout: int,
    max_sites: int = 200,
    language: str = "java",
    packages: str = "",
    module: str = "",
) -> dict[str, Any]:
    """Run joern reachability scan and return artifact dict."""
    base: dict[str, Any] = {
        "tool": "joern",
        "repo": str(repo),
        "language": language,
        "module": module or None,
    }

    joern = shutil.which("joern")
    parse = shutil.which("joern-parse")
    if not (joern and parse):
        return {**base, "status": "skipped: joern not on PATH"}

    exts = ("*.java",) if language == "java" else ("*.c", "*.h", "*.cc", "*.cpp", "*.hpp")
    if not any(f for pat in exts for f in repo.rglob(pat)):
        return {**base, "status": f"skipped: no {language} sources"}

    pats = patterns_from(
        PatternInput(
            symbols=symbols or [],
            packages=packages,
            module=module or None,
            language=language,
            repo=repo,
        )
    )
    if not pats:
        return {**base, "status": "skipped: no symbol/package patterns derivable"}

    try:
        ver = subprocess.run(
            [joern, "--version"],
            capture_output=True,
            text=True,
            timeout=120,
            stdin=subprocess.DEVNULL,
        )
        m = re.search(r"\b(\d+\.\d+\.\d+)\b", (ver.stdout or "") + (ver.stderr or ""))
        base["version"] = m.group(1) if m else "unknown"
    except (subprocess.SubprocessError, OSError):
        base["version"] = "unknown"

    with tempfile.TemporaryDirectory(prefix="joern-reach-") as td:
        tdp = Path(td)
        cpg = tdp / "cpg.bin"
        frontend = _FRONTEND[language]
        base["frontend"] = frontend
        built = subprocess.run(
            [parse, str(repo), "--language", frontend, "--output", str(cpg)],
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            env={**os.environ, "JAVA_OPTS": os.environ.get("JOERN_JAVA_OPTS", "-Xmx8g")},
        )
        if built.returncode != 0 or not cpg.is_file():
            raw = (built.stderr or built.stdout).strip()
            return {
                **base,
                "status": "error: joern-parse failed",
                "detail_head": raw[:400],
                "detail": raw[-400:],
            }

        script = tdp / "query.sc"
        script.write_text(QUERY_SC, encoding="utf-8")
        symfile = tdp / "patterns.txt"
        symfile.write_text("\n".join(p["pattern"] for p in pats) + "\n", encoding="utf-8")
        tsv = tdp / "sites.tsv"
        q = subprocess.run(
            [
                joern,
                "--script",
                str(script),
                "--param",
                f"cpgFile={cpg}",
                "--param",
                f"symbolsFile={symfile}",
                "--param",
                f"outFile={tsv}",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            env={**os.environ, "JAVA_OPTS": os.environ.get("JOERN_JAVA_OPTS", "-Xmx8g")},
        )
        if q.returncode != 0 or not tsv.is_file():
            return {
                **base,
                "status": "error: joern query failed",
                "detail": (q.stderr or q.stdout).strip()[-400:],
            }

        by_pattern: dict[str, dict] = {
            p["pattern"]: {**p, "call_sites": [], "total_calls": 0} for p in pats
        }
        repo_prefix = str(repo.resolve()) + os.sep
        for row in tsv.read_text(encoding="utf-8").splitlines():
            parts = row.split("\t")
            if parts[0] == "COUNT" and len(parts) == 3:
                if parts[1] in by_pattern:
                    by_pattern[parts[1]]["total_calls"] = int(parts[2])
            elif parts[0] == "SITE" and len(parts) == 6:
                _, pat, fname, line, caller, callee = parts
                if pat not in by_pattern:
                    continue
                rel = fname[len(repo_prefix) :] if fname.startswith(repo_prefix) else fname
                sites = by_pattern[pat]["call_sites"]
                if len(sites) < max_sites:
                    sites.append(
                        {
                            "file": rel,
                            "line": int(line),
                            "caller": caller,
                            "callee": callee,
                            "test_path": bool(_TEST_PATH.search(rel)),
                        }
                    )

    targets = []
    for p in pats:
        entry = by_pattern[p["pattern"]]
        entry["call_sites"].sort(key=lambda s: (s["file"], s["line"]))
        nontest = [s for s in entry["call_sites"] if not s["test_path"]]
        capped = entry["total_calls"] > len(entry["call_sites"])
        targets.append(
            {
                "source": entry["source"],
                "kind": entry["kind"],
                "pattern": entry["pattern"],
                "referenced": bool(nontest),
                "referenced_test_only": bool(entry["call_sites"]) and not nontest,
                "total_calls": entry["total_calls"],
                "call_sites": entry["call_sites"],
                **({"sites_capped_at": max_sites} if capped else {}),
            }
        )

    return {**base, "status": "ran", "targets": targets}


def _targets_to_findings(targets: list[dict]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for target in targets:
        for site in target.get("call_sites", []):
            loc = (
                Location(
                    path=site["file"],
                    lines=str(site.get("line", "")),
                    description=site.get("caller", ""),
                )
                if Location is not None
                else {
                    "path": site["file"],
                    "lines": str(site.get("line", "")),
                    "description": site.get("caller", ""),
                }
            )
            findings.append(
                {
                    "id": f"joern/{target['pattern']}:{site['file']}:{site['line']}",
                    "title": f"Call to {target['source']} at {site['file']}",
                    "severity": map_severity("high" if target.get("referenced") else "medium"),
                    "locations": [loc],
                    "description": (
                        f"callee={site.get('callee')} "
                        f"pattern={target['pattern']} "
                        f"kind={target.get('kind')}"
                    ),
                    "category": target.get("kind", ""),
                }
            )
    return findings


def scan(
    repo: Path,
    symbols: list[str] | None = None,
    timeout: int = 1200,
) -> AdapterResult:
    """Run joern reachability scan and return typed scan result."""
    repo = repo.resolve()
    doc = _run_joern_scan(repo, symbols=symbols, timeout=timeout)
    if doc.get("status") != "ran":
        raise RuntimeError(doc.get("status", "joern scan failed"))

    return build_scan_result(
        str(repo),
        "joern",
        _targets_to_findings(doc.get("targets", [])),
        scanned_at=utc_now(),
        scanner_version=doc.get("version", ""),
    )
