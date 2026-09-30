"""safe_exec — validate and run target-derived commands without a shell.

Two jobs:

  1. VALIDATE an argv or a PoC-derived command string against a named
     profile (config/safe-exec-profiles.yaml — policy as data).
  2. RUN the validated command — single argv or an allowlisted pipeline —
     via subprocess chaining with a scrubbed environment. No shell is
     ever involved, so shell metacharacters have no interpreter.

Deny layers (validation order):
  raw-pattern denies (string form)   → substitution, expansion, /dev/tcp
  shell operators (string form)      → only `|` permitted, as a pipeline
  hard-deny binaries                 → never grantable by any profile
  shells                             → never grantable (pipelines are
                                       executed natively, no shell needed)
  profile allowlist                  → basename (or explicit ./path head)
  git hardening (when git is allowed)→ network subcommands denied;
                                       dangerous -c/--config-env keys denied
  curl hardening (when curl allowed) → vetted option walk; upload/local-read
                                       /local-write/proxy denied; http(s)
                                       only; optional host allowlist
  protected env assignments          → PATH/LD_PRELOAD/GIT_SSH_COMMAND/…
  recursion cap                      → safe_exec cannot re-enter itself

Modes: the library tells the truth unconditionally; enforcement policy
belongs to the caller. The CLI honors SAFE_EXEC_MODE=warn|enforce
(default enforce) — warn reports the verdict and exits 0 so batch lanes
can calibrate. SAFE_EXEC_DISABLED=<reason> bypasses `run` but shouts to
stderr and appends to a per-user 0700 bypass log — never silent, and
library callers (validate-findings adapters) do not honor it.

Usage:
  safe_exec.py check --profile validation-step -- oc get pods -A
  safe_exec.py check --profile validation-step --string 'oc get po | grep x'
  safe_exec.py run   --profile go-fuzz --timeout 900 -- make build
  safe_exec.py list-profiles
"""

from __future__ import annotations

import contextlib
import dataclasses
import ipaddress
import logging
import os
import re
import shlex
import socket
import subprocess
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any, Literal, get_args
from urllib.parse import urlsplit

from traust_contracts import SafeExecProfiles

_log = logging.getLogger(__name__)
RECURSION_ENV = "SAFE_EXEC_DEPTH"
MAX_RECURSION = 3
BYPASS_LOG_DIR = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
BYPASS_LOG = BYPASS_LOG_DIR / "traust-engine" / "safe-exec-bypass.log"

# ---------------------------------------------------------------------------
# Deny tables. HARD entries are never grantable: a profile that lists one
# is a configuration error, refused at load.
# ---------------------------------------------------------------------------

HARD_DENY_BINARIES = frozenset(
    {
        # privilege / system mutation
        "sudo",
        "su",
        "doas",
        "chown",
        "chgrp",
        "dd",
        "mkfs",
        "mount",
        "umount",
        "systemctl",
        "service",
        "crontab",
        "launchctl",
        "reboot",
        "shutdown",
        "insmod",
        "rmmod",
        "sysctl",
        # process/host tampering
        "kill",
        "pkill",
        "killall",
        "renice",
        "nohup",
        # raw network tools (profiles needing egress use scoped tools, not these)
        "nc",
        "ncat",
        "netcat",
        "socat",
        "telnet",
        "ssh",
        "scp",
        "sftp",
        "rsync",
        "ftp",
        "wget",
        # package managers (runtime installs are S7 territory, never build steps)
        "pip",
        "pip3",
        "dnf",
        "yum",
        "apt",
        "apt-get",
        "brew",
        "gem",
        "cargo-install",
    }
)

SHELLS = frozenset(
    {
        "sh",
        "bash",
        "zsh",
        "ksh",
        "dash",
        "fish",
        "csh",
        "tcsh",
    }
)

# Interpreters are deny-by-default but PROFILE-grantable (python-test
# legitimately runs python3/pytest). Shells are not.
INTERPRETERS = frozenset(
    {
        "python",
        "python2",
        "python3",
        "perl",
        "ruby",
        "node",
        "deno",
        "lua",
        "php",
        "awk",
        "gawk",
        "mawk",
        "xargs",
        "env",
        "eval",
        "exec",
        "command",
        "time",
        "timeout",
        "nice",
        "setsid",
        "script",
    }
)

GIT_NETWORK_SUBCOMMANDS = frozenset(
    {
        "push",
        "pull",
        "fetch",
        "clone",
        "remote",
        "submodule",
        "ls-remote",
    }
)

# Dangerous `git -c key=value` / `--config-env` keys: each is a code-exec
# or credential-theft primitive. Matched case-insensitively; entries
# ending in "." are prefixes.
GIT_DANGEROUS_C_KEYS = (
    "core.pager",
    "core.editor",
    "core.sshcommand",
    "core.hookspath",
    "core.fsmonitor",
    "core.askpass",
    "core.alternateobjectdirectories",
    "credential.",
    "filter.",
    "diff.external",
    "difftool.",
    "mergetool.",
    "merge.",
    "remote.",
    "http.proxy",
    "http.sslcainfo",
    "http.sslcert",
    "http.sslkey",
    "protocol.",
    "sendemail.",
    "alias.",
    "gpg.program",
    "ssh.variant",
    "uploadpack.",
    "sshcommand",
)

PROTECTED_ENV_VARS = frozenset(
    {
        "PATH",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "PERL5LIB",
        "NODE_OPTIONS",
        "RUBYOPT",
        "BASH_ENV",
        "ENV",
        "IFS",
        "SHELL",
        "GIT_SSH",
        "GIT_SSH_COMMAND",
        "GIT_PROXY_COMMAND",
        "GIT_EXTERNAL_DIFF",
        "GIT_PAGER",
        "GIT_ASKPASS",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "JAVA_TOOL_OPTIONS",
        "MAVEN_OPTS",
        "GRADLE_OPTS",
        "_JAVA_OPTIONS",
        "SAFE_EXEC_MODE",
        "SAFE_EXEC_DISABLED",
        RECURSION_ENV,
    }
)

# Raw denies applied to STRING-form commands before tokenization.
RAW_DENY_PATTERNS = (
    (re.compile(r"`"), "backtick command substitution"),
    (re.compile(r"\$\("), "command substitution $( )"),
    (re.compile(r"\$\{"), "parameter expansion ${ }"),
    (re.compile(r"[<>]\("), "process substitution"),
    (re.compile(r"\$'"), "ANSI-C quoting"),
    (re.compile(r"/dev/(tcp|udp)/"), "raw socket via /dev/tcp|udp"),
    # NB: no newline deny — nothing here ever reaches a shell, so a
    # quoted newline is printf data and an unquoted one is whitespace;
    # either way every resulting token passes the vetting below.
)

# Environment kept when run() scrubs (plus profile keep_env).
BASE_KEEP_ENV = (
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "TMPDIR",
    "TERM",
    "http_proxy",
    "https_proxy",
    "no_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
)

_ENV_PREFIX_RX = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.S)


Posture = Literal["restricted", "baseline", "privileged"]
POSTURES: tuple[Posture, ...] = get_args(Posture)

POSTURE_ALIASES: dict[str, Posture] = {
    "restricted": "restricted",
    "baseline": "baseline",
    "privileged": "privileged",
    "high": "restricted",
    "medium": "baseline",
    "low": "privileged",
}


@dataclasses.dataclass(frozen=True)
class Profile:
    name: str
    description: str
    allow: frozenset[str]
    allowed_path_heads: frozenset[str]
    allow_pipelines: bool
    keep_env: tuple[str, ...]
    # segment heads that receive keep_env/extra_env; empty = all segments
    keep_env_heads: tuple[str, ...] = ()
    # hostnames curl may contact; empty = see posture
    curl_allowed_hosts: tuple[str, ...] = ()
    # posture: restricted (fail closed), baseline (public only), privileged (fail open)
    posture: Posture = "privileged"

    def permits(self, head: str) -> bool:
        return head in (self.allowed_path_heads if "/" in head else self.allow)


@dataclasses.dataclass(frozen=True)
class Verdict:
    ok: bool
    reason: str = ""
    # tokenized pipeline segments (only for string-form validation)
    segments: tuple = ()


# Embedded fallback so library consumers (validate-findings adapters)
# keep functioning if the config file is absent in a stripped checkout.
# The YAML file is authoritative; keep this entry in sync with it
# (tests/test_safe_exec.py::test_fallback_matches_config enforces).
_FALLBACK_PROFILES = {
    "validation-step": Profile(
        name="validation-step",
        description="embedded fallback — see config/safe-exec-profiles.yaml",
        allow=frozenset(
            {
                "curl",
                "oc",
                "kubectl",
                "jq",
                "grep",
                "base64",
                "head",
                "tail",
                "tr",
                "wc",
                "cat",
                "sleep",
                "echo",
                "printf",
            }
        ),
        allowed_path_heads=frozenset(),
        allow_pipelines=True,
        # VF_OAUTH_TOKEN kept for probe soundness (F15) — lab-scoped,
        # short-TTL; see config/safe-exec-profiles.yaml
        keep_env=("KUBECONFIG", "VF_OAUTH_TOKEN"),
        keep_env_heads=("curl", "oc", "kubectl"),
        posture="privileged",
    ),
}


_BASELINE_DENIED_SUFFIXES = (
    ".local",
    ".internal",
    ".lan",
    ".home.arpa",
    ".cluster.local",
    ".localhost",
    ".svc",
)
_BASELINE_DENIED_NAMES = frozenset({"localhost", "instance-data", "metadata"})


def _parse_ip(literal: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse standard or libc-compatible IPv4/IPv6 address literals."""
    with contextlib.suppress(ValueError):
        return ipaddress.ip_address(literal)
    with contextlib.suppress(OSError, ValueError):
        return ipaddress.ip_address(socket.inet_ntoa(socket.inet_aton(literal)))
    return None


def _is_baseline_denied_host(host: str) -> str | None:
    """Check whether a normalized hostname/IP is denied under the 'baseline' posture."""
    lowered = host.lower().rstrip(".")
    literal = lowered.removeprefix("[").removesuffix("]")
    if (ip := _parse_ip(literal)) and not ip.is_global:
        return (
            f"curl host {host!r} is a non-global IP address ({ip}) — "
            "denied under posture 'baseline' (allowlist it explicitly in "
            "curl_allowed_hosts or call-site allowed_hosts)"
        )
    if ip:
        return None
    if lowered in _BASELINE_DENIED_NAMES:
        return (
            f"curl host {host!r} is a local/internal name — denied under posture "
            "'baseline' (allowlist it explicitly in curl_allowed_hosts or call-site allowed_hosts)"
        )
    if lowered.endswith(_BASELINE_DENIED_SUFFIXES):
        return (
            f"curl host {host!r} is in an internal domain — "
            "denied under posture 'baseline' (allowlist it explicitly in "
            "curl_allowed_hosts or call-site allowed_hosts)"
        )
    if "." not in lowered:
        return (
            f"curl host {host!r} is a single-label host (intranet/cluster service) — "
            "denied under posture 'baseline' (allowlist it explicitly in "
            "curl_allowed_hosts or call-site allowed_hosts)"
        )
    return None


def _norm_host(entry: object) -> str:
    """Normalize a host-allowlist entry to the bare lowercase hostname
    `urlsplit()` reports, so allowlist entries and URL operands are
    compared on identical terms. Unparseable entries normalize to ''."""
    h = str(entry).strip().split("://", 1)[-1]
    if h.count(":") > 1 and "[" not in h:  # bare IPv6 literal
        h = f"[{h}]"
    try:
        return (urlsplit(f"//{h}").hostname or "").rstrip(".")
    except ValueError:
        return ""


def _resolve_posture(value: str | None, default: Posture, context: str) -> Posture:
    if value is None:
        return default
    if value not in POSTURE_ALIASES:
        raise ValueError(
            f"{context} posture {value!r} is not one of "
            f"{list(POSTURE_ALIASES.keys())} — fix safe-exec-profiles.yaml"
        )
    return POSTURE_ALIASES[value]


def profiles_from_section(section: SafeExecProfiles) -> dict[str, Profile]:
    out = {}
    defaults: dict[str, Any] = getattr(section, "defaults", None) or {}
    default_posture = _resolve_posture(defaults.get("posture"), "privileged", "defaults")

    for name, spec in (section.profiles or {}).items():
        allow = frozenset(spec.get("allow") or [])
        if bad := sorted(allow & (HARD_DENY_BINARIES | SHELLS)):
            raise ValueError(
                f"profile {name!r} grants hard-denied binaries {bad} — "
                "hard denies are never grantable; fix "
                "safe-exec-profiles.yaml"
            )

        posture = _resolve_posture(spec.get("posture"), default_posture, f"profile {name!r}")

        raw_hosts = [str(x).strip() for x in spec.get("curl_allowed_hosts") or ()]
        globby = sorted(
            h
            for h in raw_hosts
            if any(c in h for c in "*?{}") or (("[" in h or "]" in h) and ":" not in _norm_host(h))
        )
        if globby:
            raise ValueError(
                f"profile {name!r} curl_allowed_hosts entries {globby} contain "
                "glob characters — the allowlist is exact-hostname only; fix "
                "safe-exec-profiles.yaml"
            )
        unparseable = sorted(h for h in raw_hosts if h and not _norm_host(h))
        if unparseable:
            raise ValueError(
                f"profile {name!r} curl_allowed_hosts entries {unparseable} do "
                "not normalize to a hostname — dropping them could disable "
                "host enforcement; fix safe-exec-profiles.yaml"
            )
        hosts = tuple(h for h in (_norm_host(x) for x in raw_hosts) if h)

        keep_env = tuple(spec.get("keep_env") or ())
        keep_env_heads = tuple(spec.get("keep_env_heads") or ())

        allow_pipelines = bool(spec.get("allow_pipelines", False))
        if posture == "restricted" and allow_pipelines and not keep_env_heads:
            raise ValueError(
                f"profile {name!r} has posture 'restricted' with pipelines enabled, "
                "but keep_env_heads is empty — keep_env_heads is required under restricted "
                "to prevent pipeline secret leakage; fix safe-exec-profiles.yaml"
            )

        out[name] = Profile(
            name=name,
            description=str(spec.get("description", "")),
            allow=allow,
            allowed_path_heads=frozenset(spec.get("allowed_path_heads") or []),
            allow_pipelines=allow_pipelines,
            keep_env=keep_env,
            keep_env_heads=keep_env_heads,
            curl_allowed_hosts=hosts,
            posture=posture,
        )
    return out


_profiles_from_section = profiles_from_section  # tests / legacy alias


_PROFILE_CACHE: dict | None = None


def bind_profiles(section: SafeExecProfiles | None) -> None:
    """Seed the module-global cache (tests and standalone CLI only).

    Engine callers should use ``ContextOps.safe_exec_profile_map()`` — it is
    scoped to one ``HarnessEngine`` instance and does not clobber other contexts
    in the same process.
    """
    global _PROFILE_CACHE
    if section is None:
        _PROFILE_CACHE = dict(_FALLBACK_PROFILES)
        return
    _PROFILE_CACHE = profiles_from_section(section)


def reset_profiles() -> None:
    """Clear the module-global cache (tests only)."""
    global _PROFILE_CACHE
    _PROFILE_CACHE = None


def profiles(*, profile_map: dict | None = None) -> dict:
    if profile_map is not None:
        return profile_map
    global _PROFILE_CACHE
    if _PROFILE_CACHE is None:
        _log.warning(
            "safe_exec profiles not bound — falling back to built-in profiles. "
            "This is a security-policy fallback: the operator's allowlists are "
            "NOT in effect. Pass profile_map= or bind via HarnessEngine."
        )
        _PROFILE_CACHE = dict(_FALLBACK_PROFILES)
    return _PROFILE_CACHE


def get_profile(name: str, *, profile_map: dict | None = None) -> Profile:
    p = profiles(profile_map=profile_map).get(name)
    if p is None:
        raise KeyError(
            f"unknown safe_exec profile {name!r}; "
            "known: {sorted(profiles(profile_map=profile_map))} "
            "(see safe-exec-profiles.yaml in $TRAUST_CONFIG_HOME)"
        )
    return p


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------


def _check_git_argv(argv: list) -> str:
    """Extra hardening when the head binary is git. Returns deny reason
    or ''."""
    i = 1
    subcommand = None
    while i < len(argv):
        tok = argv[i]
        if tok in ("-c", "--config-env"):
            if i + 1 < len(argv):
                key = argv[i + 1].split("=", 1)[0].strip().lower()
                for danger in GIT_DANGEROUS_C_KEYS:
                    if key == danger or (danger.endswith(".") and key.startswith(danger)):
                        return f"git config key {key!r} is a code-exec/credential primitive"
                i += 2
                continue
            return "dangling git -c"
        if tok == "-C":
            i += 2
            continue
        if tok.startswith("-"):
            i += 1
            continue
        subcommand = tok
        break
    if subcommand in GIT_NETWORK_SUBCOMMANDS:
        return (
            f"git network subcommand {subcommand!r} is denied under "
            "safe_exec (clones/fetches belong to S3-gated skill "
            "steps, not target-derived commands)"
        )
    return ""


_CURL_SHORT_BOOL = frozenset("sSvkiILfgGlMNRqVhjZa#012346")

_CurlValueKind = Literal["data", "urlencode", "header", "cookie", "writeout", "sink", "url"]

_CURL_VALUE_KIND: dict[str, _CurlValueKind | None] = {
    "-A": None,
    "--user-agent": None,
    "-e": None,
    "--referer": None,
    "-m": None,
    "--max-time": None,
    "-r": None,
    "--range": None,
    "-u": None,
    "--user": None,
    "-X": None,
    "--request": None,
    "-C": None,
    "--continue-at": None,
    "-Y": None,
    "--speed-limit": None,
    "-y": None,
    "--speed-time": None,
    "--connect-timeout": None,
    "--keepalive-time": None,
    "--retry": None,
    "--retry-delay": None,
    "--retry-max-time": None,
    "--max-redirs": None,
    "--max-filesize": None,
    "--limit-rate": None,
    "--oauth2-bearer": None,
    "--ciphers": None,
    "--tls-max": None,
    "--cacert": None,
    "--capath": None,
    "--pinnedpubkey": None,
    "--request-target": None,
    "--noproxy": None,
    "--aws-sigv4": None,
    # request bodies: the @file/@- upload leg is the exfil primitive;
    # inline bodies stay allowed (probes legitimately POST JSON)
    "-d": "data",
    "--data": "data",
    "--data-ascii": "data",
    "--data-binary": "data",
    "--data-raw": "data",
    "--json": "data",
    "--data-urlencode": "urlencode",
    "--url-query": "urlencode",
    "-H": "header",
    "--header": "header",
    "-b": "cookie",
    "--cookie": "cookie",
    "-w": "writeout",
    "--write-out": "writeout",
    # local-file sinks: only the no-op targets are allowed so the
    # validate-findings idiom `-s -o /dev/null -w '%{http_code}'` works
    "-o": "sink",
    "--output": "sink",
    "-D": "sink",
    "--dump-header": "sink",
    "-c": "sink",
    "--cookie-jar": "sink",
    "--trace": "sink",
    "--trace-ascii": "sink",
    "--stderr": "sink",
    "--url": "url",
}

_CURL_SHORT_VALUE = frozenset(k[1] for k in _CURL_VALUE_KIND if len(k) == 2)

_CURL_SHORT_DENY = {
    "E": "local key-material read",
    "F": "multipart upload (local-file read)",
    "K": "config-file read",
    "n": "netrc credential read",
    "O": "server-named local file write",
    "J": "server-named local file write",
    "P": "ftp active mode",
    "Q": "server-side (ftp) command",
    "T": "local-file upload",
    "U": "proxy credentials",
    "p": "proxy tunnel",
    "t": "telnet option",
    "x": "proxy redirection",
    "z": "local-file mtime read (If-Modified-Since oracle)",
}

_CURL_LONG_BOOL = frozenset(
    {
        "--silent",
        "--show-error",
        "--verbose",
        "--insecure",
        "--include",
        "--head",
        "--get",
        "--globoff",
        "--location",
        "--fail",
        "--fail-with-body",
        "--fail-early",
        "--compressed",
        "--raw",
        "--path-as-is",
        "--tcp-nodelay",
        "--ipv4",
        "--ipv6",
        "--http0.9",
        "--http1.0",
        "--http1.1",
        "--http2",
        "--http2-prior-knowledge",
        "--http3",
        "--http3-only",
        "--tlsv1",
        "--tlsv1.0",
        "--tlsv1.1",
        "--tlsv1.2",
        "--tlsv1.3",
        "--digest",
        "--basic",
        "--anyauth",
        "--ntlm",
        "--negotiate",
        "--retry-connrefused",
        "--retry-all-errors",
        "--progress-bar",
        "--disable",
        "--junk-session-cookies",
        "--parallel",
        "--next",
        "--trace-time",
        "--styled-output",
        "--buffer",
        "--keepalive",
        "--progress-meter",
        "--sessionid",
        "--alpn",
        "--npn",
        "--version",
        "--help",
        "--manual",
    }
)

_CURL_LONG_DENY = {
    "--upload-file": "local-file upload",
    "--form": "multipart upload (local-file read)",
    "--form-string": "multipart upload",
    "--config": "config-file read",
    "--netrc": "netrc credential read",
    "--netrc-file": "netrc credential read",
    "--netrc-optional": "netrc credential read",
    "--variable": "local file/stdin read into request variables",
    "--etag-compare": "local-file read",
    "--etag-save": "local file write",
    "--alt-svc": "local cache-file write",
    "--hsts": "local cache-file write",
    "--libcurl": "local file write",
    "--remote-name": "server-named local file write",
    "--remote-name-all": "server-named local file write",
    "--remote-header-name": "server-named local file write",
    "--output-dir": "local directory write",
    "--create-dirs": "local directory write",
    "--resolve": "connection redirection",
    "--connect-to": "connection redirection",
    "--unix-socket": "connection redirection",
    "--abstract-unix-socket": "connection redirection",
    "--interface": "connection redirection",
    "--location-trusted": "credential-forwarding redirects",
    "--proto": "protocol-allowlist override",
    "--proto-default": "protocol-allowlist override",
    "--proto-redir": "protocol-allowlist override",
    "--doh-url": "DNS resolution redirection",
    "--cert": "local key-material read",
    "--key": "local key-material read",
    "--quote": "server-side (ftp) command",
    "--telnet-option": "telnet option",
    "--time-cond": "local-file mtime read (If-Modified-Since oracle)",
}

_CURL_REDIRECT_SHORT = frozenset("L")
_CURL_REDIRECT_LONG = frozenset({"--location"})
_CURL_REDIRECT_WHY = "follows redirects off the enforced host allowlist"

_CURL_DENY_PREFIXES = (
    ("--proxy", "proxy redirection"),
    ("--socks", "proxy redirection"),
    ("--expand-", "curl variable expansion"),
    ("--ftp-", "ftp option"),
    ("--mail-", "smtp option"),
    ("--tftp-", "tftp option"),
)

_CURL_SINK_OK = frozenset({"-", "/dev/null", "/dev/stdout", "/dev/stderr"})

_SCHEME_RX = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*):")

_CURL_KNOWN_SCHEMES = frozenset(
    {
        "http",
        "https",
        "ftp",
        "ftps",
        "file",
        "dict",
        "gopher",
        "gophers",
        "imap",
        "imaps",
        "ldap",
        "ldaps",
        "mqtt",
        "pop3",
        "pop3s",
        "rtmp",
        "rtmpe",
        "rtmps",
        "rtmpt",
        "rtmpte",
        "rtmpts",
        "rtsp",
        "scp",
        "sftp",
        "smb",
        "smbs",
        "smtp",
        "smtps",
        "telnet",
        "tftp",
        "ws",
        "wss",
    }
)

_PORT_SHORTHAND_RX = re.compile(r"^\d+([/?#].*)?$")

_CURL_GUESSED_SCHEME_LABELS = frozenset({"ftp", "dict", "ldap", "imap", "smtp", "pop3"})


def _is_bracketed_ip(authority: str) -> bool:
    """True when `authority` is a bracketed IP literal with an optional
    `:port` — what curl takes as a host, as opposed to a `[1-9]`-style
    glob. `ipaddress` decides whether the literal is real."""
    if not authority.startswith("["):
        return False
    literal, closed, port = authority[1:].partition("]")
    if not closed or (port and not (port.startswith(":") and port[1:].isdigit())):
        return False
    try:
        ipaddress.ip_address(literal)
    except ValueError:
        return False
    return True


def _curl_deny(opt: str, why: str) -> str:
    return f"curl option {opt!r} is denied under safe_exec ({why})"


@dataclasses.dataclass(frozen=True)
class _CurlVetter:
    """Vets one curl argv against the tables above, returning the deny
    reason or '' so callers can shape their own Verdict. A non-empty
    `allowed_hosts` additionally pins every URL operand to those hostnames
    and denies redirect-following (which would leave the allowlist). When it
    is empty, `posture` decides."""

    allowed_hosts: tuple[str, ...] = ()
    posture: Posture = "privileged"

    def check_argv(self, argv: Sequence[str]) -> str:
        """Walk a curl argv the way curl's own option parser does: short-flag
        clusters with attached or following values, `--opt value`,
        `--opt=value`, and `--` end-of-options. Every option must be on the
        vetted tables above; unknown options are denied."""
        i = 1
        end_of_options = False
        while i < len(argv):
            tok = argv[i]
            i += 1
            if end_of_options or tok == "-" or not tok.startswith("-"):
                reason = self._check_url(tok)
                if reason:
                    return reason
                continue
            if tok == "--":
                end_of_options = True
                continue
            if tok.startswith("--"):
                opt, sep, attached = tok.partition("=")
                why = next((w for prefix, w in _CURL_DENY_PREFIXES if opt.startswith(prefix)), "")
                if why:
                    return _curl_deny(opt, why)
                if opt in _CURL_LONG_DENY:
                    return _curl_deny(opt, _CURL_LONG_DENY[opt])
                if (self.allowed_hosts or self.posture in ("restricted", "baseline")) and (
                    opt in _CURL_REDIRECT_LONG
                ):
                    return _curl_deny(opt, _CURL_REDIRECT_WHY)
                if opt in _CURL_LONG_BOOL:
                    continue
                if opt in _CURL_VALUE_KIND:
                    if sep:
                        val = attached
                    elif i < len(argv):
                        val = argv[i]
                        i += 1
                    else:
                        val = None
                    reason = self._check_value(opt, _CURL_VALUE_KIND[opt], val)
                    if reason:
                        return reason
                    continue
                if opt.startswith("--no-") and "--" + opt[5:] in _CURL_LONG_BOOL:
                    continue
                return _curl_deny(opt, "not on the vetted option table — denied by default")
            j = 1
            while j < len(tok):
                ch = tok[j]
                j += 1
                if ch in _CURL_SHORT_DENY:
                    return _curl_deny(f"-{ch}", _CURL_SHORT_DENY[ch])
                if (self.allowed_hosts or self.posture in ("restricted", "baseline")) and (
                    ch in _CURL_REDIRECT_SHORT
                ):
                    return _curl_deny(f"-{ch}", _CURL_REDIRECT_WHY)
                if ch in _CURL_SHORT_BOOL:
                    continue
                if ch in _CURL_SHORT_VALUE:
                    if j < len(tok):
                        val = tok[j:]
                    elif i < len(argv):
                        val = argv[i]
                        i += 1
                    else:
                        val = None
                    reason = self._check_value(f"-{ch}", _CURL_VALUE_KIND[f"-{ch}"], val)
                    if reason:
                        return reason
                    break
                return _curl_deny(f"-{ch}", "not on the vetted option table — denied by default")
        return ""

    def _check_url(self, tok: str) -> str:
        """Vet one curl URL operand: scheme always, hostname when enforced."""
        rest = tok
        schemeless = True
        m = _SCHEME_RX.match(tok)
        if m:
            scheme = m.group(1).lower()
            if scheme in ("http", "https"):
                rest = tok[m.end() :].lstrip("/")
                schemeless = False
            elif scheme not in _CURL_KNOWN_SCHEMES and _PORT_SHORTHAND_RX.match(tok[m.end() :]):
                pass  # host:port shorthand (e.g. api.lab:6443/healthz), not a scheme
            else:
                return f"curl URL scheme {scheme!r} is denied under safe_exec (only http/https)"
        authority = re.split(r"[/?#]", rest, maxsplit=1)[0]
        if ("{" in authority or "}" in authority) or (
            ("[" in authority or "]" in authority) and not _is_bracketed_ip(authority)
        ):
            return (
                "curl URL globbing in the scheme/host part is denied under "
                "safe_exec (glob-expanded scheme/host smuggling)"
            )
        if schemeless:
            label = authority.split(":", 1)[0].split(".", 1)[0].lower()
            if label in _CURL_GUESSED_SCHEME_LABELS:
                return (
                    f"curl URL {tok!r} is denied under safe_exec (no scheme — curl "
                    f"guesses {label}:// from the hostname prefix; only http/https)"
                )
        if not self.allowed_hosts:
            if self.posture == "restricted":
                return (
                    f"curl URL {tok!r} is denied under safe_exec — posture is 'restricted' "
                    "and no allowed hosts are in effect (list them in "
                    "curl_allowed_hosts or pass them at the call site)"
                )
            if self.posture == "privileged":
                return ""

        if "{" in tok or "}" in tok:
            return "curl URL globbing is denied under safe_exec when a host allowlist is enforced"
        try:
            parts = urlsplit("http://" + rest)
            host = parts.hostname
        except ValueError:
            return (
                f"unparseable curl URL {tok!r} is denied under safe_exec (host allowlist enforced)"
            )
        if parts.username is not None:
            return "curl URL userinfo (user@host) is denied under safe_exec (host-spoof)"
        if any("[" in part or "]" in part for part in (parts.path, parts.query, parts.fragment)):
            return "curl URL globbing is denied under safe_exec when a host allowlist is enforced"
        if not host:
            return f"curl URL {tok!r} has no hostname — denied under safe_exec (allowlist enforced)"

        norm = host.rstrip(".")
        if self.posture == "baseline":
            if norm not in self.allowed_hosts and (denied := _is_baseline_denied_host(norm)):
                return denied
            return ""

        if self.allowed_hosts and norm not in self.allowed_hosts:
            return (
                f"curl host {host!r} is not in the enforced allowlist {sorted(self.allowed_hosts)}"
            )
        return ""

    def _check_value(self, opt: str, kind: _CurlValueKind | None, val: str | None) -> str:
        if val is None:
            return f"curl option {opt!r} is missing its value and is denied under safe_exec"
        if kind == "data":
            if val.startswith("@"):
                return _curl_deny(opt, f"{opt} @<file>/@- upload — local-file exfiltration")
        elif kind == "urlencode":
            if re.match(r"^[^=]*@", val):
                return _curl_deny(opt, f"{opt} [name]@<file> upload — local-file exfiltration")
        elif kind == "header":
            if val.startswith("@"):
                return _curl_deny(opt, f"{opt} @<file> — header read from local file")
        elif kind == "cookie":
            if "=" not in val:
                return _curl_deny(opt, "cookie-file read — local-file exfiltration")
        elif kind == "writeout":
            if val.startswith("@"):
                return _curl_deny(opt, f"{opt} @<file> — format read from local file")
            if "%output{" in val:
                return _curl_deny(opt, "%output{} — local file write")
        elif kind == "sink":
            if val not in _CURL_SINK_OK:
                return _curl_deny(
                    opt, f"local file write sink {val!r} — only {sorted(_CURL_SINK_OK)}"
                )
        elif kind == "url":
            return self._check_url(val)
        return ""


# kube hardening (assessment 2026-07-31 live-F1/F2 defense-in-depth):
# cluster/credential override flags never belong in target-derived
# commands — the adapter supplies context and kubeconfig. The execute
# layer denies these too; this is the second fence.
KUBE_DENY_FLAGS = frozenset(
    {
        "--kubeconfig",
        "--context",
        "--cluster",
        "--user",
        "--server",
        "-s",
        "--token",
        "--as",
        "--as-group",
        "--as-uid",
        "--insecure-skip-tls-verify",
        "--tls-server-name",
        "--certificate-authority",
        "--client-certificate",
        "--client-key",
        "--username",
        "--password",
    }
)


def _check_kube_argv(argv: list) -> str:
    for tok in argv[1:]:
        flag = tok.split("=", 1)[0]
        if flag in KUBE_DENY_FLAGS:
            return (
                f"kubectl/oc flag {flag!r} is denied under safe_exec "
                "— target-derived commands run only against the "
                "engagement-pinned context (assessment 2026-07-31 F2)"
            )
    return ""


def _curl_host_union(profile: Profile, allowed_hosts: Iterable[str] | None) -> tuple[str, ...]:
    """Union of profile and caller host entries, normalized. Raises on a
    non-empty entry that normalizes to '' — silently dropping it could
    leave the union empty and turn host enforcement off (fail closed)."""
    hosts = (*profile.curl_allowed_hosts, *(allowed_hosts or ()))
    bad = sorted({str(x) for x in hosts if str(x).strip() and not _norm_host(x)})
    if bad:
        raise ValueError(
            f"curl host allowlist entries {bad} do not normalize to a "
            "hostname — refusing to drop them (host enforcement would be "
            "silently weakened)"
        )
    return tuple(sorted({h for h in (_norm_host(x) for x in hosts) if h}))


def validate_argv(
    argv: Sequence[str], profile: Profile, *, allowed_hosts: Iterable[str] = ()
) -> Verdict:
    """Validate one command (no pipeline) as an argv list.

    `allowed_hosts` unions with the profile's `curl_allowed_hosts`; a
    non-empty union restricts every curl URL operand to those hostnames, an
    empty one defers to the profile's `posture`."""
    if not argv:
        return Verdict(False, "empty command")
    if int(os.environ.get(RECURSION_ENV, "0")) >= MAX_RECURSION:
        return Verdict(False, f"safe_exec recursion depth cap ({MAX_RECURSION}) reached")
    head = None
    for tok in argv:
        m = _ENV_PREFIX_RX.match(tok)
        if m and head is None:
            var = m.group(1)
            if var.upper() in PROTECTED_ENV_VARS or var.upper().startswith("GIT_"):
                return Verdict(False, f"assignment to protected env var {var!r}")
            continue
        head = tok
        break
    if head is None:
        return Verdict(False, "command has no executable head")
    base = head if "/" in head else Path(head).name
    name = Path(base).name
    if name in HARD_DENY_BINARIES:
        return Verdict(False, f"{name!r} is hard-denied (never grantable)")
    if name in SHELLS:
        return Verdict(
            False, f"shell {name!r} is never grantable — pipelines run natively under safe_exec"
        )
    if name in ("safe_exec", "safe_exec.py"):
        return Verdict(False, "safe_exec may not re-invoke itself")
    if not profile.permits(head if "/" in head else name):
        if name in INTERPRETERS:
            return Verdict(False, f"interpreter {name!r} not granted by profile {profile.name!r}")
        return Verdict(
            False,
            f"binary {head!r} not in profile {profile.name!r} allowlist {sorted(profile.allow)}",
        )
    if name == "git":
        reason = _check_git_argv([head, *list(argv[argv.index(head) + 1 :])])
        if reason:
            return Verdict(False, reason)
    if name == "curl":
        try:
            hosts = _curl_host_union(profile, allowed_hosts)
        except ValueError as exc:
            return Verdict(False, str(exc))
        reason = _CurlVetter(
            hosts,
            posture=profile.posture,
        ).check_argv(argv[argv.index(head) :])
        if reason:
            return Verdict(False, reason)
    if name in ("kubectl", "oc"):
        reason = _check_kube_argv(list(argv[argv.index(head) :]))
        if reason:
            return Verdict(False, reason)
    return Verdict(True)


def vet_command_string(cmd: str, profile: Profile, *, allowed_hosts: Iterable[str] = ()) -> Verdict:
    """Vet a PoC-derived command STRING. On success, `segments` holds the
    tokenized pipeline (one tuple per `|` segment). `allowed_hosts` — see
    validate_argv."""
    for rx, why in RAW_DENY_PATTERNS:
        if rx.search(cmd or ""):
            return Verdict(False, f"{why} not allowed in step text")
    lex = shlex.shlex(cmd, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    try:
        tokens = list(lex)
    except ValueError as e:
        return Verdict(False, f"unparseable step command: {e}")
    if not tokens:
        return Verdict(False, "empty step command")
    for t in tokens:
        if t and all(c in ";&<>|()" for c in t) and t != "|":
            return Verdict(False, f"shell operator {t!r} not allowed in step text")
    segments: list = [[]]
    for t in tokens:
        if t == "|":
            segments.append([])
        else:
            segments[-1].append(t)
    if len(segments) > 1 and not profile.allow_pipelines:
        return Verdict(False, f"profile {profile.name!r} does not allow pipelines")
    for seg in segments:
        v = validate_argv(seg, profile, allowed_hosts=allowed_hosts)
        if not v.ok:
            return v
    return Verdict(True, segments=tuple(tuple(s) for s in segments))


# ---------------------------------------------------------------------------
# execution
# ---------------------------------------------------------------------------


def _scrubbed_env(
    profile: Profile, extra_env: dict[str, str] | None = None, *, with_keep_env: bool = True
) -> dict[str, str]:
    keep = (*BASE_KEEP_ENV, *(profile.keep_env if with_keep_env else ()))
    env = {k: os.environ[k] for k in keep if k in os.environ}
    env[RECURSION_ENV] = str(int(os.environ.get(RECURSION_ENV, "0")) + 1)
    if extra_env:
        for k, v in extra_env.items():
            if k.upper() in PROTECTED_ENV_VARS:
                raise ValueError(f"extra_env may not set protected {k!r}")
            if with_keep_env:
                env[k] = v
    return env


def _segment_head(seg: Sequence[str]) -> str:
    for tok in seg:
        if _ENV_PREFIX_RX.match(tok):
            continue
        return Path(tok).name
    return ""


def _extract_seg_env(seg: Sequence[str]) -> dict[str, str]:
    env: dict[str, str] = {}
    for tok in seg:
        if m := _ENV_PREFIX_RX.match(tok):
            env[m.group(1)] = m.group(2)
        else:
            break
    return env


def _prepare_exec_argv(seg: Sequence[str]) -> list[str]:
    """Prepare a validated segment for execution: strip leading VAR=val prefixes
    (they are not programs) and ensure curl is invoked with -q to ignore .curlrc."""
    argv = list(seg)
    head_idx = next((i for i, tok in enumerate(argv) if not _ENV_PREFIX_RX.match(tok)), 0)
    cmd = argv[head_idx:]
    if cmd and Path(cmd[0]).name == "curl" and (len(cmd) == 1 or cmd[1] not in ("-q", "--disable")):
        cmd.insert(1, "-q")
    return cmd


def _env_for_segment(
    seg: Sequence[str], profile: Profile, extra_env: dict[str, str] | None
) -> dict[str, str]:
    """Per-segment environment: keep_env/extra_env reach only keep_env_heads
    segments, or every segment when keep_env_heads is empty.
    Also incorporates any validated leading VAR=val assignments for this segment."""
    with_keep = not profile.keep_env_heads or _segment_head(seg) in profile.keep_env_heads
    env = _scrubbed_env(profile, extra_env, with_keep_env=with_keep)
    env.update(_extract_seg_env(seg))
    return env


def run_segments(
    segments,
    profile: Profile,
    *,
    timeout: int = 120,
    cwd=None,
    input_: str | None = None,
    extra_env: dict | None = None,
):
    """Execute validated pipeline segments via subprocess chaining —
    no shell. Returns (rc, stdout, stderr); rc/stderr come from the
    final segment, non-zero upstream rcs are appended to stderr."""
    if len(segments) == 1:
        try:
            proc = subprocess.run(
                _prepare_exec_argv(segments[0]),
                capture_output=True,
                text=True,
                timeout=timeout,
                input=input_,
                cwd=cwd,
                env=_env_for_segment(segments[0], profile, extra_env),
            )
        except subprocess.TimeoutExpired as e:
            out = (
                e.stdout
                if isinstance(e.stdout, str)
                else (e.stdout or b"").decode(errors="replace")
            )
            err = (
                e.stderr
                if isinstance(e.stderr, str)
                else (e.stderr or b"").decode(errors="replace")
            )
            return 124, out, err + f"\n[timeout after {timeout}s]"
        except OSError as e:
            return 127, "", f"[exec failed: {e}]"
        return proc.returncode, proc.stdout, proc.stderr
    procs = []
    prev_stdout = subprocess.PIPE if input_ is not None else None
    try:
        for _i, seg in enumerate(segments):
            stdin = procs[-1].stdout if procs else prev_stdout
            procs.append(
                subprocess.Popen(
                    _prepare_exec_argv(seg),
                    stdin=stdin,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    cwd=cwd,
                    env=_env_for_segment(seg, profile, extra_env),
                )
            )
            if procs[:-1]:
                # let upstream see SIGPIPE naturally
                procs[-2].stdout.close()
        if input_ is not None:
            procs[0].stdin.write(input_)
            procs[0].stdin.close()
        out, err = procs[-1].communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        for p in procs:
            p.kill()
        return 124, "", f"[pipeline timeout after {timeout}s]"
    except OSError as e:
        for p in procs:
            p.kill()
        return 127, "", f"[exec failed: {e}]"
    rc = procs[-1].returncode
    tail_err = err or ""
    for i, p in enumerate(procs[:-1]):
        p.wait(timeout=5)
        if p.returncode not in (0, None):
            tail_err += f"\n[pipeline segment {i} exited {p.returncode}]"
    return rc, out, tail_err


def run(
    cmd,
    profile_name: str,
    *,
    timeout: int = 120,
    cwd=None,
    input_: str | None = None,
    extra_env: dict | None = None,
    honor_bypass: bool = False,
    profile_map: dict | None = None,
    allowed_hosts: Iterable[str] = (),
):
    """Validate then execute. `cmd` is an argv list or a command string.
    Library callers default to NOT honoring SAFE_EXEC_DISABLED.
    `allowed_hosts` — curl host allowlist, see validate_argv."""
    profile = get_profile(profile_name, profile_map=profile_map)
    bypass = os.environ.get("SAFE_EXEC_DISABLED", "").strip()
    if bypass and honor_bypass:
        _log_bypass(cmd, profile_name, bypass)
        segments = (
            [tuple(cmd)]
            if not isinstance(cmd, str)
            else vet_command_string(cmd, profile, allowed_hosts=allowed_hosts).segments
            or [tuple(shlex.split(cmd))]
        )
        return run_segments(
            segments, profile, timeout=timeout, cwd=cwd, input_=input_, extra_env=extra_env
        )
    if isinstance(cmd, str):
        v = vet_command_string(cmd, profile, allowed_hosts=allowed_hosts)
        segments = v.segments
    else:
        v = validate_argv(list(cmd), profile, allowed_hosts=allowed_hosts)
        segments = (tuple(cmd),)
    if not v.ok:
        return 126, "", f"[safe_exec blocked: {v.reason}]"
    return run_segments(
        segments, profile, timeout=timeout, cwd=cwd, input_=input_, extra_env=extra_env
    )


def _log_bypass(cmd, profile_name: str, reason: str) -> None:
    line = f"SAFE_EXEC BYPASS profile={profile_name} reason={reason!r} cmd={cmd!r}"
    print(f"*** {line}", file=sys.stderr)
    try:
        BYPASS_LOG.parent.mkdir(parents=True, exist_ok=True)
        BYPASS_LOG.parent.chmod(0o700)
        with BYPASS_LOG.open("a", encoding="utf-8") as fh:
            import datetime

            fh.write(f"{datetime.datetime.now().astimezone().isoformat()} {line}\n")
    except OSError:
        pass  # the stderr shout already happened


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def check_command(
    profile: str,
    cmd: str | list[str],
    *,
    timeout: int = 120,
    cwd: str | None = None,
    allowed_hosts: Iterable[str] = (),
) -> int:
    profile_obj = get_profile(profile)
    mode = os.environ.get("SAFE_EXEC_MODE", "enforce").lower()
    if isinstance(cmd, str):
        verdict = vet_command_string(cmd, profile_obj, allowed_hosts=allowed_hosts)
    else:
        verdict = validate_argv(cmd, profile_obj, allowed_hosts=allowed_hosts)
    if verdict.ok:
        print("OK")
        return 0
    if mode == "warn":
        print(f"WARN (would block): {verdict.reason}")
        return 0
    print(f"BLOCK: {verdict.reason}")
    return 1


def execute_command(
    profile: str,
    cmd: str | list[str],
    *,
    timeout: int = 120,
    cwd: str | None = None,
    allowed_hosts: Iterable[str] = (),
) -> int:
    profile_obj = get_profile(profile)
    mode = os.environ.get("SAFE_EXEC_MODE", "enforce").lower()
    if isinstance(cmd, str):
        verdict = vet_command_string(cmd, profile_obj, allowed_hosts=allowed_hosts)
    else:
        verdict = validate_argv(cmd, profile_obj, allowed_hosts=allowed_hosts)
    if not verdict.ok and mode == "warn":
        print(f"WARN (would block, running anyway — warn mode): {verdict.reason}", file=sys.stderr)
        segs = verdict.segments or (
            [tuple(shlex.split(cmd))] if isinstance(cmd, str) else [tuple(cmd)]
        )
        rc, out, err = run_segments(segs, profile_obj, timeout=timeout, cwd=cwd)
    else:
        rc, out, err = run(
            cmd, profile, timeout=timeout, cwd=cwd, honor_bypass=True, allowed_hosts=allowed_hosts
        )
    sys.stdout.write(out or "")
    sys.stderr.write(err or "")
    return rc


def list_profiles_cmd() -> int:
    for name, p in sorted(profiles().items()):
        hosts = f"{len(p.curl_allowed_hosts)} listed" if p.curl_allowed_hosts else "none listed"
        print(
            f"{name:18s} posture={p.posture} allow={sorted(p.allow)} "
            f"pipelines={p.allow_pipelines} curl_hosts={hosts} "
            f"— {p.description}"
        )
    return 0
