# Traust Opengrep Rule Pack

Traust-authored opengrep rules — the default ruleset for `run_opengrep.py`.
Shipped with the traust engine and safe to vendor or redistribute.

## Layout

One YAML per language and category (`go/injection.yaml`, …). Each rule file
has a same-basename test fixture (`go/injection.go`, `yaml/foo.test.yaml`)
using standard `// ruleid: <id>` / `// ok: <id>` annotations (or YAML
`# ruleid:` / `# ok:` comments).

```
opengrep-rules/
  go/           # Go rules + .go fixtures
  python/       # Python rules + .py fixtures
  java/         # Java rules + .java fixtures
  typescript/   # TypeScript/JavaScript rules + .ts fixtures
  ruby/         # Ruby rules + .rb fixtures
  rust/         # Rust rules + .rs fixtures
  bash/         # Shell rules + .sh fixtures
  yaml/         # YAML config-default rules + .test.yaml fixtures
```

YAML-language rules use `.test.yaml` fixture files because the rule files
themselves are `.yaml`.

## Running tests

From the `traust-engine` package root, with [opengrep](https://github.com/opengrep/opengrep) on `PATH`:

```bash
opengrep test src/traust_engine/data/secure-code-audit/opengrep-rules/<lang>
```

Run every language directory, or target one (`go`, `python`, `yaml`, …).

`opengrep test` evaluates every fixture whose name extends the rule file's
basename (`data-exposure.nocred.sh` pairs with `data-exposure.yaml`) but
**ignores** `paths:` filters — path exclusions are exercised at scan time
only. File-level co-occurrence constraints (`pattern-inside: pattern-regex:`
with an anchored lookahead) scan comments too; fixtures must not name the
lexicon words they test.

The pytest suite also exercises the pack end-to-end when opengrep is
available:

```bash
pytest tests/test_run_opengrep.py -q
```

## Rule conventions

- **ids:** `traust-<lang>-<category>-<slug>` where `<category>` is a kebab-case
  security category (`injection`, `ssrf`, `cryptography`, `data-exposure`, …).
- **metadata:** `cwe` (primary CWE first — feeds finding fingerprints),
  `category`, `asvs` chapter ref, `confidence`, and optional `references`
  naming the vulnerability pattern cluster (CWE-oriented, no repo slugs).
- **taint mode:** prefer `mode: taint` for data-flow rules; pattern-only
  rules should carry an honest `confidence` tier.
- **messages:** original wording; framework and standard citations by ID only
  (e.g. SEI CERT rule IDs in `metadata.cert` for Java rules).

## Companion gitleaks pack

DSN URLs with embedded credentials are detected by the gitleaks extension in
`../gitleaks-rules/gitleaks-default.toml` (gitleaks reads every file type — `.env`,
`toml`, `properties`, not just code). The yaml tranche here covers the same
miss class in helm values, docker-compose, and operator CR samples.
v1.8 (2026-10-14) — the **authentication, ownership and crypto-hygiene
tranche**: credential acceptance, ownership resolution, security-relevant
configuration flags, and deserialization-sink completeness. These are
seeded rules, not mined ones: each encodes a defect shape that review
missed and no existing rule could surface. Their precision is unmeasured
until their facts are judged (`/mine-ledger`).

- `traust-python-injection-like-wildcard-unescaped`,
  `traust-go-injection-like-wildcard-unescaped` (CWE-155, class CWE-943):
  a LIKE/ILIKE pattern assembled from a run-time value, through an ORM
  pattern operator (SQLAlchemy `like`/`ilike`, peewee `**`), raw SQL text,
  or a bound argument that is itself a wildcard concatenation. An escape
  helper or an ESCAPE clause sanitizes. Pattern rules, not taint: a
  self-chosen account or namespace name is enough to widen the match.
- `traust-python-authentication-jwt-signature-unverified` (new
  `python/authentication.yaml`) and
  `traust-go-authentication-jwt-signature-unverified` (CWE-347): token
  decoding with signature verification switched off, including the
  conditional shape where an options dict is mutated under a test/debug
  flag, the legacy `verify=False` keyword, the `none` algorithm, a Go key
  function that returns no key, and `ParseUnverified` (MEDIUM: it has a
  legitimate key-selection use).
- `traust-python-input-validation-pickle-loads-taint` gained sinks
  (`Unpickler(...).load()` including subclasses, `dill`, `jsonpickle`,
  `shelve`), and `traust-python-input-validation-restricted-unpickler-inventory`
  (INFO, LOW) inventories every `Unpickler` subclass that overrides
  `find_class`. A restricted unpickler is still a deserialization site, so
  a negative result must name it rather than report the class absent.
- `traust-python-cryptography-secret-compare-not-constant-time`,
  `traust-go-cryptography-secret-compare-not-constant-time` (CWE-208,
  LOW): `==`/`!=` (and Go `bytes.Equal`) on token-, password-, digest-,
  signature-, MAC- or API-key-named operands. Literal and nil comparisons
  and metadata-named operands (`*_type`, `*_id`, `*_len`, …) are excluded.

v1.9 (2026-10-16): **two misses from a recall-fixture run.**
- `traust-python-injection-like-wildcard-unescaped` matches a bound
  argument that's an f-string with an interpolation and a `%` anywhere in
  it, inside a tuple or list: `(f"{owner}/{folder}/%",)`. Before this, only
  `f"{x}%"`-shaped arguments matched.
- `traust-python-ssrf-request-taint`:
  - sources add `request.get_json(...)`, `request.json.get(...)`,
    `request.values.get(...)` and `request.form[...]`
  - sinks add the remaining `requests` verbs and `httpx.post`/`request`
  - a database fetch (`fetchone`, `fetchall`, `first`, `one`, …) ends
    request taint, because the value now comes from storage
- New `traust-python-ssrf-stored-url` (CWE-918, WARNING, LOW): an outbound
  call whose URL argument is a database row subscript or a model field with
  a url-type name (`url`, `callback_url`, `webhookUrl`). A URL saved by one
  request and fetched by another never appears as taint. Excluded:
  - config, settings and environment lookups, because the operator sets
    them
  - API response objects (`links`, `resp`, `response`, `headers`)
  - values from a variable assigned from `request` (the taint rule's case)

  Whether anyone other than the operator can write the field is the
  review's judgement.

v1.10 (2026-10-22): **LLM-application tranche** (`<lang>/llm-application.yaml`
for Python, TypeScript and Go). Every rule carries `metadata.owasp_llm`
(OWASP Top 10 for LLM Applications IDs) next to its CWEs. Only shapes that
can be decided from the code itself are here. Whether a tool needs a
per-caller authorization check, how much agency a model should have, and
prompt-injection exposure are left to the review surface.
- **Model output is untrusted input (LLM05, CWE-1426 plus the sink's CWE).**
  Taint rules from SDK completion calls (OpenAI, Anthropic, Gemini,
  LiteLLM, Ollama, LangChain `invoke`, Vercel AI `generateText`, Go
  `openai-go`/`go-openai`/`anthropic-sdk-go`/langchaingo) and their response
  shapes (`choices[i].message.content`, `content[i].text`, `output_text`)
  to:
  - a shell (`output-to-shell-taint`, Go `output-to-exec-taint`)
  - code evaluation (`output-to-code-exec-taint`; Python and TypeScript)
  - SQL text (`output-to-sql-taint`)
  - file paths (`output-to-path-taint`; Python and Go)
- **Supply chain (LLM03, Python only):** `trust-remote-code`,
  `unsafe-model-deserialization` (`torch.load(weights_only=False)`),
  `model-load-default-pickle` (no `weights_only`; WARNING), and
  `unpinned-model-download` (`from_pretrained`/`hf_hub_download`/
  `snapshot_download` with no `revision`; local paths excluded).
- **`mcp-http-without-auth` (LLM06, CWE-306).** An MCP server on an HTTP or
  SSE transport, in a file that configures no authentication. Stdio servers
  and transports chosen at run time are not matched. FastMCP `auth=`,
  `token_verifier=` or `auth_server_provider=` clears a match, and so does
  any bearer/OAuth/JWT/auth-middleware construct in the file. A per-tool
  "handler has no auth call" rule was tried first and dropped: on
  modelcontextprotocol/servers, github/github-mcp-server and the TypeScript
  SDK examples it flagged almost every tool. Those servers are stdio-local,
  delegate to the user's own token, or authenticate at the transport.
- **`unbounded-agent-loop` (LLM10, CWE-834).** `while True` / `while (true)`
  / `for (;;)` / Go `for {}` whose body calls a model and names no step,
  budget, deadline or timeout bound.

Engine note (v1.8): `metavariable-regex` is anchored at the start of the
bound text, so a "contains" test needs a leading `.*` (`(?is).*\blike\b`),
and it cannot sit directly under `pattern-either` — wrap each branch in
its own `patterns:`.


v1.11 (2026-10-27): **TypeScript/JavaScript tranche, from the ledger.** The
rule-mining report's largest uncovered TS/JS clusters were XSS (CWE-79, 37
confirmed findings in about 30 repositories), path traversal (CWE-22, 10)
and open redirect (CWE-601, 4); each rule is written from the cited
findings' evidence. Test, spec, mock and mock-backend files are excluded.
- **XSS (`typescript/cross-site-scripting.yaml`).**
  - `xss-dangerously-set-inner-html`: a computed `__html` value with no
    sanitizer. Translation strings (`t(...)`, `i18n*`) and values named as
    sanitized are not matched.
  - `xss-dom-html-sink`: `innerHTML`/`outerHTML` assignment,
    `insertAdjacentHTML`, `document.write` (also on an opened window) and
    jQuery `.html()` with a computed, unsanitized value.
  - `xss-markdown-raw-html` (WARNING): `rehype-raw` without a later
    `rehype-sanitize`.
  - `xss-reflected-response-taint`: a request value in an Express
    `send`/`write`/`end` string body (sent as text/html).
- **Path traversal (`typescript/path-traversal.yaml`).**
  `path-traversal-fs-taint`: a request value (query, params, body, a
  destructured body field, or `req.url`/`req.path`) reaching the path
  argument of an fs read, write, stream or remove, or `res.sendFile` /
  `res.download`; `path.basename` and filename sanitizers clear it.
- **Open redirect (`typescript/open-redirect.yaml`).**
  `open-redirect-response-taint`: a request value as the target of
  `res.redirect` or a `Location` header. `open-redirect-client-navigation`
  (WARNING): an address-bar value (`URLSearchParams.get`, `location.search`,
  `location.hash`) as the URL of `location.assign/replace/href` or
  `window.open`.
- **SSRF (`typescript/ssrf.yaml`).** More outbound sinks: `http(s).request`,
  the remaining axios methods, got, superagent, needle and undici.

Measured on eight checkouts: 35 hits, including every confirmed TS/JS
finding present in them. Precision is unmeasured until the facts are judged
(`/mine-ledger`). Not covered:
`javascript:` URLs bound to `href`, markdown-to-jsx and marked renderer
overrides, and sanitize-then-transform pipelines; these stay with review.

v1.12 (2026-10-28): **TS/JS sources and one sanitizer, from review.** The
reflected-XSS, open-redirect and SSRF taint rules also take destructured
request fields (`const { x } = req.query`), request headers (`Referer`,
`Host`, any `req.get(...)`), and `req.url` / `req.path` as sources.
`JSON.stringify` is no longer an XSS sanitizer: it leaves `<` and `>` as they
are, and Express sends a string body as HTML, so `res.send(JSON.stringify(x))`
of request data is a sink. On the same eight checkouts this adds 5 hits and
loses none. Flows through helper functions are still not followed.

v1.13 (2026-10-29): **Java, Python, Ruby and Rust, from the ledger.** These
close the Vercel comparison gap plan's recall follow-ups. Each rule is
written from the cited confirmed findings' evidence. Classes with no
confirmed findings (Rust and Ruby SQL, shell interpolation, disabled JWT
verification) get no rule.
- **Java SQL (`java/injection.yaml`).** `injection-sql-concat` now also
  takes:
  - SQL built with `String.format`, `format` or `.formatted`;
  - query text held in a local variable before the call;
  - JPQL and HQL (`createQuery`, `createSQLQuery`) and `JdbcTemplate`'s
    `queryFor*` / `batchUpdate`.

  A literal, or a value declared `int`/`Integer`/`long`/`Long`/`short`, is
  not matched.
- **Python path traversal (`python/path-traversal.yaml`).**
  `path-traversal-file-response-taint`: a catch-all `{name:path}` route
  parameter, or Starlette `request.path_params` / `query_params`, reaching
  `FileResponse`, `open`, `read_bytes`/`read_text`, or returned from a
  `response_class=FileResponse` route. `basename`, `secure_filename` and
  `.name` clear it.
- **Ruby (`ruby/`, new).**
  - `deserialization-yaml-unsafe-load`: `YAML`/`Psych` `unsafe_load` and
    `load` of non-literal data, unless `permitted_classes:` is passed.
  - `deserialization-marshal-load` (WARNING).
  - `injection-kernel-open`: `Kernel#open` / `URI.open` on a non-literal.
    That covers command execution through `|` and SSRF; `File.open` is not
    matched.
  - `injection-erb-template` (WARNING): `ERB.new` on non-literal template
    text, not read from a file.
- **Rust (`rust/`, new).** `path-traversal-request-taint`: a gRPC message
  field (`into_inner()`, or a `…Request` parameter) or an axum/actix `Path`
  / `Query` extractor reaching `std::fs`, `tokio::fs`, `File::open` /
  `create` or `NamedFile::open`; `file_name()` clears it.

Measured on public sample projects (Spring, Rails, FastAPI, axum, tonic):
- `injection-sql-concat` gives 9 hits in one Spring sample, each
  concatenating an id held as a `String` or returned from `getId()`. These
  aren't exploitable but match the shape.
- `yaml-unsafe-load` gives 1 hit, on a maintenance script's local input.
- Nothing else fires.

Precision is unmeasured until the facts are judged (`/mine-ledger`).

v1.14 (2026-10-29): **classic classes for Rust and Ruby.** These rules
cover well-known vulnerability classes in every supported language, for
adopters' code, whether or not this deployment's ledger has seen them.
- **Rust (`rust/injection.yaml`, `rust/authentication.yaml`).**
  - `injection-sql-format`: format!-built SQL (inline or through a `let`)
    run through sqlx, diesel, rusqlite or the postgres client.
  - `injection-shell-format`: `sh -c` / `bash -c` / `cmd /C` with a
    format!-built command.
  - `authentication-jwt-validation-disabled`: jsonwebtoken's
    `insecure_disable_signature_validation`, `validate_exp = false`, or a
    `dangerous_insecure_decode`.
- **Ruby (`ruby/injection.yaml`).**
  - `injection-sql-interpolation`: interpolated SQL in ActiveRecord query
    methods (`where`, `order`, `joins`, `find_by_sql`,
    `connection.execute`, …), and a request parameter used as a raw
    `order`.
  - `injection-shell-interpolation`: interpolated command strings in
    `system`, `exec`, `spawn`, backticks, `%x`, `IO.popen` and `Open3`. The
    multi-argument form is not matched.

