# FalconEye Security Assessment — 2026-07-20

**Scope:** Full codebase (`app/`), dependency manifest, git history, live security headers, and an in-process SSRF/decoder test battery. **Assessment only — nothing was fixed or committed.** Dynamic SSRF/decoder testing was run in-process against the guard functions (no HTTP requests to prod; the public origin was only probed with a single read-only header check). External APIs were never fuzzed; no Mailgun send, AbuseIPDB, or VirusTotal quota was consumed.

---

## Executive summary

**Findings: 0 Critical · 2 High · 7 Medium · 6 Low · (plus INFO/positives).**

The application's core defensive posture is **good**: every server-side fetch of an attacker-controlled URL routes through the canonical `safe_fetch` guard, the username-enumeration path is tightly validated, the abuse-send admin auth is implemented correctly (constant-time compare + bcrypt, fails closed, never logs the password), all SQL is parameterized, and no secret was ever committed to git.

The **single most important fix** is to **pin `safe_fetch` connections to the already-validated IP address**. Today the guard resolves the hostname, validates the resolved IP, and then hands the *hostname* back to httpx, which re-resolves at connect time — the classic DNS-rebinding TOCTOU window (the guard's own docstring acknowledges it). This is the one path by which the app's central SSRF protection can be defeated to reach internal/link-local/metadata services.

**SSRF battery result:** the canonical guard **blocked the entire battery on Linux** (loopback, metadata `169.254.169.254`, decimal/hex/octal encodings, IPv4-mapped IPv6, CGNAT, NAT64, IPv6 link-local, userinfo, `file://`/`gopher://`). The one apparent miss (`http://0177.0.0.1/`) is a **macOS test-host artifact**, not a production bug: macOS `getaddrinfo` resolves `0177.0.0.1`→`177.0.0.1` (public), whereas Linux glibc `inet_aton` resolves it to `127.0.0.1`, which `is_private_ip()` blocks. Production is Linux → blocked.

**Committed secrets:** none. `.env` is git-ignored and was never committed; no bcrypt hash, `sk-ant-`, or `key-` token exists anywhere in history. **Rotate the AbuseIPDB key anyway** — it was exposed in a chat transcript out-of-band (not recoverable from this repo, but exposure stands).

---

## HIGH

### [HIGH] H-1 — DNS-rebinding TOCTOU in the SSRF guard (connection is not pinned to the validated IP)
- **Location:** `app/utils/safe_fetch.py:123-134`; same pattern in `app/routers/url_expander.py:220-233`, `app/routers/scanner.py:81` (via `safe_fetch`), `app/username/checker.py:125` (via `resolve_and_check`)
- **Class:** SSRF
- **Description:** `safe_fetch` resolves the hostname and validates every returned IP with `resolve_and_check(host)`, then issues the request with the **hostname**, letting httpx perform its *own* DNS resolution at connect time. Between the guard's resolution and httpx's resolution, a short-TTL attacker-controlled domain can rebind from a public IP (passes the check) to an internal IP (what httpx actually connects to). The HTTP connection is never pinned to the IP the guard approved. (In `url_expander._grab_tls` the TLS cert grab *is* pinned to `addrs[0]` — but the actual HTTP fetch is not.)
- **Evidence:**
  ```python
  # safe_fetch.py
  resolve_and_check(host)                       # (A) resolve + validate
  async with httpx.AsyncClient(follow_redirects=False, ...) as client:
      response = await client.request(method, current_url, ...)   # (B) httpx re-resolves host → connects
  ```
  The docstring states the gap explicitly: *"httpx still performs its own resolution at connect time (the true TOCTOU window)."*
- **Impact:** An attacker who controls a domain's authoritative DNS can bypass the guard and make the server connect to `127.0.0.1`, `169.254.169.254` (cloud metadata / link-local), or other internal hosts, reaching the URL Expander, phishing Scanner, username sweep, and RDAP paths. This is the highest-impact class for this application.
- **Confidence:** Confirmed design gap. Real-world exploitation requires the attacker to control DNS for the submitted host and win the rebind race within one request (httpx opens a fresh resolution per `AsyncClient`, so the window is real but not deterministic). Note the VPS is OVH, which does not expose the AWS-style `169.254.169.254` metadata service — but loopback/internal services and other link-local endpoints remain reachable.
- **Recommended fix:** Resolve once, then connect to the validated IP: pass the approved IP to a custom `httpx` transport / resolver (or connect to the IP directly with `server_hostname`/`Host` preserved for SNI+vhost). Apply the same pinning to redirect hops. This makes check-time and connect-time resolution identical.

### [HIGH] H-2 — Reachable DoS in `python-multipart 0.0.9` and `starlette 0.37.2` on unauthenticated upload/form endpoints
- **Location:** `requirements.txt` (`python-multipart==0.0.9`; `starlette==0.37.2` pulled by `fastapi==0.111.0`). Reachable via `POST /api/qr/decode`, `POST /api/email-header/upload`, `POST /api/image/*`, and any form-parsing route.
- **Class:** dependency-CVE / DoS
- **Description:** `pip-audit` reports multiple denial-of-service advisories fixed in later releases, all in the multipart/form parsing path that Starlette/FastAPI invokes **before** the route handler runs (so the handlers' 5 MB / 10 MB size checks do not mitigate them — the parser has already processed the body).
- **Evidence (pip-audit, `requirements.txt`, Python 3.12):**
  - `python-multipart 0.0.9`: `PYSEC-2026-3038` (large preamble/epilogue DoS, fix 0.0.26), `PYSEC-2026-3039` (part-header parsing DoS, fix 0.0.27), `PYSEC-2026-3040` (Content-Length not validated before chunked read, fix 0.0.31), `PYSEC-2026-1851` (fix 0.0.18), plus `PYSEC-2026-1852` path-traversal (only with non-default `UPLOAD_DIR`+`UPLOAD_KEEP_FILENAME` — **not** used here).
  - `starlette 0.37.2`: `PYSEC-2026-1943` (non-filename multipart parts buffered in memory, fix 0.40.0), `PYSEC-2026-1941` (large-file spool DoS, fix 0.47.2), `PYSEC-2026-249` (`request.form` `max_fields`/`max_part_size`, fix 1.3.1), `PYSEC-2026-161`/`248` (Host/path not validated in `request.url` reconstruction).
- **Impact:** An unauthenticated client can exhaust CPU/memory on the origin by POSTing crafted multipart bodies to the file-upload endpoints. Cloudflare + nginx body-size limits and the per-IP daily caps blunt but do not remove this (the caps run *after* parsing, and are per-CF-IP — see M-4).
- **Confidence:** Confirmed (tool-reported, current advisories).
- **Recommended fix:** Bump `python-multipart>=0.0.31`. Upgrading Starlette to a fixed line requires moving off FastAPI 0.111 (Starlette 0.40+/1.x) — plan that upgrade; interim mitigation: strict nginx `client_max_body_size`, request timeouts, and Cloudflare upload limits.

---

## MEDIUM

### [MEDIUM] M-1 — `/api/abuse/send` has no rate limit → online bcrypt brute-force + CPU-exhaustion DoS
- **Location:** `app/abuse/routes.py:176-189` (no `@limiter` decorator, no SQLite quota); `_verify_admin` at `routes.py:77-101`
- **Class:** auth / DoS
- **Description:** Send rate limits were removed in v3.8.3 ("auth is the only remaining control"). But the endpoint runs `bcrypt.checkpw` on every request and always returns HTTP 200 with `{sent, error}` (no 401, by design). With no throttle and no lockout, an attacker gets (a) **unthrottled online guessing** against the admin password, and (b) a **CPU-exhaustion primitive** — each unauthenticated request forces a deliberately expensive bcrypt computation.
- **Evidence:** `send` has only `@router.post("/send")` (confirmed: no `@limiter.limit`). `_verify_admin` → `bcrypt.checkpw(...)` on every call regardless of outcome.
- **Impact:** Answering the question posed in the brief directly: **removing the rate limit *does* enable abuse.** The bcrypt hash is strong so password recovery is slow, but the CPU-DoS is immediate and there is no failed-attempt backoff.
- **Confidence:** Confirmed.
- **Recommended fix:** Reinstate a burst limit on `/send` (per-IP + a global ceiling) and a short exponential backoff on consecutive auth failures. Keep the structured-200 response contract.

### [MEDIUM] M-2 — Email-header `/analyze` DoS via nested-multipart `RecursionError`
- **Location:** `app/routers/email_header.py:965` (`@router.post("/api/email-header/analyze")`, no rate limit), `:995` (`msg = message_from_string(raw)` — not wrapped), `:1002-1003` (`msg.walk()`)
- **Class:** DoS / info-disclosure
- **Description:** `/analyze` is unauthenticated and has no rate limit. It parses the pasted header (≤200 KB) with `message_from_string`. A deeply nested `multipart/*` structure that fits well within 200 KB overflows Python's recursion limit during parse/walk.
- **Evidence (in-process test):**
  ```
  depth=  50  bytes=  4173  parsed OK (51 parts) in 22ms
  depth= 500  bytes= 42723  parsed OK (501 parts) in 82ms
  depth=2000                 RecursionError
  ```
  ~85 bytes per nesting level → depth ~2000 fits in the 200 KB cap; `message_from_string` is not in a try/except → unhandled `RecursionError` → HTTP 500. Cache is keyed on payload hash, so a novel payload each request bypasses it.
- **Impact:** Unauthenticated, unthrottled 500-inducing requests; each is cheap for the attacker (~170 KB).
- **Confidence:** Confirmed.
- **Recommended fix:** Add a rate limit to `/analyze`; reject or cap multipart nesting depth (or wrap the parse and return a 400); consider a hard cap on `msg.walk()` part count.

### [MEDIUM] M-3 — CSP allows `'unsafe-inline'` in `script-src`
- **Location:** Response headers (nginx). Observed on the live origin.
- **Class:** misconfiguration
- **Description:** `script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com`. The UI is built with template-string HTML and inline `onclick=` handlers, and the Tailwind Play CDN requires `unsafe-inline`. With `unsafe-inline` present, CSP provides **no second line of defense** against a DOM/HTML-injection bug — a single missed `escapeHtml`/`escapeAttr` would execute.
- **Evidence:** `content-security-policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com; ...` (the rest of the policy is strong: `object-src 'none'`, `base-uri 'self'`, `form-action 'self'`, `frame-ancestors 'none'`).
- **Impact:** Reduced XSS containment. (No XSS sink was found in this review — the client-side escaping is applied consistently, e.g. `googleUrl` uses `encodeURIComponent` — so this is defense-in-depth.)
- **Confidence:** Confirmed (documented Tailwind tradeoff).
- **Recommended fix:** Move to a nonce- or hash-based CSP and self-host a compiled Tailwind bundle so `'unsafe-inline'` can be dropped from `script-src`.

### [MEDIUM] M-4 — Rate-limit bypass via spoofed `CF-Connecting-IP` if the origin is reachable outside the nginx allowlist
- **Location:** `app/utils/client_ip.py:19-22`
- **Class:** defense-in-depth / rate-limit bypass
- **Description:** `get_client_ip` returns `CF-Connecting-IP` unconditionally when present. This is safe **only** because nginx restricts inbound connections to Cloudflare ranges (documented in the module). If the origin/`:8001` is ever reachable directly (staging port exposed, allowlist drift, container port publish), an attacker sets a fresh `CF-Connecting-IP` per request and every per-IP limit sees a "new" client — defeating the username fan-out cap, QR/URL/LLM daily caps, and the SSRF-probe metering on the URL Expander.
- **Impact:** Per-IP quotas become ineffective; only the global daily ceilings (e.g. username 100/day) still bound abuse.
- **Confidence:** Confirmed logic; real-world impact is config-dependent on the nginx allowlist holding.
- **Recommended fix:** Validate at the app layer that `request.client.host` is a Cloudflare IP before trusting `CF-Connecting-IP`; otherwise fall back to the socket peer. Keep the nginx allowlist as the primary control.

### [MEDIUM] M-5 — Legacy `ssrf.validate_url` has multiple blocklist bypasses (latent SSRF landmine)
- **Location:** `app/utils/ssrf.py:5-54`
- **Class:** SSRF (latent)
- **Description:** The older guard's `BLOCKED_RANGES` is incomplete. The battery confirmed it **allows**: `::ffff:127.0.0.1` and `::ffff:169.254.169.254` (IPv4-mapped IPv6 is never unwrapped), `100.64.0.1` (CGNAT), `0.0.0.0`, `fe80::1` (IPv6 link-local), and `64:ff9b::7f00:1` (NAT64). By contrast `safe_fetch.is_private_ip` correctly returns `True` for all of these.
- **Evidence:** Battery output — `legacy NOT blocked: [::ffff:127.0.0.1, ::ffff:169.254.169.254, 100.64.0.1, 0.0.0.0, fe80::1, 64:ff9b::7f00:1, 0177.0.0.1]`.
- **Impact:** **None today** — per the call-site census this guard only wraps fixed blockchain-API hosts in `crypto.py` (address is a path segment) and the `image_search` `image_url` that is *forwarded to SearchAPI as a parameter, not fetched locally*. But it is a landmine: any future reuse of `validate_url` for a local fetch of a user URL yields immediate SSRF.
- **Confidence:** Confirmed.
- **Recommended fix:** Delete `app/utils/ssrf.py` and route the two remaining callers through `safe_fetch.is_private_ip` / `resolve_and_check` (single source of truth, as the codebase already intends).

### [MEDIUM] M-6 — `lxml 5.2.1` XML entity-expansion advisory (present, not currently reachable)
- **Location:** `requirements.txt` (`lxml==5.2.1`); only use is `app/routers/telegram_inspector.py:64` `BeautifulSoup(html, "lxml")`
- **Class:** dependency-CVE
- **Description:** `pip-audit` reports `PYSEC-2026-87` (entity resolution with `resolve_entities=True` allows untrusted-XML attacks; fix 6.1.0). The only lxml usage is BeautifulSoup's **HTML** parser applied to `https://t.me/s/{channel}` content — a fixed, trusted host, and bs4's HTML parser does not enable external-entity resolution, so the advisory is **not reachable** through current code.
- **Impact:** No current exploit path; hygiene only.
- **Confidence:** Not reachable via current usage.
- **Recommended fix:** Bump `lxml>=6.1.0` on the next dependency pass.

### [MEDIUM] M-7 — QR decoder relies on Pillow's default decompression-bomb limit; Pillow is unpinned
- **Location:** `app/routers/qr_analyzer.py:96-104` (`img.load()` forces a full raster); `requirements.txt` (`Pillow>=10.0.0`, unpinned)
- **Class:** DoS / dependency-hygiene
- **Description:** `decode_qr` caps the *input* at 5 MB and calls `img.load()` to force decoding. There is no explicit output-dimension / `Image.MAX_IMAGE_PIXELS` cap — a small compressed PNG can inflate to a large bitmap. Pillow's default `MAX_IMAGE_PIXELS` (~178 M px hard error) does bound it, and the exception is caught gracefully, but the control is implicit. Separately, `Pillow>=10.0.0` is unpinned: a host that installed an early 10.x carries image-parsing CVEs (e.g. the `_imaging`/ICC-profile issues fixed by 10.3.0) reachable via `Image.open`+`load`.
- **Impact:** Memory spike on a crafted image (bounded but implicit); unknown deployed Pillow version could carry parsing CVEs.
- **Confidence:** Likely (bounded by Pillow default + 5 MB input).
- **Recommended fix:** Set `Image.MAX_IMAGE_PIXELS` explicitly and reject oversized dimensions before `load()`; pin `Pillow>=10.3.0` (confirm the deployed version on the VPS).

---

## LOW

### [LOW] L-1 — `/api/abuse/send` trusts the client-supplied `composed` dict; `target`/`category` are not CRLF-stripped before becoming mail headers
- **Location:** `app/abuse/send.py:96-116`
- **Class:** injection (header) / defense-in-depth
- **Description:** `send` accepts `composed: dict` straight from the request body — the server-side `compose_report` sanitization is **not** enforced. `subject` and `reporter_email` are re-stripped of CR/LF in `send.py`, but `target` → `h:X-Report-Abuse` (`target[:255]`) and `category` → `o:tag` are **not**. httpx form-encodes the values (so no HTTP request smuggling), and whether CR/LF survives into the outbound email depends on Mailgun's own header handling (Mailgun typically sanitizes custom headers).
- **Impact:** Low — requires valid admin credentials, the recipient is constrained to RDAP-cached addresses, and Mailgun likely neutralizes it. At most an authenticated admin could attempt to inject a header into their own outbound report.
- **Recommended fix:** Apply the same `_strip_single_line` treatment to `target` and `category` in `send.py`, or re-run `compose_report` server-side from primitive fields instead of trusting the client dict.

### [LOW] L-2 — `whois` invoked on an unvalidated hostname (leading-hyphen argument injection)
- **Location:** `app/utils/domain_age.py:145` (`subprocess.run(["whois", domain])`); `domain` derived from `urlparse(url).hostname` (scanner path), not regex-validated
- **Class:** injection (argv)
- **Description:** Unlike `domain_intel.py`/`normalize_domain` (which blocks a leading hyphen), the domain-age path passes the parsed hostname straight to `whois`. A hostname beginning with `-` is interpreted by `whois` as a flag. It is an argv list (no shell) so there is no command injection — only whois-flag confusion.
- **Impact:** Cosmetic; a crafted hostname could alter whois behavior/output. No RCE.
- **Recommended fix:** Validate the hostname (reuse `normalize_domain`) or pass `--` before `domain`.

### [LOW] L-3 — Crypto address validation is prefix+length only (no charset/checksum)
- **Location:** `app/routers/crypto.py:23-31`
- **Class:** input-validation
- **Description:** `detect_chain` checks only prefix and length, not charset or checksum. The address is a path segment appended to a fixed blockchain-API host and re-checked by `validate_url`. A decoded `?`/`#` inside the segment could smuggle query/fragment content to the upstream API — same host, so **not** SSRF.
- **Impact:** Low (malformed upstream query at worst).
- **Recommended fix:** Add a per-chain charset regex (`^0x[0-9a-fA-F]{40}$`, base58/bech32 for BTC, base58 for TRON).

### [LOW] L-4 — SQL identifier guards use `assert` (stripped under `python -O`)
- **Location:** `app/abuse/store.py:197, 211` (`count_recent`/`record_event`); analogous fixed-registry pattern in `app/abuse/tools.py`
- **Class:** injection (defense-in-depth)
- **Description:** The f-string `{table}`/`{column}` interpolation is constrained by `assert table in _RL_TABLES ...`. Every current caller passes hardcoded literals, so there is no injection today, but `assert` is removed under `-O`, so the guard is interpreter-flag-dependent.
- **Impact:** None currently; robustness only.
- **Recommended fix:** Replace the asserts with explicit `if ... raise ValueError`.

### [LOW] L-5 — `_enrich_ip` uses a regex-only IP (not `ipaddress`-parsed) before the RIPEstat query
- **Location:** `app/routers/email_header.py:207-217, 392-421`
- **Class:** input-validation
- **Description:** IPs are pulled from user-supplied `Received:` headers with a loose regex (`\d{1,3}(\.\d{1,3}){3}` — accepts octets >255) and filtered only by string-prefix `PRIVATE_RANGES` (misses `169.254/16`, `0/8`, `100.64/10`, multicast). The value is only sent as `params={"resource": ip}` to the fixed host `stat.ripe.net` (httpx URL-encodes params), so host/path cannot be altered.
- **Impact:** Low — junk queries to RIPEstat and a PTR lookup of an arbitrary public IP.
- **Recommended fix:** Parse with `ipaddress.ip_address` and reuse `safe_fetch.is_private_ip` for the public-IP filter.

### [LOW] L-6 — `ip_intel.validate_ip` omits CGNAT `100.64.0.0/10`
- **Location:** `app/routers/ip_intel.py:29-37`
- **Class:** input-validation
- **Description:** The IP validator blocks private/loopback/link-local/multicast/reserved/unspecified but not CGNAT. All downstream targets are fixed reputation APIs, so this is inconsequential, but it is inconsistent with `safe_fetch.is_private_ip`.
- **Recommended fix:** Add the CGNAT range (or delegate to `is_private_ip`).

---

## INFO / positive observations

- **SSRF canonical guard held against the full battery on Linux.** `is_private_ip` correctly flags IPv4-mapped IPv6, CGNAT, NAT64, `0.0.0.0`, and IPv6 link-local. The `0177.0.0.1` "allow" is a macOS test-host artifact (`getaddrinfo`→`177.0.0.1`); on Linux `inet_aton`→`127.0.0.1`→blocked. *Caveat:* the guard's correctness for numeric hosts is coupled to libc's `getaddrinfo` parsing — a minor argument for pre-parsing/`AI_NUMERICHOST` normalization.
- **No committed secrets.** `.env` is git-ignored and never appears in history; no bcrypt hash, `sk-ant-`, or `key-` token in any commit. The only scanner hits are a `key-xxxx…` placeholder in `docs/` and vendored `.venv` library fixtures (both false positives).
- **Username enumeration path is well-built:** anchored `^[a-zA-Z0-9._-]{1,40}$`, `quote(..., safe="")` re-encoding, per-host `resolve_and_check` with fail-closed verdicts, `follow_redirects=False`, quotas enforced before fan-out. No host-injection or SSRF path.
- **Abuse-send auth is correct:** `secrets.compare_digest` (username) + `bcrypt.checkpw` (password), both evaluated (no short-circuit timing leak), fails closed on missing/empty env, and the password is never logged or written to the audit table.
- **Open-relay protection is sound:** recipients are constrained to RDAP-cached abuse contacts or the operator's own reporter address; a request-body recipient cannot be spoofed.
- **All SQL is parameterized.** The only dynamic-identifier queries interpolate table/column names from fixed internal registries with all values bound.
- **Security headers are otherwise strong:** HSTS (`max-age=31536000; includeSubDomains`), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` + `frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, `object-src 'none'`, `base-uri 'self'`.

---

## Appendix — false positives / findings triaged out

| Source | Finding | Disposition |
|---|---|---|
| semgrep | `app/static/app.js:2375` `raw-html-format` on `${googleUrl}` in `href` | **FP** — `googleUrl` = `https://www.google.com/search?q=${encodeURIComponent(dk.query)}`; value is encoded, no injection. |
| bandit B608 (×5) | `abuse/store.py:202/215/216`, `abuse/tools.py:47/53` "SQL injection via string construction" | **FP** — `{table}`/`{column}` come from fixed internal registries (`_RL_TABLES`/`RATE_LIMIT_TABLES`); all values bound with `?`. (Assert-hardening noted as L-4.) |
| bandit B101 (×2) | `assert` used | Tracked as L-4 (defense-in-depth). |
| bandit B404/B603/B607 (×2 each) | `subprocess`/`whois` without absolute path | Benign — argv lists, no shell. Hostname-validation gap tracked as L-2. |
| bandit B110/B112 (×8) | `try/except/pass` and `try/except/continue` | Benign best-effort error handling (network/DNS/parse fallbacks). |
| trufflehog3 | `docs/abuse-reporting.md:100` `key-xxxx…`; multiple `.venv/site-packages/*` URL-credential fixtures | **FP** — documentation placeholder and vendored library test data; no real secret. |
| pip-audit | `python-multipart` `PYSEC-2026-1852` path traversal | **Not applicable** — requires non-default `UPLOAD_DIR`+`UPLOAD_KEEP_FILENAME`, not used. |

---

## Tooling notes

- Static: **semgrep 1.170.0** (`p/python`, `p/owasp-top-ten`, `p/secrets`) → 1 finding (FP above). **bandit** → 21 findings, all triaged above. **pip-audit 2.10.1** against `requirements.txt` → 18 advisories across `lxml`/`python-multipart`/`starlette` (H-2, M-6). **trufflehog3** full-tree secret scan → no real secret. Git history manually scanned for `.env`, bcrypt, `sk-ant-`, `key-` patterns → clean.
- All scanner tooling was installed in a throwaway Python 3.12 venv under the session scratchpad and is being removed; the production `.venv` was not modified. (Note: the repo's local `.venv` is Python 3.9 and cannot import the app — it uses 3.10+ `str | None` syntax — so it is stale; production runs a newer Python.)
- Dynamic SSRF/decoder testing was performed **in-process** against the guard/parser functions (no HTTP to prod, no external API calls, no Mailgun send).

**Nothing was fixed. Nothing was committed. This document and the independent-review bundle are the only artifacts.**
