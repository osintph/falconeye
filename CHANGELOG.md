# Changelog

All notable changes to FalconEye are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [3.14.0] — 2026-07-22

New tab: **Breach Check**, a Have I Been Pwned integration. Tab count 17 → 18.

### Added

- **Email breach + paste lookup.** Queries HIBP's `breachedaccount` and `pasteaccount` endpoints concurrently, enriches every breach hit with full metadata (title, dates, account count, description, data classes, logo, verified/sensitive/fabricated/retired/spam-list flags) from the free `breach/{name}` endpoint. Results show a summary card (breach/paste counts, earliest/latest breach date, a prominent notice when passwords were exposed), a chronological timeline, per-breach cards with colour-coded data-class chips (passwords red, financial deep red, email-only neutral, everything else amber), and the paste list.
- **Sensitive breaches redacted by default.** Any HIBP-flagged `IsSensitive` breach (adult/dating sites etc.) renders as a "click to reveal" placeholder in per-target results (email/domain lookups) unless the "Show sensitive breaches" toggle is on — mirrors how the Username tab gates adult platforms. The reference sections (recent breaches, browse all) show a plain sensitivity flag instead, since they aren't tied to a specific person.
- **Password check via Pwned Passwords K-anonymity — fully client-side.** The browser hashes the password with `crypto.subtle.digest('SHA-1', ...)` and sends only the first 5 hex characters to `api.pwnedpasswords.com`, matching the returned suffix list locally. There is no backend endpoint for this at all: proxying it through our server would break the one property that makes the check trustworthy. Verifiable in DevTools — the only network call is to `api.pwnedpasswords.com`, never to falconeye.
- **Domain breach lookup** via HIBP's free `breaches?domain=` endpoint, same card format as email results, plus a resolved hosting-IP pivot to the IP Reputation tab.
- **Recent breaches** (5 most recently added, combining the cached bulk breach list with the fresher `latestbreach` pointer so the top of the list is never more than 1h stale even though the bulk list caches 6h) and a collapsible, lazily-loaded **browse all breaches** reference table (searchable, sortable, cached indefinitely per the corpus not retroactively changing).
- **Cross-tab pivots:** email local-part → Username Enumeration, email domain → Domain Intelligence, resolved hosting IP → IP Reputation, recent/browse-all breach → the HIBP page for that breach. Reuses the existing global `pivotToUsernameEnum`/`pivotToDomain`/`pivotToIp` helpers rather than adding new ones.
- **CSV export** for email and domain results, with the HIBP CC BY 4.0 attribution as the first row of the file.
- New backend package `app/breach/` (`client.py`: safe_fetch-based HIBP client with Retry-After-aware exponential backoff on 429; `store.py`: SQLite cache + rate limiting; `routes.py`: `/api/breach/email`, `/api/breach/domain`, `/api/breach/recent`, `/api/breach/all`, `/api/breach/dataclasses`). Email and domain lookups are POST with a JSON body (never a query string) specifically so the address never lands in an access log.

### Security / privacy

- Emails are **never stored in plaintext** — the cache key is SHA-256(normalized email); the raw address is never persisted, only echoed back in the same request's response.
- Every HIBP call goes through the `safe_fetch` SSRF guard, matching `app.abuse.lookup`'s policy of one SSRF primitive for the whole app even for fixed, trusted hosts.
- Per-IP limits (5/hour, 30/day for both email and domain search, well under HIBP's 10 req/min ceiling) plus a 200/day global cap on each, to protect the monthly API budget. A rate-limited request returns HTTP 200 with `{"rate_limited": true}` rather than 429 — a deliberate choice for this endpoint's contract, verified by test.
- Cache TTLs: email/paste results 24h, domain results 12h, bulk breach list 6h, latest-breach pointer 1h, per-breach metadata and the data-classes list indefinitely (they don't change).

### Notes

- Requires an `HIBP_API_KEY` (HIBP Core 1 subscription) for the email/paste endpoints; domain/recent/browse-all use HIBP's free, unauthenticated endpoints and work without a key.
- HIBP's CC BY 4.0 licence requires visible attribution on every surface that shows breach data: the tab subtitle, a footer on every result set (email, domain, password, recent, browse-all), the per-breach logo, CSV exports, and the tab's privacy note — all five confirmed present at staging before release.
- HIBP subscription and this use case confirmed in writing by HIBP support (Bruce); the confirmation email is kept outside the git tree as a compliance record.

---

## [3.13.0] — 2026-07-21

Telegram Intelligence — full rework of the old Telegram Channel Inspector, which only handled `t.me/s/{channel}` and 404'd on any user, bot, or channel/group without preview enabled. Replaces `app/routers/telegram_inspector.py` + `app/utils/telegram.py` with a new `app/telegram/` package.

### Added

- **Any Telegram username, @handle, channel, bot, or t.me link now resolves.** Three independent capability tiers, each degrading gracefully on its own:
  - **Tier 1 (free scrape, always on).** Fetches `t.me/{identifier}` — not just the old `/s/{channel}` preview — which works for any entity type. Entity-type detection (user/bot/channel/group) is derived from empirically-confirmed t.me HTML signals (action-button text, subscriber/member counters, the verified checkmark), documented in `tier1_scrape.py`. A syntactically-valid-but-unowned username renders the identical generic fallback page as a genuinely nonexistent one, so this tier reports "unresolved" rather than a false "not found," giving tier 3 a chance to resolve it first.
  - **Tier 2 (Bot API, `TELEGRAM_BOT_TOKEN`).** `getChat` + `getChatMemberCount` enrichment for channels/groups (member count needs a separate call — not present in `ChatFullInfo`). Correctly skipped as not-applicable for users/bots, a real Bot API limitation.
  - **Tier 3 (MTProto via Telethon, `TELEGRAM_API_ID`/`TELEGRAM_API_HASH`/session file).** Definitive entity type, verified/scam/fake flags, DC geolocation, and a clearly-caveated rough account-era estimate from the ID range. `FLOOD_WAIT` is slept through inline up to 10s; longer waits are reported as a status instead of hanging the request.
  - Tier 3 is authoritative when available and overrides tier 1's best-effort guess; every header field is tagged with the tier it came from (shown subtly in the UI).
- **IOC extraction** now separates URLs, other `@handles`, and other `t.me` links into distinct buckets (previously only URLs/crypto/contact patterns). New pivots: Telegram handle → Username Enumeration (the highest-value one — a Telegram handle is a username), extracted URLs → URL Expander, extracted handles → re-run this tab, crypto → Crypto tab.
- **Renamed to "Telegram Intelligence"** with a full visual rework: entity-type badges (user/bot/channel/group), loud red scam/fake flags, a green verified badge, and per-field tier-source tags. All-new privacy note covering the three lookup paths.

### Fixed

- Standalone one-time login script (`telegram_login.py`, deployed outside the git tree to `/opt/falconeye/private/`) had an un-awaited `get_me()` call that printed `(@None, id=?)` and a `RuntimeWarning` on successful login. Fixed — future re-authentications print the account confirmation correctly.

### Known caveat (tracked for v3.13.1, not built yet)

Gunicorn's 3 worker processes each lazily open their own Telethon connection against the same SQLite session file, which isn't designed for concurrent multi-process access. Under real concurrent load this can occasionally raise "database is locked," caught and surfaced as a transient tier-3 error rather than a crash. Being monitored via the daily operator report; if it shows up meaningfully, the fix is a dedicated async worker or file-lock initialization for tier 3.

---

## [3.12.2] — 2026-07-21

Fixes the Username Enumeration tab's Full scan (~965 sites, ~50s) returning a raw parse error instead of a result. Closes the whole class of "non-JSON reached the frontend," not just the immediate cause, with three independent layers.

### Fixed

- **nginx/gunicorn timeouts were cutting off Full scans.** `proxy_read_timeout`/`proxy_send_timeout` (nginx) and gunicorn's worker `--timeout` are raised 30s/60s → 90s. A Full scan's own hard wall-clock deadline (`app.username.routes._DEADLINE["full"]`, 50s) means the real worst case is ~50-53s regardless of how many individual sites are slow or unresponsive that day — 90s leaves comfortable headroom under Cloudflare's ~100s edge ceiling, so no async job-polling rework was needed. Quick scope (25s deadline) was never affected. Already applied live as routine tuning (commit `886d354`, 2026-07-20); folded into this release's notes for a complete record.
- **Global JSON exception handler.** Any unhandled exception anywhere in the app previously fell through to Starlette's default `PlainTextResponse("Internal Server Error")` — not JSON, so it broke callers the same way the nginx HTML timeout page did, just with different text. `app/main.py` now registers an app-wide handler that converts any exception without a more specific handler into a JSON 500. Existing explicit error paths (400/429/503, the burst limiter's 429) are untouched — this only catches what previously slipped through uncaught, across every router.
- **`app.username.store.count_recent` fails closed instead of raising.** The one concrete known gap the global handler above was added to catch: a SQLite read failure in the per-IP scan-rate-limit lookup had no exception handling (unlike the paired `record_event` write). It now logs and returns a large sentinel count on error, so a DB hiccup is treated as "over the limit" — fails closed, the correct default for a rate limiter — instead of a 500.
- **Frontend guard for any non-JSON scan response.** The Username tab's scan handler now recognizes a JSON-parse failure specifically (`SyntaxError`) and shows "Full scan timed out or failed — try Quick scope or retry" instead of surfacing the raw `Unexpected token '<'...` parse error, regardless of what actually broke upstream.

---

## [3.12.1] — 2026-07-20

Security release fixing the two unauthenticated denial-of-service findings (M-1, M-2) from the 2026-07-20 assessment, on top of the v3.12.0 framework upgrade. Scoped to just these two.

### Security

- **M-1 — rate limiting reinstated on `/api/abuse/send`.** Send throttling was removed in v3.8.3 on the assumption that admin auth sufficed; the assessment showed otherwise. Because `/send` runs `bcrypt.checkpw` on every request and always returns 200, an unthrottled endpoint was both an unauthenticated bcrypt CPU-exhaustion primitive and an unthrottled online password-guessing oracle. It now enforces, **all before bcrypt runs**, a per-IP burst cap (5/min), a per-IP hourly cap (20/hr), and a global hourly ceiling (60/hr), plus **exponential backoff on consecutive failed auth from the same IP** (first 3 failures free; each further failure requires a cooldown that doubles 2→4→8… seconds up to 5 minutes, reset on a successful auth). Reuses the pre-existing `abuse_send_rate_limit` table. Throttled/backed-off requests return the structured `{"sent": false, "rate_limited": true, "error": …}` at HTTP 200 — never 401 (which would re-open the browser Basic Auth dialog killed in v3.8.1); the frontend already surfaces `rate_limited`. A real operator sending a handful of reports never hits the limit.
- **M-2 — `/api/email-header/analyze` hardened against the nested-multipart RecursionError DoS.** The unauthenticated endpoint parsed pasted headers (≤200KB) with the stdlib `message_from_string` unguarded; a deeply nested multipart (~85 bytes/level, so depth ~2000 fits the cap) overflowed Python's recursion limit → an unhandled HTTP 500, and a novel payload each request bypassed the response cache. Now: the parse is wrapped so a `RecursionError` (or any parse error) returns a clean **400**; an **iterative (non-recursive) depth/part-count cap** (≤100 nesting levels, ≤500 parts) rejects excessive structures with a 400 well below the overflow threshold; and the endpoint is **rate-limited per IP** (20/min). This path uses the stdlib email parser, not Starlette's multipart parser, so it is unaffected by the v3.12.0 framework change. Legitimate email, including normal multipart, analyzes unchanged.

Both are unauthenticated DoS vectors a hostile visitor could exploit against the origin.

---

## [3.12.0] — 2026-07-20

Security release closing **H-2 part 2** — the FastAPI/Starlette framework upgrade — the last open HIGH from the 2026-07-20 assessment. Scoped to the framework bump only.

### Security

- **H-2 (part 2) — FastAPI/Starlette upgraded, clearing the remaining Starlette DoS advisories.** `python-multipart` was fixed in v3.11.0, but the Starlette-side advisories (PYSEC-2026-1943/1941/249 multipart/form DoS, and the Host/path-validation items 161/248) required moving off FastAPI 0.111 and were scoped in `docs/fastapi-upgrade-plan.md` for a following release. This is that release: **FastAPI 0.111.0 → 0.139.2**, **Starlette 0.37.2 → 1.3.1** (pinned; the exact advisory-clearing floor), **slowapi 0.1.9 → 0.1.10**, and pydantic moves to 2.13.4 transitively. `pip-audit` now reports **no Starlette advisories**. `httpx` is deliberately held at 0.27.0 so the H-1 SSRF `sni_hostname` IP-pinning is undisturbed; `lxml` stays 5.2.1 (its one advisory is not reachable — deferred). slowapi 0.1.10 was confirmed to initialize and enforce rate limits on Starlette 1.3.1 before upgrading (the scoping doc's flagged blocker). Verified: full test suite green on the new stack, every endpoint reachable, the SSRF guard (H-1) battery still blocks, the three multipart upload endpoints and their DoS vectors handled by the new parser, security headers unchanged, rate limiting enforced on the live origin, and the abuse-send auth path (bcrypt + JSON-body credentials + structured-200) intact.

---

## [3.11.0] — 2026-07-20

Security release addressing the two HIGH findings from the 2026-07-20 assessment.

### Security

- **H-1 — DNS-rebinding TOCTOU in the SSRF guard fixed via IP-pinned connections.** `safe_fetch` previously resolved and validated a hostname, then handed the *hostname* back to httpx, which re-resolved it at connect time — a short-TTL attacker-controlled domain could rebind public→internal between the guard's check and httpx's connect. The guard now resolves the hostname **once** (`resolve_and_check`), validates every returned address, and opens the connection **directly to the validated IP** (httpx receives an IP-literal URL, so there is no second resolution to rebind), while preserving the original hostname for the TLS SNI/certificate check (`extensions={"sni_hostname": …}`) and the HTTP `Host` header (vhost routing). Redirect hops re-run the full resolve→validate→pin cycle (`follow_redirects=False`), IPv6 targets are bracketed and pinned, multiple validated IPs fail over on connection error, and the guard fails closed on any resolution/parse error. Reusable primitives `resolve_pinned()` / `pinned_request()` are the single source of truth; the URL Expander now routes its per-hop fetch through them and pins its TLS-cert probe to the same validated IP as the fetch. All existing `safe_fetch` callers (phishing scanner, RDAP abuse/domain-age lookups, urlscan enrichment) inherit the fix. Verified against the full SSRF fuzzing battery (all payloads blocked, in-process and over HTTP on staging), a specific DNS-rebinding test (connection pinned to the first validated IP; no connect-time re-resolution), and legitimate traffic (TLS validated against the hostname, CDN vhost routing, and a real multi-hop redirect chain).
- **H-2 (part 1) — `python-multipart` bumped to `>=0.0.31`** (resolves to 0.0.32), clearing the multipart-parser DoS advisories (PYSEC-2026-3038/3039/3040/3036/3037, 1851, 1852) that are reachable through the file-upload endpoints before route-handler size checks apply. `pip-audit` confirms the `python-multipart` advisories are cleared.
- **H-2 (part 2) — deferred by design.** The remaining Starlette DoS advisories (PYSEC-2026-1943/1941/249, plus the Host/path-validation items) require Starlette 0.40+/1.x, which means moving off FastAPI 0.111 — a framework upgrade with regression risk across every endpoint that does not belong in the same release as an SSRF-guard rewrite. It is scoped in `docs/fastapi-upgrade-plan.md` for a following release. Interim mitigations already in place: nginx `client_max_body_size`, request timeouts, and Cloudflare upload limits.

---

## [3.10.0] — 2026-07-20

### Added

- **Light / dark theme.** FalconEye now ships a proper light theme alongside the default dark one, toggled from a control in the header next to the branding. The whole UI (every tab, card, sub-card, input, button, table, and callout) is themed via CSS custom variables — the Tailwind color scales are remapped to `rgb(var(--x) / <alpha-value>)`, so a single `data-theme` switch retints everything and opacity modifiers keep working. The light theme is deliberately tuned for readability (not a naive inversion) and keeps the terminal/monospace aesthetic. Dark remains the default and is byte-for-byte unchanged, so existing users see nothing new until they toggle. The choice persists in an `fe_theme` cookie (no localStorage).
- **Per-tab privacy notes.** Sensitive-input tabs now carry a short, factual one-line note stating exactly where the input goes: Crypto (public blockchain APIs), IP Reputation (the five reputation APIs + Shodan/GreyNoise/RIPEstat/URLhaus), URL Expander (server-side fetch; IP recorded briefly for rate limiting), Username (~965 external platforms), QR (decoded in server memory, never written to disk), plus the existing Email Header note. Abuse cards note that reports (and PDFs) are composed in-browser, recipient addresses are redacted by default, and operator sends are audit-logged.

### Changed

- **Privacy policy brought current.** The in-app privacy policy now reflects what the tool actually does: the IP Reputation provider list adds AbuseIPDB, VirusTotal, AlienVault OTX, Censys, and ThreatFox; new rows cover Username Enumeration, URL Expander, and operator abuse-report sends via Mailgun; the abuse-send audit log (and exactly what it records) is documented; QR image handling and client-side PDF generation are covered; rate-limit IP collection is described accurately (Cloudflare `CF-Connecting-IP`, across all rate-limited tabs); and the `fe_theme` cookie is disclosed. "Last updated" is now 20 July 2026, with a 14-day "updated" indicator on the footer link.

---

## [3.9.1] — 2026-07-20

### Added

- **Client-side PDF export for the IP reputation report and abuse reports.** A shared, in-browser PDF builder (jsPDF, vendored locally under `/static/vendor/` — no CDN, satisfies the existing `self` CSP) drives both:
  - **IP report** — "Download Report" button on the IP tab. FalconEye branding, the IP, a UTC generation timestamp, the consensus verdict banner with reasoning, ASN/network/prefix, geolocation consensus (including the disagreement when disputed), a section per source (AbuseIPDB, VirusTotal, OTX, Censys, ThreatFox, GreyNoise, URLhaus), a merged open-ports table with source tags, and a footer listing the data sources queried.
  - **Abuse report** — "Download as PDF" button alongside Copy Report / Send on both the IP and Email Header abuse cards. The composed report exactly as previewed (subject, full body, evidence, signature), respecting the on-screen recipient-redaction default. Prose is proportional; the technical evidence block is monospace.
  - Everything runs in the browser — no server round-trip, nothing written server-side. Filenames: `falconeye-ip-report-{ip}-{date}.pdf` and `falconeye-abuse-report-{target}-{date}.pdf` (dots in the IP sanitized to dashes). A4 layout that also prints cleanly on Letter, with page breaks that never cut a line.

### Fixed

- **Disputed-geo header no longer leads with the least-supported country.** The IP card header previously rendered e.g. "Tehran · geo disputed (IR/LT/US/RS)", anchoring the reader on a single (often wrong) city. When sources disagree it now leads with "Location disputed (IR/LT/US/RS)" and drops the single-city lead entirely; undisputed geo is unchanged.

---

## [3.9.0] — 2026-07-20

Multi-source IP reputation: the IP tab now cross-references five threat-intel vendors, forms a consensus verdict, and stops asserting a single (often wrong) country.

### Added

- **Five reputation sources on the IP Reputation tab** — **AbuseIPDB** (abuse-confidence score, reports, categories), **VirusTotal** (multi-vendor detection ratio + flagged vendors), **AlienVault OTX** (community pulses + malware families), **Censys** (host services/ports), and **ThreatFox** (IOC matches). Each renders its own sub-card with an explicit ok / no-key / quota / error / not-found state, so one source failing never blanks the card or 500s the endpoint. All five are fetched concurrently (latency bounded by the slowest, not the sum) and cached per IP in the existing 6-hour window to conserve free-tier quotas.
- **Consensus verdict banner** (Clean / Suspicious / Malicious) at the top of the IP result, with reasoning (e.g. "Malicious: AbuseIPDB 100%, VirusTotal 7 vendors"). Thresholds are named constants.
- **Geolocation consensus.** Instead of asserting one country, the tab collects geo from every source (plus MaxMind and ASN registration) and, when they disagree, shows the disagreement (e.g. "Geo disputed: LT (AbuseIPDB, Censys), IR (VirusTotal, MaxMind), US (OTX), RS (ASN registration)"), with a caveat when the ASN is a hosting/VPS network where geo is unreliable.
- **Censys + Shodan port merge** — open ports are merged and deduplicated across both, each tagged with its source(s); "no open ports observed" only when *both* sources returned nothing, naming which were consulted.
- **`docs/ip-reputation-sources.md`** documenting each source, free-tier limit, signal, `.env` variable, verdict logic, and the geo-unreliability rationale.

### Changed

- **IP abuse-report evidence prefill** now includes the consensus verdict, AbuseIPDB score/reports, VirusTotal ratio/vendors, OTX pulses, ThreatFox matches, merged ports (with source tags), and the geo disagreement.
- New `app/ip_sources/` package (one normalized module per source + aggregate/verdict/geo/ports), wired into the existing `GET /api/ip/lookup/{ip}`. ThreatFox reuses the existing `ABUSECH_AUTH_KEY` (abuse.ch made it mandatory in 2024). No new runtime dependencies — all five use the existing `httpx`.

---

## [3.8.3] — 2026-07-20

### Fixed

- **Abuse reports now include the real email content and full headers.** Previously the report evidence was a thin summary (sender, auth results, a few hops) — the message's Subject, Message-ID, body, and linked URLs never made it in, so reports composed with older versions were materially useless; **regenerate any pending drafts.** Reports now carry the real `Subject` / `Message-ID` / `Date` / `Return-Path` / `Authentication-Results`, the **verbatim `Received` chain**, and a body excerpt (or the full body via an "Include full email body" checkbox); domain-registrar reports get the message's URLs instead of the body. Attachment filenames (content omitted) and body URLs are extracted too — URL extraction **refangs** defanged links (`hxxp`, `example[.]com`) and **decodes** base64 / quoted-printable bodies, and merges the server's decoded-body URLs, so an obfuscated phishing link is still surfaced. Both abuse cards render the identical structured block. The evidence is assembled **entirely client-side** from the raw email already in the browser and kept in an editable field for PII redaction — so `email_header.py` is unchanged, nothing new is persisted, and the Email Header tab's "never written to disk" guarantee stays intact (now locked by a regression test).

### Changed

- **Send via Mailgun is no longer rate-limited.** It is admin-authenticated and single-user, so the rate limit added no protection and only created debugging friction. Auth, the RDAP-recipient allowlist, and the append-only audit log all remain. The `abuse_send_rate_limit` table is left in place (no destructive migration) but is no longer written to or read. Compose (3/hour, 10/day per IP) and lookup (10/hour per IP) stay rate-limited as public-endpoint load protection.

### Docs

- Added "What makes an abuse report actionable" to `docs/abuse-reporting.md`, citing M3AAWG Sender Best Common Practices and Abuse Desk Common Practices.

---

## [3.8.2] — 2026-07-20

### Fixed

- **Inline comments in `.env` no longer break credential / API-key reads.** A trailing `# comment` on an env line — e.g. the `FALCONEYE_ABUSE_ADMIN_PASS_HASH` bcrypt hash — reached the consumer verbatim, because `os.getenv(...).strip()` and systemd's `EnvironmentFile` both leave inline comments in place. The 88-character result (hash + comment) failed `bcrypt.checkpw`, rejecting the correct admin password on Send via Mailgun. Env values are now read through `getenv_clean` (`app/utils/env.py`), which strips dotenv-style inline comments and surrounding quotes; applied across the abuse routes/send layer and `config.py`. This gap was latent since v3.7.1 and only surfaced once the v3.8.1 popup fix enabled the first real authenticated send — v3.8.1 did not introduce it. Full post-mortem in `docs/regressions.md`.

### Added

- **Operator rate-limit reset tool.** `python -m app.abuse.tools reset-rate-limit --ip <ip> [--endpoint compose|send|lookup|username|url|qr|dork|decoder|llm|all] [--dry-run]` clears one client IP's rate-limit counters across every rate-limit table (each stores the IP differently — `client_ip` / `source_ip` / `scope='ip:<ip>'`), printing the rows cleared per table. A blocked legitimate investigator, or the operator debugging, no longer needs hand-written SQLite `DELETE`s. Documented under "Operator troubleshooting" in `docs/abuse-reporting.md`.
- **`docs/regressions.md`** — a regression post-mortem log, opened with the v3.8.1 inline-comment entry.

---

## [3.8.1] — 2026-07-20

### Fixed

- **Duplicate authentication surface on Send via Mailgun.** The `/api/abuse/send` endpoint accepted HTTP Basic Auth *and* the abuse card rendered an in-page admin form for the same credential. The endpoint's `401` + `WWW-Authenticate` response could trip the browser's native Basic Auth dialog, which raced the in-page form and caused correct passwords to be rejected. Removed Basic Auth from the endpoint entirely — credentials now travel only in the JSON body (`admin_user`, `admin_password`), validated against the bcrypt hash by the in-page form's submit. The browser dialog can no longer appear under any circumstance.

### Changed

- **Auth mechanism for `/api/abuse/send`** moved from HTTP Basic Auth to JSON body fields. Security posture is unchanged: JSON body credentials over TLS are functionally equivalent to Basic Auth over TLS (both send the password in the request). Rate limits, the append-only audit log, the RDAP-recipient allowlist, and bcrypt validation are all preserved. The endpoint now always returns HTTP 200 with a structured `{sent, error, rate_limited}` body — never `401`, never `WWW-Authenticate` — guarded by a regression test.

---

## [3.8.0] — 2026-07-19

The first identity-oriented tab: turn a handle into a map of where else it appears.

### Added

- **Username Enumeration tab.** Checks where a username appears across ~950 platforms using vendored data from **WhatsMyName** (698 sites) and **Sherlock** (478 sites), merged and deduplicated by host. Dual-engine: a hit found by both engines is tagged **high confidence** (cross-validated), single-engine hits are **medium**. Quick Scan (priority 2-3, ~280 sites) and Full Scan (all sites) modes; adult platforms excluded by default with an opt-in toggle. Results are grouped into collapsible categories (Social, Developer, Gaming, Forum, Regional, Adult, Other) with source badges, CSV export, a copy-handle button, and a one-click Telegram pivot.
- **Vendored dual-engine data pipeline.** WhatsMyName and Sherlock JSON data files vendored under `app/data/` (both MIT-licensed, no runtime dependency on either project's code). Refresh script at `scripts/refresh_username_data.py` fetches upstream and validates schema; run manually at release cadence (suggested every 4-6 weeks).
- **Backend package `app/username/`** — parser (adapters + category/NSFW/priority tagging + cross-engine merge), async checker (concurrency-capped sweep, per-detection-type logic), merger, self-initializing rate-limit store, and router (`POST /api/username/scan`, `GET /api/username/meta`).

### Security

- **Strict username validation** (`^[A-Za-z0-9._-]{1,40}$`) rejected at the router before any check runs, plus `urllib.parse.quote` on every substituted URL template. Every outbound check is validated with the existing `app/utils/safe_fetch` SSRF primitive (`resolve_and_check`) — **no second SSRF guard** — with per-host verdicts cached and a bounded DNS phase.
- **Rate limits as load protection:** a single scan makes 280-950 outbound requests, so scans are capped at 3 per client IP per hour, 20 per day, and 100 globally per day, enforced *before* any async work is spawned. The whole scan runs under one wall-clock budget so a request can never exceed the gunicorn worker timeout (Full scans return partial results with a warning rather than running long).

### Changed

- New Username tab in the nav between Contact and News; `main.py`, `/health`, and JSON-LD `softwareVersion` bumped to 3.8.0; README module count updated to seventeen.
- No new Python dependency: both data files are JSON, so PyYAML was not needed.

### Operator notes

False positives run 5-10% because some platforms return the same response for any username; hits are surfaced as leads for human verification, not proof of identity. See `docs/username-enumeration.md` for confidence tiers, the data-refresh procedure, and ethical-use guidance.

---

## [3.7.1] — 2026-07-19

UX clarification for the abuse report card on the IP Reputation and Email Header tabs.

### Changed

- **Abuse card now leads with a prominent banner** explaining that Copy is the intended path: FalconEye composes the report, you Preview it, Copy it, and send it from your own email so the provider can reply directly to you. The Send button is framed as operator-only.
- **Buttons relabeled and re-weighted.** "Copy to Clipboard" → **"Copy Report (send from your email)"** and is now the primary (amber) action; "Send via Mailgun" → **"Send via Mailgun (operator only)"** and is now the secondary (muted) action. Preview stays. This reverses the earlier visual hierarchy that made Send look like the primary action.

### Notes

The Send button remains visible to everyone; clicking it triggers admin HTTP Basic Auth, which non-operators cannot pass. No backend or endpoint behavior changed in this release.

---

## [3.7.0] — 2026-07-19

Turn identification into action: both the IP Reputation and Email Header tabs can now compose an abuse report to the responsible provider, prefilled from what FalconEye already knows.

### Added

- **Abuse report composition on the IP Reputation tab.** After an IP lookup, FalconEye resolves the hosting provider's abuse-c contact via RDAP (`rdap.org` → RIR), prefills a category-appropriate report (phishing, spam, BEC, malware, brute-force, scanning, DDoS, crypto fraud, other) with the observed network, reverse DNS, and reputation signals, and offers **Copy to Clipboard**.
- **Abuse report composition on the Email Header tab.** After a header analysis, FalconEye surfaces up to two abuse contacts — the sending IP's hoster (RDAP on the originating `Received` hop) and the sender domain's registrar (RDAP on the `From:` domain) — each with its own prefilled report. The recipient address from the analyzed email is redacted from the evidence by default.
- **RDAP-based abuse contact lookup service** (`POST /api/abuse/lookup`) with a 24-hour SQLite cache to reduce load on RDAP endpoints. Extracted abuse emails are validated against a strict regex before display.
- **Report composition service** (`POST /api/abuse/compose`) that renders reports from a shared template. Reporter identity comes from `FALCONEYE_REPORTER_NAME` / `FALCONEYE_REPORTER_EMAIL` (env, never user-supplied); the endpoint returns 503 if they are unset.
- **Optional Mailgun send** (`POST /api/abuse/send`) for operators with Mailgun credentials. Gated behind HTTP Basic Auth (bcrypt), enforces per-IP (3/hour, 10/day), per-recipient (1/hour), and global (100/day) rate limits, refuses any recipient not previously returned by an RDAP lookup, and writes an append-only audit row per send (never the report body). `GET /api/abuse/send_available` drives the UI so the Send button only appears when the server is configured for it.

### Security

- **Email header injection** is neutralized in the composition layer: CR/LF/NUL are stripped from every single-line field (target, category, reporter identity, timestamp) and normalized in the multi-line evidence field (capped at 8000 chars), with a warning surfaced whenever an input was altered. The send layer re-strips defensively before calling Mailgun.
- **RDAP is treated as untrusted input** — abuse emails are strictly validated, and the fetch goes through the existing `app/utils/safe_fetch` SSRF primitive (every redirect hop re-validated); **no second SSRF guard was introduced.** Non-public IPs short-circuit before any network call.
- **Send is defense-in-depth gated**: admin Basic Auth *plus* the RDAP-recipient allowlist means valid credentials still cannot be used to mail an arbitrary address. The Mailgun API key is read from the environment at call time and never logged, never returned, and never interpolated into an error string.

### Changed

- New abuse package `app/abuse/` (lookup, compose, send, store, routes) registered in `app/main.py`; five new SQLite tables self-initialize (`abuse_contact_cache`, three rate-limit tables, `abuse_send_audit`), mirroring the existing per-router table pattern.
- FastAPI app metadata and `/health` bumped to 3.7.0; JSON-LD `softwareVersion` bumped to 3.7.0 with an abuse-reporting `featureList` entry.
- Added `bcrypt` to `requirements.txt` (admin auth for the send endpoint).

### Operator notes

Compose and Copy work with **no configuration**. Send via Mailgun requires `FALCONEYE_REPORTER_NAME`, `FALCONEYE_REPORTER_EMAIL`, `MAILGUN_API_KEY`, `MAILGUN_DOMAIN`, `MAILGUN_REGION`, `MAILGUN_FROM`, `FALCONEYE_ABUSE_ADMIN_USER`, and `FALCONEYE_ABUSE_ADMIN_PASS_HASH`. The domain part of `MAILGUN_FROM` must exactly match `MAILGUN_DOMAIN`, and `MAILGUN_REGION` must be a bare `us`/`eu` value (systemd does not strip inline `#` comments). See `docs/abuse-reporting.md` for the full setup guide and current Mailgun free-tier state.

---

## [3.6.0] — 2026-07-17

Two new tabs for the same investigative flow: figure out where a suspicious link actually goes before touching it.

### Added

- **URL Expander + Redirect Chain Analyzer (`/api/url/expand`).** Paste a short URL and get the full redirect chain hop-by-hop with status codes, TLS certificate details per HTTPS hop, server headers, and elapsed time. Detects a meta-refresh redirect in HTML bodies (one hop deep). Computes shortener-chain depth against a curated list of 21 shorteners, and flags TLD switches, punycode hostnames, and non-standard ports. One-click pivot pushes the final URL into the Phishing Scanner.
- **QR Code Analyzer (`/api/qr/decode`).** Upload a QR image or paste a base64 data URI. Decodes multiple QR codes per image with pyzbar and categorizes decoded content by scheme: HTTP(S), Bitcoin, Ethereum, UPI, WiFi, sms, tel, geo, or plain text. Images are processed in memory and never persisted (5 MB cap). Decoded URLs pivot into the URL Expander with one click.

### Security

- The URL Expander reuses the existing `app/utils/safe_fetch` SSRF primitives (`resolve_and_check` / `is_private_ip`) — **no second SSRF implementation was introduced.** Every redirect hop and each per-hop TLS grab are re-validated against private/loopback/link-local/reserved/multicast/CGNAT/NAT64/IPv4-mapped ranges; embedded userinfo and non-`http(s)` schemes are rejected. The QR endpoint never fetches a URL — it only decodes.

### Changed

- Two new per-IP daily rate-limit tables (`url_expand_rate_limit`, `qr_decode_rate_limit`), 10 requests per client IP per 24 hours each, keyed on `CF-Connecting-IP`, mirroring the existing `dork_gen_rate_limit` pattern.
- FastAPI app metadata and `/health` bumped to 3.6.0; JSON-LD `softwareVersion` bumped to 3.6.0; README module count updated to sixteen.
- Added `pyzbar` and `qrcode[pil]` to `requirements.txt`; the `libzbar0` system package is now required (pyzbar's native dependency).

### Operator notes

Requires the `libzbar0` system package (`apt-get install -y libzbar0`) for pyzbar. **Playwright is intentionally not installed in this release** — the URL Expander skips the final-page screenshot and returns the chain as normal (the screenshot panel shows an "unavailable" note). A hardened, private-range-blocking browser capture is deferred to a later release.

---

## [3.5.2] — 2026-07-17

CSP hotfix — restores the Crypto Investigation Workbench transaction graph, which the v3.5.0 CSP `script-src` allowlist broke by omitting the D3 CDN.

### Fixed

- **Crypto Investigation Workbench D3 graph render.** The nginx CSP `script-src` allowlist added in v3.5.0 did not include `cdnjs.cloudflare.com`, the CDN serving `d3/7.9.0/d3.min.js`. The browser silently blocked D3 and the frontend surfaced the resulting `ReferenceError` as "Request failed: d3 is not defined" once a wallet lookup completed. The transaction timeline still rendered because it is plain HTML with no D3 dependency. Added `https://cdnjs.cloudflare.com` to `script-src` in `nginx/falconeye.conf` and mirrored the change to the live `/etc/nginx/sites-available/falconeye` config on the VPS. `style-src` was intentionally not widened. No frontend code changes.

---

## [3.5.1] — 2026-07-05

Phishing scanner detection improvements. Four independently-committed features that close the detection gap surfaced by `gobpi.cc/cancel/6t2w8y4b` returning zero indicators.

### Features

- **Phishing scanner: PH banking impersonation indicators.** New module `app/scanner/ph_bank_indicators.py` with 35 indicators across four groups: URL path patterns (`/cancel/`, `/verify/`, `/suspended/`, `/reactivate/`, `/otp/`), domain impersonation patterns (`gobpi*`, `bpiverify*`, `bdo-online*`, `gcash-verify*`, `maya-cancel*`, `paymaya-*`, `unionbank-verify*`, `metrobank-verify*`, `landbank-ph*`, `dbp-online*`), HTML content signals (OTP/TIN/CVV/PIN input fields, BPI/BDO/GCash/Maya brand text, PHP capture endpoints), and HTML structure signals (hidden `bank_name`/`target_bank`/`account_type` fields). 33 unit tests.

- **Phishing scanner: Cloudflare challenge page detection.** `app/scanner/cloudflare_detect.py` returns a `cloudflare_bot_protection` medium-severity indicator when the fetched HTML matches Cloudflare challenge/block page signals ("Attention Required! | Cloudflare", "Just a moment", "cf-browser-verification", "Cloudflare Ray ID", etc.). Phishing infra behind Cloudflare Tunnel/Workers routinely blocks automated scanners to prevent takedown — this is a meaningful signal for the analyst. 10 unit tests.

- **Phishing scanner: urlscan.io lookup enrichment.** `app/utils/urlscan.py` queries the urlscan.io search API for the most recent scan of the target domain. Result returned as `urlscan` key in the scanner response alongside FalconEye's own indicator verdict — the two verdicts are kept separate and neither overwrites the other. Free tier works without an API key; set `URLSCAN_API_KEY` to raise the rate limit. 12 unit tests.

- **Phishing scanner: domain age check.** `app/utils/domain_age.py` queries RDAP (rdap.org) for the domain registration date, with whois subprocess fallback. Returns `{found, created_at, age_days, source, error}`. Fires `dom_age_recent` (HIGH if ≤ 7 days, MEDIUM if 8–30 days) or `dom_age_moderate` (LOW if 31–90 days). No indicator fires on lookup failure — no false positives from unavailable registries. Results cached 24 hours in new `domain_age_cache` table. whois parser collects all creation-date candidates and returns the most recent, preventing multi-section whois output (TLD registry preamble + registrar section) from returning the TLD birth year instead of the domain registration date. urlscan and domain_age run in parallel via `asyncio.gather`. Result exposed under `domain_age` key. 35 unit tests.

### Regression test — gobpi.cc/cancel/6t2w8y4b

Before: `indicators_matched: 0`. After:

```
[HIGH  ] dom_age_recent            Domain registered 4 days ago on 2026-06-30
[HIGH  ] dom_gobpi                 gobpi* domain — known BPI impersonation TLD family
[MEDIUM] ph_path_cancel            Suspicious /cancel/ path — common in PH banking phish flows
[MEDIUM] cloudflare_bot_protection Target is behind Cloudflare bot protection
```

### Added

- `app/scanner/__init__.py`
- `app/scanner/ph_bank_indicators.py` — 35 static indicators + `match_ph_indicators()` + `match_age_indicators()`
- `app/scanner/cloudflare_detect.py` — Cloudflare challenge page detection
- `app/utils/urlscan.py` — urlscan.io enrichment
- `app/utils/domain_age.py` — RDAP + whois domain age lookup with 24h cache
- `tests/unit/test_ph_bank_indicators.py` (33 tests)
- `tests/unit/test_cloudflare_detection.py` (10 tests)
- `tests/unit/test_urlscan.py` (12 tests)
- `tests/unit/test_domain_age.py` (20 tests)
- `tests/unit/test_domain_age_indicators.py` (15 tests)

### Changed

- `app/routers/scanner.py` — chains all four new detection passes; `asyncio.gather` for urlscan + domain_age; adds `urlscan` and `domain_age` keys to response
- `app/config.py` — added `URLSCAN_API_KEY`
- `.env.example` — `URLSCAN_API_KEY` documented (optional, commented)
- `scripts/db_init.py` — `domain_age_cache` table added

---

## [3.5.0] — 2026-07-05

Security remediation release. All findings from the Fable 5 automated security review (SECURITY_REVIEW_FABLE.md) are closed except the prompt injection structural risk (M-4 note) and the `script-src 'unsafe-inline'` CSP item (M-5 note), both of which require frontend refactoring and are documented as follow-on work.

### Security

- **H-1 — SSRF in Phishing Scanner closed.** `safe_fetch` in `app/utils/safe_fetch.py` replaces the raw `httpx.AsyncClient` in `scanner.py`. Every hop in a redirect chain is independently resolved and validated against the SSRF blocklist before the request is made (`follow_redirects=False` on the underlying client). The blocklist uses Python `ipaddress` stdlib flags (`is_private`, `is_loopback`, `is_link_local`, `is_reserved`, `is_multicast`, `is_unspecified`) plus explicit blocks for CGNAT (100.64.0.0/10), NAT64 (64:ff9b::/96), and 0.0.0.0/8. IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) are unwrapped before checking. TLS certificate verification is enforced (`verify=True`).

- **H-2 / M-2 / M-3 — DOM XSS in Telegram, RDAP, and RSS render paths closed.** All attacker-controlled fields (`title`, `username`, `description`, `photo_url`, `forwarded_from` in Telegram; registrar/registrant/nameserver/status in RDAP; `title`, `url`, `feed_source`, `summary` in RSS; `loadThreatPulse` and `loadLandingNews` widget fields) are now passed through `escapeHtml()` and `escapeAttr()` before any DOM insertion. JavaScript and `data:` URIs are rejected in URL fields.

- **M-1 — Rate limiting keyed on real client IP.** All per-IP limits — including the three LLM cost-control tables (10 calls/IP/24h) and the phishing scanner limit — are now keyed on `CF-Connecting-IP`, which Cloudflare sets and nginx preserves. The fallback for local development (no header present) is `request.client.host`. The key function is centralised in `app/utils/client_ip.py`.

- **M-4 — LLM JSON output validated and clamped.** `app/utils/llm_response.py` provides `parse_llm_json`, `clamp_int`, `safe_str`, and `validate_findings_list`. In `email_header.py`, `scam_score` is type-coerced and clamped to [0, 100], the `findings` list is filtered to known dict keys, and string fields (verdict, scam_type, summary) are truncated. In `script_decoder.py`, `severity` and `intent` are validated against their enum sets and reset to `"unclear"` on mismatch. In `dork_generator.py`, the `dorks` list structure and `risk_level` enum are validated. LLM output sections are labelled as model opinions (`llm_note`, `_llm_source_note`), not verified verdicts.

- **M-5 — Security response headers at nginx.** Added to the HTTPS server block in `nginx/falconeye.conf`: `Content-Security-Policy` (with `frame-ancestors 'none'`), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and `Strict-Transport-Security` (max-age 1 year, includeSubDomains). Note: `script-src 'unsafe-inline'` is retained until the frontend's inline `onclick` handlers are refactored to `addEventListener` bindings.

- **L-1 — SSRF blocklist completeness verified.** All six ranges from the Fable L-1 finding are confirmed covered: 0.0.0.0/8 (stdlib `is_private` + explicit), 100.64.0.0/10 CGNAT (explicit), ::ffff:a.b.c.d mapped IPv6 (unwrap before check), fe80::/10 link-local (stdlib `is_link_local`), 64:ff9b::/96 NAT64 (explicit), ::/128 unspecified (stdlib `is_unspecified`). Documented inline in `safe_fetch.py`.

- **L-2 — TLS verification enforced.** `verify=False` is absent from the entire `app/` tree. `safe_fetch` sets `verify=True` explicitly. All other outbound clients inherit httpx's default of `True`.

- **L-3 — Image search URL validation.** The `image_url` parameter to `/api/image/search` is now validated with `validate_url` before being forwarded to SearchAPI. Rate limiting on the image search endpoint is keyed on the real client IP (`CF-Connecting-IP`) rather than the Cloudflare edge IP.

- **L-4 — Upstream error strings scrubbed.** `crypto.py` (3 exception handlers), `telegram_inspector.py` (1 handler), and `safe_fetch.py` (resolved-IP oracle) no longer echo `str(e)` or internal addresses to HTTP responses. Exceptions are logged server-side with `log.exception` (full traceback); clients receive generic messages only.

- **L-5 — Regex compute cap on email body.** `_analyze_body` in `email_header.py` truncates `text_only` to `REGEX_MAX_BODY_BYTES` (100 KB, configurable in `app/config.py`) before running the ~50 `SCAM_PATTERNS` regexes. The LLM pass is unchanged; it has its own token accounting. The API response exposes `body_regex_truncated: bool` so analysts know when a scan was partial.

- **Rate-limit INSERT error handling.** Errors in rate-limit `INSERT` functions are now logged and swallowed instead of propagating as HTTP 500.

### Added

- `app/utils/safe_fetch.py` — SSRF-safe fetcher with per-hop blocklist revalidation
- `app/utils/llm_response.py` — LLM JSON validation helpers (parse, clamp, truncate, filter)
- `app/utils/client_ip.py` — Centralised `CF-Connecting-IP` extraction
- `tests/unit/test_safe_fetch.py` — 18 unit tests for SSRF guard
- `tests/unit/test_llm_response.py` — 23 unit tests for LLM response helpers
- `tests/unit/test_client_ip.py` — Unit tests for IP extraction

### Changed

- `nginx/falconeye.conf` — Added five security headers
- `app/routers/scanner.py` — Replaced validate_url + raw httpx with safe_fetch
- `app/routers/email_header.py` — LLM merge uses validated helpers; regex body cap applied
- `app/routers/script_decoder.py` — LLM output validated before return
- `app/routers/dork_generator.py` — LLM output validated before return
- `app/routers/crypto.py` — Exception handlers log and return generic messages
- `app/routers/telegram_inspector.py` — Exception handler returns generic message
- `app/config.py` — Added `REGEX_MAX_BODY_BYTES = 100_000`
- `app/main.py` — Version bumped to 3.5.0
- `README.md` — Rewritten; install paths, security posture, and version corrected
- `.env.example` — Fixed `DB_PATH` key name to `FALCONEYE_DB`; added `FALCONEYE_DATA_DIR`

### Removed

- Direct `httpx.AsyncClient(follow_redirects=True, verify=False)` call in scanner.py

---

## [3.4.0] — 2026-06-01

### Added

- **Image Search tab** — Reverse image search via Google Lens and Yandex in parallel. Accepts a URL or uploaded file (JPEG/PNG/WebP/GIF, max 10 MB). Displays visual match grids, Yandex image size table, cross-source domain corroboration, and EXIF data for uploads. Results cached 24 hours in Redis. Requires SearchAPI.io key.
- HMAC-signed, expiring temporary image URLs (SHA256 + timestamp, 5-minute TTL, `hmac.compare_digest`)
- Magic-byte MIME sniffing on upload (not just extension)
- Image Search endpoints: `/api/image/search`, `/api/image/upload`, `/api/image/temp/{token}`

### Changed

- Rate limiting on image search URL input keyed on real client IP (fixed in 3.5.0 security batch)

---

## [3.3.x] — 2026-05

### Added (3.3.2)

- Meta page identity filtering with fuzzy threshold
- Multi-advertiser tabs and top ads table in Prospect
- hp.com identity fix in company resolver

### Added (3.3.1)

- Company identity resolver
- Query disambiguation
- Result validation layer

### Added (3.3.0)

- Prospect / Company tab — 6 search engines, investigation log, hiring/news/timeline cards

---

## [3.2.0] — 2026-04

### Added

- Prospect tab — commercial intelligence dossier via SearchAPI.io, 6-hour Redis cache

---

## [3.1.0] — 2026-03

### Added

- Script Decoder tab (Claude Haiku 4.5)
- Contact tab
- Google Dork Generator tab (Claude Haiku 4.5)
- Privacy policy modal
- .eml / .msg file upload for Email Header Analyzer

---

## [3.0.0] — 2025

### Added

- FalconEye v3 full rebuild: Crypto Workbench, Phishing Scanner, Domain Intelligence, Telegram Inspector, IP Reputation, Sandbox History, Email Header Analyzer with LLM body analysis, curated cyber news
- FastAPI + Gunicorn + SQLite backend
- Cloudflare + nginx deployment architecture
