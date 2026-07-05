# Changelog

All notable changes to FalconEye are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
