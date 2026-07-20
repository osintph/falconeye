# FastAPI / Starlette upgrade plan (H-2 part 2)

**Status:** scoped, NOT executed. Deferred out of v3.11.0 by design — a framework
upgrade with regression risk across every endpoint must not ride in the same
release as the SSRF-guard rewrite (H-1), so that a regression can be isolated to
one change. This becomes its own release after v3.11.0.

## Why

`pip-audit` reports DoS advisories in the pinned Starlette that FastAPI 0.111.0
brings in transitively. `python-multipart` was already bumped in v3.11.0 (H-2
part 1); the Starlette items remain because their fixes require Starlette
0.40+/1.x, which is not compatible with FastAPI 0.111.

Remaining advisories (from `pip-audit -r requirements.txt`):

| Package | Installed | Advisory | Fixed in | Class |
|---|---|---|---|---|
| starlette | 0.37.2 | PYSEC-2026-1943 | 0.40.0 | multipart: non-filename parts buffered in memory (DoS) |
| starlette | 0.37.2 | PYSEC-2026-1941 | 0.47.2 | multipart: large-file spool DoS |
| starlette | 0.37.2 | PYSEC-2026-249  | 1.3.1 | `request.form` `max_fields`/`max_part_size` handling |
| starlette | 0.37.2 | PYSEC-2026-248  | 1.3.0 | request path not validated before `request.url` reconstruction |
| starlette | 0.37.2 | PYSEC-2026-161  | 1.0.1 | Host header not validated before `request.url` reconstruction |
| starlette | 0.37.2 | PYSEC-2026-2280/2281 | 1.1.0 | StaticFiles / HTTPEndpoint (SSRF is Windows-only; we run Linux) |
| lxml | 5.2.1 | PYSEC-2026-87 | 6.1.0 | XML entity expansion (NOT reachable — see note) |

To clear **all** Starlette advisories the floor is **Starlette >= 1.3.1**.

## Current pinned versions (as of v3.11.0)

- `fastapi==0.111.0`
- `starlette==0.37.2` (transitive via FastAPI)
- `uvicorn[standard]==0.29.0`
- `gunicorn==22.0.0`
- `pydantic` 2.x (via FastAPI 0.111; app already uses Pydantic v2 models)
- `slowapi==0.1.9` (depends on Starlette internals + `limits`)
- `python-multipart>=0.0.31` (already bumped)
- `lxml==5.2.1` (only used via `bs4` HTML parser — advisory not reachable)

## Target versions

- **`starlette>=1.3.1`** (mandatory floor to clear every Starlette advisory).
- **`fastapi`**: the latest release whose dependency pin permits `starlette>=1.3.1`.
  Confirm the exact minimum at execution time against the FastAPI release notes /
  compatibility matrix (FastAPI adopted Starlette 0.40+ in the 0.115 line; Starlette
  1.x support lands in a later FastAPI — pin to that release, do not float).
- **`uvicorn`**: bump to current stable alongside (ASGI-compatible; low risk).
- **`slowapi`**: verify against the target Starlette. slowapi 0.1.9 reaches into
  Starlette request/response internals; if it is incompatible with Starlette 1.x,
  bump slowapi (or its `limits` dependency) to a compatible release, or pin the
  Starlette version slowapi supports and re-evaluate. **This is the single most
  likely blocker** and must be validated before committing to a Starlette 1.x target.
- Also fold in `lxml>=6.1.0` (hygiene; not reachable today) while touching deps.
- Consider `gunicorn` current stable at the same time (not advisory-driven here).

## Known breaking changes to check (FastAPI 0.111 → target, Starlette 0.37 → 1.x)

1. **Multipart form parsing.** Starlette 0.40+ enforces `max_part_size` (default
   1 MB per field) and changed spooling for large files. The three upload endpoints
   (`/api/qr/decode`, `/api/email-header/upload`, `/api/image/upload`) read the file
   with `await file.read()` and then apply their own 5 MB / 10 MB caps — confirm the
   new per-part default does not reject legitimate uploads below those caps, and that
   `UploadFile.read()` semantics (SpooledTemporaryFile threshold) are unchanged for
   our sizes. `qr_analyzer.decode` also branches on `await request.json()` when no
   file is present — verify the JSON branch is unaffected.
2. **`request.url` / Host reconstruction.** The advisories change how Starlette
   validates the Host header and path. We derive the client IP from
   `CF-Connecting-IP` (not `request.url`), so low risk — but audit any use of
   `request.url` / `request.base_url` for absolute-URL construction.
3. **Deprecated `@app.on_event`.** Not used (verified: no `on_event`/lifespan in the
   codebase; routers self-initialize their SQLite tables at import). No migration
   needed, but keep it that way (don't add `on_event` during the upgrade).
4. **Exception handlers.** `app.add_exception_handler(RateLimitExceeded, …)` — confirm
   the slowapi handler signature still matches Starlette's expected
   `(Request, exc) -> Response`.
5. **`StaticFiles` mount** (`/static`). Behavior stable on Linux; the SSRF advisory is
   Windows-only. Smoke-test static asset serving after the bump.
6. **Pydantic.** Already v2 — no v1→v2 migration. Still, re-run all request-model
   validation tests (every router defines `BaseModel` request bodies).
7. **`TestClient`.** Not used in the test suite (tests call functions directly or use
   `httpx`), so Starlette's TestClient changes don't affect CI — but if any smoke
   harness adopts it, note httpx-based `TestClient` differences.

## Affected surface (must be regression-tested)

- **All 17 included routers** (`app/main.py`): crypto, scanner, news, domain_intel,
  telegram_inspector, ip_intel, sandbox, threat_pulse, email_header, dork_generator,
  script_decoder, url_expander, qr_analyzer, prospect, image_search, abuse, username.
- **slowapi rate limiting** on 14 routers + `app/main.py` (every `@limiter.limit(...)`
  decorator and the shared `Limiter(key_func=get_client_ip_key)`).
- **The three multipart upload endpoints** (highest risk from the parser changes).
- **`CF-Connecting-IP` client-IP extraction** (`app/utils/client_ip.py`) and the
  per-IP SQLite rate-limit tables keyed on it.
- **StaticFiles** mount and the security headers applied at nginx (unchanged by the
  Python upgrade, but re-verify the response header set after deploy).
- **The H-1 SSRF guard** — re-run its full battery + rebinding test to confirm the
  upgrade did not change httpx/transport behavior underlying `pinned_request`.

## Test plan

1. `pip-audit -r requirements.txt` → confirm **zero** Starlette advisories remain
   (and python-multipart/lxml clear).
2. Full `pytest` suite green (including the H-1 pinning/rebind tests in
   `tests/unit/test_safe_fetch.py` and all upload-endpoint tests).
3. Upload-endpoint matrix per endpoint: valid small file, file at the cap, file over
   the cap (expect the endpoint's own 413/400, not an opaque 500), malformed
   multipart, many-small-parts (the DoS shape — confirm bounded), and the JSON/data-URI
   branch for QR.
4. Rate-limit behavior unchanged: per-IP hour/day caps and slowapi burst limits still
   fire (spot-check username `/scan`, url `/expand`, abuse `/lookup`).
5. SSRF regression: full battery over HTTP on staging (as in v3.11.0) + the
   DNS-rebinding test.
6. Smoke every tab manually on staging; confirm the security-header set
   (CSP/HSTS/X-Frame/etc.) is byte-for-byte unchanged.
7. Staging soak before production; deploy off-peak with a rollback pin ready
   (`fastapi==0.111.0`, `starlette==0.37.2`) in case slowapi or a router regresses.

## Interim mitigation (already in place, documented for the record)

Until this upgrade ships, the Starlette multipart DoS is blunted (not eliminated) by:
nginx `client_max_body_size` and request timeouts, Cloudflare upload-size limits in
front of the origin, and the per-IP daily caps on the upload endpoints. These do not
remove the advisory (the parser runs before the handler's size check), so the upgrade
remains required — just not in the same release as H-1.
