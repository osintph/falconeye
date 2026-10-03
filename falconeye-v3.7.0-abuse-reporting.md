# FalconEye v3.7.0 — Abuse Reporting on IP and Email Header tabs

## Context

Two tabs already exist that end with a piece of hostile infrastructure identified: the IP Reputation tab lands on a scanning or brute-forcing IP, and the Email Header analyzer lands on a spam or BEC sending IP plus sender domain. Nothing in FalconEye converts that identification into action. Investigators copy the IP, look up the ASN's abuse contact in a separate tool, hand-write an abuse report, and paste it into their mail client. That workflow is exactly the kind of friction a workbench is supposed to eliminate.

v3.7.0 adds abuse report composition to both tabs. Given an IP or a parsed email header, FalconEye looks up the correct abuse contact via RDAP, composes a report from a category-appropriate template, prefills the evidence section from what FalconEye already knows, and offers two actions: **copy to clipboard** (always available, no auth) and **send via Mailgun** (admin-authenticated only).

Mailgun integration is opt-in and gated. The public UI can only compose and copy. Sending requires HTTP Basic Auth so Sigmund can trigger sends from his own browser but public users cannot.

## Scope

- Two backend services: abuse contact lookup (RDAP-based) and report composition (template rendering with sanitization)
- One optional backend service: Mailgun sender with rate limits and audit log
- Additions to two existing tabs (IP Reputation, Email Header), no new tabs
- New environment variables for reporter identity and optional Mailgun credentials
- New docs page explaining the Mailgun setup and free-tier state
- Version bump to 3.7.0

## Files that will be touched

### New
- `app/services/abuse_lookup.py` (RDAP abuse contact resolution)
- `app/services/abuse_compose.py` (template rendering, sanitization)
- `app/services/abuse_send.py` (Mailgun client, audit log)
- `app/routers/abuse.py` (three endpoints)
- `app/templates/abuse_reports/` (plain text templates per category)
- `docs/abuse-reporting.md` (operator documentation)

### Modified
- `app/main.py` (register router, version bump)
- `app/db.py` (three new tables: rate limit, audit log, abuse recipients cache)
- `app/static/index.html` (additions to IP and Email Header panels, version bump in JSON-LD)
- `app/routers/ip_reputation.py` (surface abuse-c contact in existing response, no behavioral change)
- `app/routers/email_header.py` (same)
- `requirements.txt` (httpx already present; may need `dnspython` if not already installed for MX lookups)
- `README.md` (feature note, current version)
- `CHANGELOG.md` (v3.7.0 entry)
- `.env.example` (new env vars documented)

## MANUAL PREREQUISITES — Sigmund, do these before or during Claude Code's work

These are things Claude Code cannot do for you. Complete them and have the values ready when Claude Code reaches Part E.

### M1. Verify Mailgun account state

Your memory notes say your prior Mailgun account was closed and you migrated newsletters to Ghosler. Confirm current state:

1. Log into https://app.mailgun.com/
2. Check the account status (active, suspended, closed)
3. If closed or suspended, either reactivate or open a new account. Mailgun's current free-tier state as of 2026 is uncertain; historically it was 10K emails/month, later replaced with a pay-as-you-go "Flex" plan. Claude Code will web-search the current state when writing the docs, but you need to know what your own plan allows.
4. Verify your sending domain `osintph.net` is still verified in the Mailgun dashboard (Sending > Domains). If it is not, re-verify by adding the DNS records Mailgun shows and waiting for propagation.
5. Note whether your Mailgun account is on the US or EU region (dashboard header shows this). The API endpoint differs: `api.mailgun.net` (US) vs `api.eu.mailgun.net` (EU).

### M2. Generate a Mailgun API key

1. In the Mailgun dashboard, go to Send > Sending > Domain settings > `osintph.net` > API keys
2. Create a new **Sending API key** (not the master key). Scope it to sending only.
3. Copy the key value. It looks like a UUID or a base64 string depending on when Mailgun issued it.
4. Store it somewhere safe. You will paste it into the `.env` file on the VPS during Part B4.

### M3. Choose a reporter identity

Every abuse report needs a real reporter name and reply-to email. Abuse desks ignore anonymous reports. Decide:

- **Reporter name**: e.g. `Sigmund Brandstaetter, OSINT-PH`
- **Reporter email (reply-to)**: e.g. `abuse-reports@osintph.net`. This must be an address you actually check because abuse desks reply to it.
- **From address**: the Mailgun-verified sending address, e.g. `abuse-reports@osintph.net` (same as reply-to for simplicity) or `noreply@osintph.net`. Must be at `osintph.net` since that is your verified sending domain.

### M4. Choose an admin password for Mailgun send

The "Send via Mailgun" button will be gated by HTTP Basic Auth. Public users see the button grayed out; you enter credentials when you click it. Choose a strong password now. Suggested username: `admin`. Password: generate a long random string and store it in your password manager.

Do NOT reuse your Mailgun API key as the password. These are two different secrets.

### M5. Confirm you want the send-via-Mailgun feature at all

Option A (safer, simpler): **compose and copy only**. FalconEye composes the report, shows it, offers Copy to Clipboard. You paste into your own mail client and send from there. No Mailgun code paths executed, no auth surface, no rate limits to tune, no audit log to babysit.

Option B (what you asked for): **compose plus optional send**. Public users get compose and copy. You (authenticated via Basic Auth) get an additional Send button that hits Mailgun.

Both options ship the same abuse contact lookup and report composition. Only the send layer differs.

**Recommendation: Option A** for v3.7.0, defer Option B to v3.7.1 once the compose flow proves out in real casework. Reason: sending emails from a real domain via a public web UI is a legitimate abuse vector, and rate limits alone are not always enough. Getting the compose flow right and dogfooding it for two weeks in Copy mode will reveal edge cases before you point Mailgun credentials at it.

**If you agree with Option A**, tell Claude Code to skip Part B4 and Part C3 (send button in UI). Documentation still mentions Mailgun as a planned v3.7.1 feature.

**If you want Option B directly**, Claude Code implements the full plan below.

## Cautionary notes

- **Sender identity risk.** Sending emails from your real domain via a public web UI is a legitimate abuse vector even with rate limits. Basic Auth on the send endpoint is the minimum bar, not a complete answer.
- **Email header injection.** All user-editable fields (subject, body, evidence) must strip carriage returns and line feeds before being passed to the Mailgun client. The composition service is responsible for this.
- **RDAP trust boundary.** RDAP responses can contain garbage. Validate the abuse email against a strict regex before displaying it, and never auto-send. The user always sees and confirms the recipient before send.
- **Rate limits.** Per client IP: 3 compose requests per hour, 10 per day (both endpoints combined). Per recipient abuse contact: 1 send per hour. Global: 100 sends per day. Enforced in SQLite with the same pattern as existing tabs.
- **Audit log.** Every successful send records: timestamp UTC, sender IP (CF-Connecting-IP), recipient abuse contact, subject line, target IP or domain, evidence category, Mailgun message ID. Never log the full body (privacy).
- **API key handling.** Mailgun API key lives in `/opt/falconeye/app_src/.env` with file permissions 600 owned by the falconeye service user. Never logged. Never returned in API responses.
- **SSRF surface.** RDAP endpoints are known bootstrap URLs (`rdap.org` and RIR endpoints), but pass them through the existing `safe_fetch.py` helper anyway for consistency.
- **Do not use nano.** Use sed, vi, or `sudo tee` heredoc.

## Part A. Dependency check and install

### A1. Verify existing dependencies

```bash
cd /opt/falconeye/app_src
python3 -c "import httpx; print('httpx', httpx.__version__)"
python3 -c "import dnspython" 2>&1 || echo "dnspython not installed"
python3 -c "from email.utils import formataddr; print('email stdlib ok')"
grep -E "^(httpx|dnspython)" requirements.txt
```

Report results. httpx is definitely there. dnspython may or may not be; needed only if we do MX lookups (we do not need them for v3.7.0, RDAP covers everything).

### A2. No new dependencies expected

Verify by dry-run:

```bash
cd /opt/falconeye/app_src
source venv/bin/activate  # adjust to actual venv path
pip install --dry-run -r requirements.txt
```

If pip reports nothing to install, we are done. If it wants to install anything, stop and report before proceeding.

## Part B. Backend implementation

### B1. Abuse contact lookup service

Path: `app/services/abuse_lookup.py`

Interface:

```python
async def lookup_ip_abuse(ip: str) -> AbuseLookupResult:
    """
    Query RDAP for the abuse contact of an IP address.
    Uses https://rdap.org/ip/{ip} as the bootstrap URL; rdap.org redirects
    to the correct RIR (ARIN, RIPE, APNIC, LACNIC, AFRINIC).
    Returns:
    {
      "target": "1.2.3.4",
      "target_type": "ip",
      "abuse_email": "abuse@provider.example" | None,
      "abuse_phone": str | None,
      "network_name": str,
      "network_handle": str,
      "asn": int | None,
      "country": str | None,
      "rir": str,  # "ARIN" | "RIPE" | "APNIC" | "LACNIC" | "AFRINIC"
      "source_url": str,  # the RDAP URL that answered
      "raw_entities": list,  # trimmed vcard entities for debug
      "error": str | None,
    }
    """

async def lookup_domain_abuse(domain: str) -> AbuseLookupResult:
    """
    Query RDAP for the abuse contact of a domain via registrar.
    Uses https://rdap.org/domain/{domain}.
    Returns same shape as lookup_ip_abuse with target_type='domain' and
    additional field 'registrar' (str).
    """
```

Requirements:

- Use `httpx.AsyncClient` with a 10-second timeout.
- Pass the URL through `safe_fetch.check_url()` before fetching (defense in depth even though rdap.org is trusted).
- Parse the RDAP JSON per RFC 7483. The abuse contact is in the `entities` array where an entity has `roles` containing `"abuse"`. The email is inside its vCard array under the `"email"` key.
- Validate the extracted email against a strict regex: `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`. Reject anything else.
- Cache successful lookups in the `abuse_contact_cache` SQLite table (see B5) for 24 hours to avoid hammering RDAP.
- On error, return the result with `error` populated and everything else None. Never raise.

### B2. Report composition service

Path: `app/services/abuse_compose.py`

Interface:

```python
def compose_report(
    target: str,
    target_type: str,        # "ip" | "domain"
    category: str,           # see below
    evidence_text: str,      # user-editable, sanitized
    observed_at_utc: str,    # ISO 8601
    reporter_name: str,
    reporter_email: str,
) -> ComposedReport:
    """
    Render an abuse report from a category template.
    Returns:
    {
      "subject": str,
      "body_text": str,
      "reporter_name": str,
      "reporter_email": str,
      "category": str,
      "target": str,
      "warnings": list[str],  # e.g. "evidence contained CR/LF, stripped"
    }
    Never raises. Sanitizes all inputs against email header injection.
    """
```

Categories (each has a plain-text template in `app/templates/abuse_reports/`):

- `phishing` — credential harvest, brand impersonation
- `spam` — unsolicited bulk email
- `bec` — business email compromise, wire fraud attempts
- `malware` — malware distribution or C2
- `bruteforce` — SSH, RDP, web login brute-force
- `scanning` — port or vulnerability scanning
- `ddos` — participation in DDoS
- `crypto_fraud` — crypto scam infrastructure (PH-specific relevance)
- `other` — freeform, requires user to specify in evidence

Template shape (all templates):

```
Subject: Abuse Report: {category_title} from {target}

To Whom It May Concern,

I am reporting abusive activity originating from infrastructure under
your administration. Details below.

Target: {target}
Target type: {target_type}
Activity category: {category_title}
Observed at (UTC): {observed_at_utc}

Evidence:

{evidence_text}

I am reporting this in good faith as an independent OSINT investigator.
Please take appropriate action per your abuse policy and reply to this
email if you require additional information.

Regards,
{reporter_name}
{reporter_email}
```

Sanitization rules for `compose_report`:

- Strip `\r`, `\n`, `\0` from all single-line inputs (target, category, reporter fields, observed_at)
- For `evidence_text` (multi-line allowed): normalize line endings to `\n`, strip `\r`, disallow raw `\0`, cap length at 8000 characters
- If any sanitization changed the input, add a warning to the response

### B3. Mailgun sender service

Path: `app/services/abuse_send.py`

Skip this file entirely if user picked Option A in M5.

Interface:

```python
async def send_via_mailgun(
    composed: ComposedReport,
    recipient_email: str,
    client_ip: str,
) -> SendResult:
    """
    Send composed report via Mailgun HTTP API.
    Applies rate limits before sending. Logs to audit table on success.
    Returns:
    {
      "sent": bool,
      "mailgun_message_id": str | None,
      "error": str | None,
      "rate_limited": bool,
    }
    """
```

Requirements:

- Read config from env: `MAILGUN_API_KEY`, `MAILGUN_DOMAIN` (e.g., `osintph.net`), `MAILGUN_REGION` (`us` or `eu`, defaults `us`), `MAILGUN_FROM` (e.g., `abuse-reports@osintph.net`).
- Endpoint: `https://api.mailgun.net/v3/{MAILGUN_DOMAIN}/messages` (US) or `https://api.eu.mailgun.net/v3/{MAILGUN_DOMAIN}/messages` (EU).
- Authentication: HTTP Basic Auth with username `api` and password `${MAILGUN_API_KEY}`.
- Body (form-urlencoded): `from`, `to` (recipient), `subject`, `text` (body_text), `h:Reply-To` (reporter_email), `h:X-Report-Abuse` (the target), `o:tag` (`abuse-report`, `category:{category}`).
- Enforce rate limits before hitting Mailgun:
  - Per client IP: 3 sends per hour, 10 per day
  - Per recipient email: 1 send per hour
  - Global: 100 sends per day
- On successful send, insert one row into `abuse_send_audit` table (see B5).
- Validate `recipient_email` against the same strict email regex as B1.
- Reject if `recipient_email` was not returned by a recent RDAP lookup (check `abuse_contact_cache`). This prevents the endpoint being abused to send emails to arbitrary addresses even with valid auth.

### B4. Endpoints

Path: `app/routers/abuse.py`

Three endpoints:

```
POST /api/abuse/lookup
  Body: {"target": str, "target_type": "ip" | "domain"}
  Auth: none
  Rate limit: 10 per client IP per hour
  Returns: AbuseLookupResult

POST /api/abuse/compose
  Body: {
    "target": str, "target_type": str, "category": str,
    "evidence_text": str, "observed_at_utc": str
  }
  Auth: none (uses reporter identity from env, not user input)
  Rate limit: 3 per client IP per hour
  Returns: ComposedReport

POST /api/abuse/send
  Body: {
    "composed": ComposedReport, "recipient_email": str
  }
  Auth: HTTP Basic Auth (see B6)
  Rate limit: enforced by send service
  Returns: SendResult
```

The compose endpoint reads reporter identity from these env vars, NOT from the request body:

- `FALCONEYE_REPORTER_NAME`
- `FALCONEYE_REPORTER_EMAIL`

If either is missing, the endpoint returns 503 with a clear message telling the operator to set the env vars. Never fall back to a default.

Register the router in `app/main.py` following whatever pattern the existing routers use.

### B5. SQLite tables

Add to `app/db.py` alongside existing table definitions:

```sql
CREATE TABLE IF NOT EXISTS abuse_contact_cache (
  target TEXT NOT NULL,
  target_type TEXT NOT NULL,
  abuse_email TEXT,
  network_name TEXT,
  raw_json TEXT,
  cached_at INTEGER NOT NULL,
  PRIMARY KEY (target, target_type)
);
CREATE INDEX IF NOT EXISTS idx_abuse_contact_cached_at
  ON abuse_contact_cache(cached_at);

CREATE TABLE IF NOT EXISTS abuse_lookup_rate_limit (
  client_ip TEXT NOT NULL,
  ts INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_abuse_lookup_rl_ip_ts
  ON abuse_lookup_rate_limit(client_ip, ts);

CREATE TABLE IF NOT EXISTS abuse_compose_rate_limit (
  client_ip TEXT NOT NULL,
  ts INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_abuse_compose_rl_ip_ts
  ON abuse_compose_rate_limit(client_ip, ts);

CREATE TABLE IF NOT EXISTS abuse_send_rate_limit (
  scope TEXT NOT NULL,  -- 'ip:<clientip>', 'recipient:<email>', 'global'
  ts INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_abuse_send_rl_scope_ts
  ON abuse_send_rate_limit(scope, ts);

CREATE TABLE IF NOT EXISTS abuse_send_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  client_ip TEXT NOT NULL,
  recipient_email TEXT NOT NULL,
  target TEXT NOT NULL,
  target_type TEXT NOT NULL,
  category TEXT NOT NULL,
  subject TEXT NOT NULL,
  mailgun_message_id TEXT,
  success INTEGER NOT NULL  -- 1 or 0
);
CREATE INDEX IF NOT EXISTS idx_abuse_send_audit_ts
  ON abuse_send_audit(ts);
```

### B6. HTTP Basic Auth on send endpoint

Only if implementing Option B (send-via-Mailgun).

Read from env:
- `FALCONEYE_ABUSE_ADMIN_USER`
- `FALCONEYE_ABUSE_ADMIN_PASS_HASH` — bcrypt hash, not plaintext

Use FastAPI's `HTTPBasic` dependency. On the `/api/abuse/send` endpoint, decorate with the auth dependency. Compare provided password against the bcrypt hash using `bcrypt.checkpw`. On failure, return 401 with `WWW-Authenticate: Basic realm="FalconEye Admin"`.

Sigmund generates the hash himself with:

```bash
python3 -c "import bcrypt; print(bcrypt.hashpw(b'YOUR_PASSWORD_HERE', bcrypt.gensalt()).decode())"
```

He pastes the resulting hash (starts with `$2b$`) into `.env` as `FALCONEYE_ABUSE_ADMIN_PASS_HASH`.

If bcrypt is not installed: `pip install bcrypt` in the venv.

## Part C. Frontend implementation

### C1. IP Reputation tab additions

Path: `app/static/index.html`, IP Reputation panel section.

After the existing IP details render, add a new section "Report Abuse to Hosting Provider":

- Fetches abuse contact on tab load (calls `/api/abuse/lookup`) and displays: abuse email, network name, RIR. If lookup fails, show a note.
- Category dropdown (populated from the fixed list in B2).
- Evidence textarea prefilled with observed IP, reason FalconEye flagged it (from existing IP Reputation output), and timestamp. Editable.
- Observed-at datetime picker prefilled with the current UTC timestamp. Editable.
- Two buttons:
  - **Preview Report** (calls `/api/abuse/compose`, shows composed subject + body in a preview panel)
  - The preview panel then shows: **Copy to Clipboard** button (always available), and **Send via Mailgun** button (visible only if the frontend detects Basic Auth is configured; if user has not authenticated, clicking prompts for credentials via the browser's native prompt).

Do not show any real email content until the user clicks Preview.

### C2. Email Header tab additions

Same pattern as C1, adapted to the header context:

- Two abuse contacts are possible from an email header: the sending IP hoster (from the `Received:` chain) and the sender domain registrar (from the From: domain).
- Show both contact cards. User picks one or both via checkboxes.
- Evidence textarea prefilled with a redacted excerpt of the parsed header (Received chain, Return-Path, Authentication-Results). Personal info from the "To:" line is stripped by default (privacy for the recipient of the abusive email).
- Category dropdown appropriate to email context (default: `spam` or `phishing`).
- Preview → Copy → Send flow as C1.

If user picked both contacts, compose runs twice (once per recipient) and shows both previews stacked.

### C3. Send button visibility logic

Skip if Option A.

The Send button is always rendered in the DOM but starts hidden. On page load, the frontend makes a GET request to `/api/abuse/send_available` (a new tiny endpoint that returns `{"available": true}` only if the auth env vars are configured on the backend). If yes, the button is shown but disabled with tooltip "Admin authentication required." Clicking it triggers a synthetic 401 to prompt the browser's Basic Auth dialog; on successful auth, the button becomes enabled and clicking it again performs the real send.

Simpler approach if the above is fiddly: always show the Send button; on click, browser prompts for auth if not already authenticated; on 401, show the auth prompt naturally.

### C4. Shared UI components

The abuse report card is nearly identical between IP and Email Header tabs. Extract it into a shared JavaScript function `renderAbuseReportCard(container, targetInfo)` that both tabs call. Reduces duplication and makes future maintenance easier.

## Part D. Documentation

### D1. Update README.md

- Bump `Current version: **3.6.0**` to `**3.7.0**`
- Update the feature intro paragraph: add "abuse report composition on IP and Email Header tabs, with optional Mailgun send"
- Add a short section titled "Abuse Reporting" pointing at `docs/abuse-reporting.md` for setup

### D2. Prepend CHANGELOG.md with v3.7.0

Follow the same Python prepend pattern used in v3.5.2 and v3.6.0. Entry:

```
## v3.7.0 (YYYY-MM-DD)

### Added

- **Abuse report composition on IP Reputation tab.** Given an IP under investigation, FalconEye now looks up the hosting provider's abuse-c contact via RDAP, prefills an abuse report from a category-appropriate template (phishing, spam, BEC, malware, brute-force, scanning, DDoS, crypto fraud, other), and offers Copy to Clipboard. Sending via Mailgun is available for authenticated operators only.
- **Abuse report composition on Email Header tab.** Given a parsed email header, FalconEye surfaces two abuse contacts: the sending IP's hoster (from RDAP on the Received chain) and the sender domain's registrar (from RDAP on the From: domain). Reports can be composed for either or both contacts.
- **RDAP-based abuse contact lookup service** with 24-hour SQLite cache to reduce load on RDAP endpoints.
- **Optional Mailgun send integration** for operators with Mailgun credentials. Gated behind HTTP Basic Auth. Enforces per-IP, per-recipient, and global rate limits. Every send is audited to an append-only SQLite table.

### Operator notes

Compose and Copy work with no configuration. Send via Mailgun requires setting `FALCONEYE_REPORTER_NAME`, `FALCONEYE_REPORTER_EMAIL`, `MAILGUN_API_KEY`, `MAILGUN_DOMAIN`, `MAILGUN_REGION`, `MAILGUN_FROM`, `FALCONEYE_ABUSE_ADMIN_USER`, and `FALCONEYE_ABUSE_ADMIN_PASS_HASH` in the environment. See docs/abuse-reporting.md for the full setup guide.

Mailgun free-tier state as of 2026 varies by plan and region; FalconEye documentation notes what to check but the operator is responsible for staying within their Mailgun account's sending allowance.
```

### D3. New docs page: `docs/abuse-reporting.md`

Create this file with these sections:

1. **Overview** — what the feature does, why compose-only vs send modes exist
2. **Compose and Copy mode** — no configuration required, works out of the box
3. **Send via Mailgun mode** — full setup guide:
   - Reporter identity env vars
   - Mailgun API key generation (link to Mailgun docs)
   - Mailgun domain verification
   - US vs EU region selection
   - Admin Basic Auth setup (with the bcrypt hash generation command)
   - Rate limits (per-IP, per-recipient, global)
   - Audit log location and rotation
4. **Mailgun free-tier note** — web-search current state at write time and document what you find. Note that Mailgun's pricing changes and the operator is responsible for their own account's sending allowance. Historically their Flex plan replaced older free tiers; if a "Foundation" or "Free" trial exists in 2026, document its monthly ceiling.
5. **RDAP fallback** — what happens when RDAP lookup fails or returns no abuse contact (feature disabled for that target, UI shows explanation)
6. **Security posture** — reasons behind the design: why send is gated, why only RDAP-verified recipients are allowed, why audit log exists

Claude Code: web-search "Mailgun pricing free tier 2026" and cite the answer with a link in section 4. Do not assume the historical 10K/month tier still exists.

### D4. Update `.env.example`

Add all new env vars with placeholder values and inline comments explaining each:

```
# Reporter identity (required for /api/abuse/compose)
FALCONEYE_REPORTER_NAME="Sigmund Brandstaetter, OSINT-PH"
FALCONEYE_REPORTER_EMAIL="abuse-reports@osintph.net"

# Mailgun send (optional, for send-via-mailgun feature)
MAILGUN_API_KEY=""
MAILGUN_DOMAIN="osintph.net"
MAILGUN_REGION="us"   # or "eu"
MAILGUN_FROM="abuse-reports@osintph.net"

# Admin auth for send endpoint (bcrypt hash, not plaintext)
FALCONEYE_ABUSE_ADMIN_USER="admin"
FALCONEYE_ABUSE_ADMIN_PASS_HASH=""
```

### D5. Update JSON-LD and main.py version

- `app/static/index.html`: change `"softwareVersion": "3.6.0"` to `"3.7.0"`. Add abuse reporting to the `featureList` array.
- `app/main.py`: change `version="3.6.0"` and `/health` return `"version": "3.6.0"` to `"3.7.0"` in both spots.

## Part E. Testing

All tests happen on staging (:8001) before flipping the live service. Same pattern Claude Code established for v3.6.0.

### E1. Unit tests

New file: `tests/test_abuse_lookup.py`

- Test parsing of a real ARIN RDAP response (paste a sanitized fixture)
- Test parsing of a real RIPE RDAP response (fixture)
- Test parsing of a malformed RDAP response (returns error, does not raise)
- Test email validation regex rejects garbage
- Test cache hit returns without HTTP call

New file: `tests/test_abuse_compose.py`

- Test each category renders without error
- Test CR/LF injection in evidence gets stripped and adds a warning
- Test CR/LF injection in target gets rejected
- Test long evidence gets truncated at 8000 chars
- Test missing reporter identity env vars raises the correct 503

New file: `tests/test_abuse_send.py` (skip if Option A)

- Mock Mailgun API with pytest-httpx
- Test successful send inserts audit row
- Test rate limit blocks second send within same hour to same recipient
- Test send rejects recipient not in abuse_contact_cache
- Test Mailgun API key never appears in exception messages or logs

Run tests:

```bash
cd /opt/falconeye/app_src
source venv/bin/activate
pytest tests/test_abuse_lookup.py tests/test_abuse_compose.py tests/test_abuse_send.py -v
```

All must pass.

### E2. Deploy to staging on port 8001

Same pattern as v3.6.0 staging flow. Start a second instance on :8001 with the new code, live service stays on :8000 unchanged.

```bash
cd /opt/falconeye/app_src
source venv/bin/activate
FALCONEYE_ENV=staging uvicorn app.main:app --host 127.0.0.1 --port 8001 &
sleep 2
curl -s http://127.0.0.1:8001/health
```

### E3. Smoke test lookup

```bash
curl -s -X POST http://127.0.0.1:8001/api/abuse/lookup \
  -H "Content-Type: application/json" \
  -d '{"target": "8.8.8.8", "target_type": "ip"}' | python3 -m json.tool
```

Expected: `abuse_email` populated (something like `network-abuse@google.com`), `rir: "ARIN"`, `network_name` mentioning Google.

Test SSRF:

```bash
curl -s -X POST http://127.0.0.1:8001/api/abuse/lookup \
  -H "Content-Type: application/json" \
  -d '{"target": "127.0.0.1", "target_type": "ip"}' | python3 -m json.tool
```

Expected: RDAP returns nothing useful or an error; FalconEye returns `error` populated, does not crash.

### E4. Smoke test compose

```bash
FALCONEYE_REPORTER_NAME="Test Reporter" \
FALCONEYE_REPORTER_EMAIL="test@example.com" \
curl -s -X POST http://127.0.0.1:8001/api/abuse/compose \
  -H "Content-Type: application/json" \
  -d '{
    "target": "1.2.3.4",
    "target_type": "ip",
    "category": "bruteforce",
    "evidence_text": "SSH brute-force attempts from this IP against my server between 03:14 and 04:22 UTC on 2026-07-19. Approximately 1200 failed login attempts against user root.",
    "observed_at_utc": "2026-07-19T04:22:00Z"
  }' | python3 -m json.tool
```

Expected: `subject` starting with "Abuse Report: Brute-Force", `body_text` containing the evidence, `warnings` empty.

Test injection:

```bash
curl -s -X POST http://127.0.0.1:8001/api/abuse/compose \
  -H "Content-Type: application/json" \
  -d '{
    "target": "1.2.3.4\r\nBCC: evil@attacker.com",
    "target_type": "ip",
    "category": "spam",
    "evidence_text": "test",
    "observed_at_utc": "2026-07-19T00:00:00Z"
  }' | python3 -m json.tool
```

Expected: request rejected OR target sanitized with a warning. No `BCC:` line survives in the composed output.

### E5. Smoke test send (skip if Option A)

Requires MAILGUN_API_KEY and admin auth env vars set on the staging process.

```bash
curl -s -X POST http://127.0.0.1:8001/api/abuse/send \
  -u "admin:YOUR_PASSWORD" \
  -H "Content-Type: application/json" \
  -d '{
    "composed": { ...paste the compose output... },
    "recipient_email": "abuse-reports@osintph.net"
  }' | python3 -m json.tool
```

Send to yourself (recipient = your own inbox) for the first test. Confirm the email arrives. Check headers include Reply-To and X-Report-Abuse.

Test auth failure:

```bash
curl -s -X POST http://127.0.0.1:8001/api/abuse/send \
  -u "admin:wrongpassword" \
  -H "Content-Type: application/json" \
  -d '{...}' -i | head -5
```

Expected: `HTTP/1.1 401 Unauthorized`, WWW-Authenticate header present.

Test rate limit: run the send command twice within one hour to the same recipient. Second call must return `rate_limited: true`.

## Part F. Human review checkpoint

Claude Code stops here and waits for Sigmund to click through both tabs on staging (http://127.0.0.1:8001 via SSH tunnel, or by temporarily exposing :8001 via nginx on a hidden path).

Sigmund's checklist:

- [ ] IP Reputation tab: lookup a real hostile IP from your own logs. Confirm abuse contact appears. Preview a report. Confirm evidence prefill is sensible. Copy to clipboard, paste into a text editor, sanity check the text.
- [ ] Email Header tab: paste a real spam header from your inbox. Confirm both contacts are surfaced. Preview reports for both.
- [ ] If Option B: click Send on a report addressed to your own inbox. Confirm delivery. Check the audit log has one row.
- [ ] Try to send a second report to the same recipient within an hour. Confirm rate limit rejects it.
- [ ] Try to send with wrong password. Confirm 401.
- [ ] Try to send with no auth. Confirm 401.
- [ ] Read the composed subject and body in each category. Confirm the language is professional and not overly aggressive.

Report back to Claude Code with any changes needed. Common asks: wording changes in templates, additional categories, evidence prefill tweaks.

## Part G. Commit, tag, release

Only after Sigmund approves the staging build.

### G1. Diff review

```bash
cd /opt/falconeye/app_src
git status
git diff --stat
```

Expected new files: everything in "New" from the "Files that will be touched" section. Modified: everything in "Modified".

### G2. Commit

```bash
git add -A
git commit -m "v3.7.0: abuse report composition on IP and Email Header tabs

Adds RDAP-based abuse contact lookup and category-templated report
composition to the IP Reputation and Email Header tabs. Compose and
copy work without configuration. Optional Mailgun send is gated
behind HTTP Basic Auth with per-IP, per-recipient, and global rate
limits, plus an append-only audit log.

Nine categories: phishing, spam, BEC, malware, brute-force, scanning,
DDoS, crypto fraud, other. Templates in app/templates/abuse_reports/.

RDAP responses cached 24h in SQLite. Reporter identity from env vars,
never user-supplied. Email header injection prevention in all
sanitized fields.

Version bumps: README, CHANGELOG, JSON-LD, main.py app + health."
```

### G3. Tag v3.7.0

```bash
git tag -a v3.7.0 -m "v3.7.0: abuse reporting"
```

### G4. Push

```bash
git push origin main
git push origin v3.7.0
```

### G5. GitHub release

Use `gh release create v3.7.0` with notes derived from the CHANGELOG entry. Same pattern as v3.6.0.

## Final report to Sigmund

Claude Code reports:

1. All tests passing (unit and smoke).
2. Staging clicked through and approved by Sigmund.
3. Live service restarted with v3.7.0.
4. `/health` and `/openapi.json` both return `3.7.0`.
5. Commit hash, tag, release URL.
6. Whether Option A or Option B shipped.
7. If Option B: confirm Sigmund received the test send email and audit log has the row.
8. `docs/abuse-reporting.md` published on the repo, linked from README.
9. Blog post draft is next.
