# Abuse Reporting

FalconEye v3.7.0 adds abuse report composition to the **IP Reputation** and
**Email Header** tabs. When an investigation lands on a piece of hostile
infrastructure — a scanning IP, a spam sending host, a phishing sender domain —
FalconEye can look up the responsible provider's abuse contact, compose a
report, and either hand it to you to copy or (optionally) send it via Mailgun.

## Overview

Two modes exist because sending email from a real domain through a public web UI
is itself a legitimate abuse vector:

- **Compose and Copy** — the default. Works with no configuration and no
  authentication. FalconEye resolves the abuse contact, renders a report, and
  gives you a *Copy to Clipboard* button. You paste into your own mail client
  and send from there. No Mailgun code path runs.
- **Send via Mailgun** — optional, off unless you configure it. Adds a *Send via
  Mailgun* button gated behind admin credentials, rate limits, an audit log,
  and an allowlist that restricts recipients to addresses FalconEye itself
  resolved via RDAP.

Both modes share the same RDAP lookup and the same composition/sanitization
logic. Only the send layer differs.

## What makes an abuse report actionable

Provider abuse desks and registrars triage by whether a report carries enough
**forensic evidence to verify and act on** — not by how strongly it is worded. An
actionable report includes the raw material: the full header block with every
`Received` line in original order, the message's `Subject`, `Message-ID`, `Date`,
`From`, `Return-Path`, and `Authentication-Results` (SPF/DKIM/DMARC), plus the
body or the URLs it linked to. For an IP report, name the ASN/network and the
concrete observed activity (log excerpts, UTC timestamps, malicious-URL records).
A vague "this IP/domain is bad" is routinely ignored; a report the desk can
reproduce or cross-check gets acted on. This is why FalconEye v3.8.3 composes
reports from the real email content (verbatim `Received` chain, real headers, and
a body excerpt or the full body) rather than a summary.

Beyond the evidence, keep the report **specific, factual, and self-contained**:
one incident per report, a real monitored reply-to address (desks reply asking
for clarification), UTC timestamps, and no overstatement. Registrars care most
about what the mail *linked to* (the URLs); hosting abuse desks care about what
their IP *did* — FalconEye tailors each report accordingly. Because the body is
included as evidence, **review it and remove any of your own PII before sending**
(the evidence field is editable for exactly that). See M3AAWG's
[Sender Best Common Practices](https://www.m3aawg.org/documents/en/m3aawg-sender-best-common-practices-version-30)
and [Abuse Desk Common Practices](https://www.m3aawg.org/documents/en/abuse-desk-common-practices)
for the authoritative guidance.

## Compose and Copy mode

No configuration is required for lookup and copy. Composition additionally needs
a reporter identity (abuse desks ignore anonymous reports), so the *Preview*
button requires two environment variables:

```
FALCONEYE_REPORTER_NAME="Your Name, Your Org"
FALCONEYE_REPORTER_EMAIL="abuse-reports@example.com"
```

`FALCONEYE_REPORTER_EMAIL` becomes the report's reply-to. Use an inbox you
actually monitor — abuse desks reply there for more information. If either
variable is unset, `POST /api/abuse/compose` returns HTTP 503 with a message
telling you which variable to set; it never falls back to a default identity.

Workflow in the UI:

1. Run an IP lookup (or analyze an email header).
2. Scroll to the **Report Abuse** card. FalconEye resolves the abuse contact via
   RDAP and shows it.
3. Pick a category, edit the prefilled evidence, confirm the observed-at
   timestamp, and click **Preview Report**.
4. Review the composed subject and body, then **Copy to Clipboard**.

## Send via Mailgun mode

Enabling send requires the reporter identity above, a configured Mailgun
account, and an admin credential.

### 1. Mailgun account and sending domain

1. Sign in at <https://app.mailgun.com/> and confirm your account is active.
2. Add and verify a sending domain (Send → Sending → Domains) by publishing the
   DNS records Mailgun shows (SPF, DKIM, tracking CNAME) and waiting for
   verification. FalconEye sends from this domain.
3. Note your account **region**. The API host differs:
   `api.mailgun.net` (US) vs `api.eu.mailgun.net` (EU).

### 2. Sending API key

In the Mailgun dashboard create a **Sending** API key (scope it to sending, not
the master key) and copy the value. Store it only in the server `.env` file.

### 3. Environment variables

Add to `/opt/falconeye/.env` (loaded by the systemd `EnvironmentFile`):

```
MAILGUN_API_KEY=key-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
MAILGUN_DOMAIN=email.example.com
MAILGUN_REGION=eu            # "us" or "eu" — bare value, no inline comment
MAILGUN_FROM=reports@email.example.com
```

Two rules the send path enforces implicitly:

- **The domain part of `MAILGUN_FROM` must exactly match `MAILGUN_DOMAIN`.** If
  they differ, Mailgun silently rejects the send from an unverified domain and
  the failure mode is opaque.
- **`MAILGUN_REGION` must be a bare `us` or `eu`.** systemd's `EnvironmentFile`
  parser does *not* strip trailing `# ...` inline comments, so a line like
  `MAILGUN_REGION=eu   # or us` is read as the whole junk string. FalconEye
  defensively takes the first whitespace/`#`-delimited token, but keep the file
  clean. Anything unrecognized falls back to `us`.

### 4. Admin authentication

The send endpoint is gated by admin credentials. Store a **bcrypt hash**, not
a plaintext password:

```bash
python3 -c "import bcrypt; print(bcrypt.hashpw(b'YOUR_PASSWORD', bcrypt.gensalt()).decode())"
```

Paste the resulting `$2b$...` string into `.env`:

```
FALCONEYE_ABUSE_ADMIN_USER=admin
FALCONEYE_ABUSE_ADMIN_PASS_HASH=$2b$12$............................................
```

Do **not** reuse the Mailgun API key as the password — they are two different
secrets. Restart the service after editing `.env` (`sudo systemctl restart
falconeye`) so the new environment is loaded.

The **Send via Mailgun** button reveals an in-page authentication form with
username and password fields (username defaults to `admin`). Credentials are
sent in the JSON request body and validated against the bcrypt hash in
`FALCONEYE_ABUSE_ADMIN_PASS_HASH`. **No browser authentication dialog is
triggered at any point** — the endpoint never returns `401` or a
`WWW-Authenticate` header (that would pop the browser's native Basic Auth prompt
and race the in-page form; see v3.8.1). Credentials are kept in memory for the
browser session so you authenticate once; a wrong password shows an inline error
under the form.

### 5. Rate limits

**Send is not rate-limited** (as of v3.8.3). It is admin-authenticated and
single-user, so a rate limit added no protection and only created debugging
friction. Send is protected instead by admin credentials, the RDAP-recipient
allowlist, and the append-only audit log.

The public, unauthenticated endpoints **are** rate-limited as load protection:

| Endpoint | Limit (per client IP) |
|---|---|
| `/api/abuse/compose` | 3/hour, 10/day |
| `/api/abuse/lookup` | 10/hour |

plus a short-window burst limit on each.

### 6. Audit log

Every send attempt writes one row to the `abuse_send_audit` table in the
FalconEye SQLite database (`/opt/falconeye/data/falconeye.db` by default):
timestamp (UTC), sender IP (`CF-Connecting-IP`), recipient abuse contact,
subject, target IP/domain, category, Mailgun message ID, and success flag. **The
report body is never logged** (privacy). Inspect it with:

```bash
sqlite3 /opt/falconeye/data/falconeye.db \
  "SELECT datetime(ts,'unixepoch'), recipient_email, target, category, success FROM abuse_send_audit ORDER BY ts DESC LIMIT 20;"
```

The table is append-only and unbounded; prune old rows manually if desired.

## Operator troubleshooting

### Clearing a rate-limit counter

Each client IP is capped on the public endpoints (compose 3/hour, lookup
10/hour; send is not limited — it is admin-only; the Username tab and other tabs
have their own caps). If a
legitimate investigator hits their own cap mid-casework — or you hit it while
debugging — clear that IP's counters with the operator CLI instead of
hand-writing SQLite `DELETE`s against the right table and column:

```bash
cd /opt/falconeye/app_src
# clear one IP across every rate-limit table
/opt/falconeye/venv/bin/python -m app.abuse.tools reset-rate-limit --ip 1.2.3.4

# just one endpoint
/opt/falconeye/venv/bin/python -m app.abuse.tools reset-rate-limit --ip 1.2.3.4 --endpoint compose

# preview without deleting
/opt/falconeye/venv/bin/python -m app.abuse.tools reset-rate-limit --ip 1.2.3.4 --dry-run
```

`--endpoint` accepts `lookup`, `compose`, `send`, `username`, `url`, `qr`, `dork`,
`decoder`, `llm`, or `all` (default). It prints how many rows it cleared per
table. The IP is the value FalconEye records — the real client IP from
`CF-Connecting-IP`. Use it for debugging or when a real investigator is blocked;
it is not a way to disable rate limiting.

### Send rejects the correct password

If Send returns "invalid credentials" for a password you know is right, check the
`FALCONEYE_ABUSE_ADMIN_PASS_HASH` line in `/opt/falconeye/.env` for a trailing
inline comment — a real bcrypt hash is exactly 60 characters and starts with
`$2b$`. As of v3.8.2 the app strips inline comments from env values defensively,
but confirm the value and restart the service after any `.env` edit. Background:
`docs/regressions.md`.

## Mailgun free-tier note

Mailgun's pricing changes periodically and you are responsible for staying
within your own account's sending allowance. As of mid-2026:

- **Free plan:** ~100 messages/day, one custom domain, one day of data
  retention — a "forever free" tier with no time limit. For abuse reporting this
  is usually plenty.
- **Flex** is a legacy pay-as-you-go plan (~$0.80 per 1,000 emails) retained for
  older accounts; newer accounts see tiered plans (Basic ~$15/mo for 10k,
  Foundation ~$35/mo for 50k, Scale ~$90/mo for 100k).

Check your current plan and region in the Mailgun dashboard header before
enabling send. Sources:
[Mailgun pricing](https://www.mailgun.com/pricing/),
[Mailgun free plan help](https://help.mailgun.com/hc/en-us/articles/203068914-What-does-the-Free-plan-offer).

## RDAP fallback

Abuse contacts come from RDAP (`rdap.org`, which redirects to the authoritative
RIR for IPs or registry/registrar for domains). When RDAP returns no abuse
contact, fails, or the TLD does not support RDAP:

- The card shows an explanation instead of a contact address.
- **Compose and Copy still work** — you can send the report manually to a contact
  you find another way.
- **Send is unavailable** for that target, because the send path refuses any
  recipient it did not itself resolve via RDAP.

Non-public IPs (private, loopback, reserved) short-circuit before any network
call and report that no abuse contact exists.

## Security posture

Design decisions and why they exist:

- **Send is gated** behind admin credentials (validated in the request body,
  not Basic Auth) because emitting mail from a real domain via a public UI is an
  abuse vector. That gate is the minimum bar.
- **Recipients are allowlisted to RDAP results.** Even with valid admin
  credentials, the send endpoint will only mail an address that a recent RDAP
  lookup returned — so the endpoint cannot be repurposed to send to arbitrary
  addresses. The one exception is your own configured `FALCONEYE_REPORTER_EMAIL`,
  which is always allowed so you can send yourself a delivery test.
- **Email header injection is prevented** in the composition layer: CR, LF, and
  NUL are stripped from every single-line field and normalized in the evidence
  field, and any alteration surfaces a warning on the report.
- **RDAP responses are untrusted.** Extracted abuse emails are validated against
  a strict regex before display, and the fetch goes through FalconEye's existing
  `safe_fetch` SSRF guard (every redirect hop re-validated) rather than a second
  bespoke fetcher.
- **The Mailgun API key** lives only in `/opt/falconeye/.env` (mode 600), is read
  at call time, and is never logged, returned in a response, or interpolated
  into an error message.
- **An audit log** records who sent what to whom (but not the body), so sends are
  accountable after the fact.
