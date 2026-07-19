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
  Mailgun* button gated behind admin HTTP Basic Auth, rate limits, an audit log,
  and an allowlist that restricts recipients to addresses FalconEye itself
  resolved via RDAP.

Both modes share the same RDAP lookup and the same composition/sanitization
logic. Only the send layer differs.

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

### 4. Admin Basic Auth

The send endpoint is protected by HTTP Basic Auth. Store a **bcrypt hash**, not
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

In the browser, clicking **Send via Mailgun** reveals an inline credential form
(username defaults to `admin`). Credentials are kept in memory for the browser
session so you authenticate once. A wrong password returns HTTP 401 and
re-prompts.

### 5. Rate limits

Enforced in SQLite before Mailgun is ever contacted:

| Scope | Limit |
|---|---|
| Per client IP | 3 sends/hour, 10 sends/day |
| Per recipient abuse contact | 1 send/hour |
| Global (all senders) | 100 sends/day |

The compose and lookup endpoints are separately limited (compose 3/hour and
10/day per IP; lookup 10/hour per IP), plus a short-window burst limit on each.

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

- **Send is gated** behind admin Basic Auth because emitting mail from a real
  domain via a public UI is an abuse vector. Basic Auth is the minimum bar.
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
