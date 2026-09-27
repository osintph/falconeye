# IP Reputation sources

FalconEye cross-references threat-intelligence vendors on the IP Reputation tab,
forms a **consensus verdict**, merges port data, and surfaces **geolocation
disagreement** instead of asserting one country. Each source is optional and
degrades gracefully: a missing key, a quota hit, or an outage shows an inline
state on that source's sub-card and never blanks the result.

## The four verdict sources

All four are unmetered on their free tiers, which is what makes "all of them
answered" a reachable state and therefore makes CLEAN mean something.

| Source | Signal | Free-tier limit | `.env` variable | Get a key |
|---|---|---|---|---|
| **AbuseIPDB** | abuse-confidence score, report count, categories | 1,000 checks/day | `ABUSEIPDB_KEY` | <https://www.abuseipdb.com/account/api> |
| **VirusTotal** | multi-vendor detection ratio + flagged vendors | 500/day, 4/min | `VT_KEY` | <https://www.virustotal.com/gui/my-apikey> |
| **AlienVault OTX** | community pulses + malware families | generous, key-gated | `OTX_API_KEY` | <https://otx.alienvault.com/api> |
| **ThreatFox** | IOC matches (malware family, confidence) | free | `ABUSECH_AUTH_KEY` (shared) | <https://auth.abuse.ch/> |

## Censys: enrichment, and metered (v3.34.0)

Censys is **not** a verdict source. It contributes ports, services, observed OS
and ASN attribution; it has never produced a reputation signal, and nothing in
`compute_verdict()` reads a Censys field.

It is also the only metered source on the tab, which is why it is **off by
default** (`CENSYS_ENABLED=false`). Verified 2026-09-27:

| Fact | Value | Source |
|---|---|---|
| Cost of the host/entity lookup this tab makes | 1 credit | <https://docs.censys.com/docs/platform-credits-free-starter> |
| Censys Free monthly allowance | 100 credits, expiring at month end | same |
| Censys Free API scope | "Yes, lookup endpoints only" | <https://docs.censys.com/docs/data-access-tiers-entitlements> |
| Censys Starter | a Free account that has bought credits (packages from $100, valid 12 months) | <https://docs.censys.com/docs/platform-credits-free-starter> |

100 credits a month is about three host lookups a day, so on a public instance
the allowance is gone quickly. When it is gone the API answers **HTTP 422** with
an insufficient-balance body, which maps to the `no_credits` state and renders as
a grey "Censys: monthly credits exhausted" note on the ports card. That is not an
error and it never makes a verdict INCOMPLETE. A 422 that is *not* about the
balance (a malformed organization id is the case we have seen) still maps to
`error`.

Notes:
- **ThreatFox reuses `ABUSECH_AUTH_KEY`**: the same auth.abuse.ch key URLhaus
  already uses (abuse.ch made an Auth-Key mandatory in 2024). No separate key.
- **Censys uses the PAT alone.** The PAT is organization-scoped, so no
  `organization_id` is needed. FalconEye only sends `X-Organization-ID` if
  `CENSYS_ORG_ID` is a valid UUID (a placeholder/short value would cause a 422),
  so PAT-only "just works".
- Keys are read with inline-comment/quote tolerance (`getenv_clean`), so a stray
  `# comment` on the value line won't silently break a source (see
  `docs/regressions.md`, v3.8.1).

## Consensus verdict

The verdict combines the sources into one of three levels with a reasoning
string. Thresholds are named constants in `app/ip_sources/reputation.py`:

- **MALICIOUS**: AbuseIPDB confidence ≥ 75, **or** VirusTotal malicious ≥ 3,
  **or** a ThreatFox IOC match, **or** OTX pulses ≥ 3.
- **SUSPICIOUS**: AbuseIPDB 25-74, **or** VirusTotal malicious 1-2, **or** OTX
  pulses 1-2, **or** GreyNoise classified malicious.
- **CLEAN**: nothing flagged it **and all four verdict sources answered**.
- **INCOMPLETE**: nothing flagged it but at least one verdict source did not
  answer. Silence is not evidence of innocence (v3.33.2).

A source that errored, is missing a key, or hit its quota contributes nothing to
the verdict (it never counts as "clean" evidence, it counts as *unknown*).
Censys is outside this count entirely.

## Geolocation consensus and why single-source geo is unreliable

IP geolocation is an estimate, and different providers disagree, especially for
hosting/VPS/cloud ranges, where the registered country, the datacenter country,
and the vendor's guess can all differ. Asserting one country (as the old tab did)
is often simply wrong. FalconEye instead collects the country from every source
that returns one (AbuseIPDB, VirusTotal, OTX, Censys, plus MaxMind geolocation
and the ASN registration country) and:

- shows the country plainly when sources **agree**;
- shows the **disagreement** when they don't (e.g. "LT (AbuseIPDB, Censys), IR
  (VirusTotal, MaxMind), US (OTX), RS (ASN registration)");
- adds a caveat when the ASN name looks like a hosting/VPS/cloud provider, where
  geolocation is least reliable.

## Port coverage

Censys host services are merged with Shodan InternetDB ports, deduplicated by
port number, each tagged with the source(s) that saw it. "No open ports observed"
is shown only when **both** sources returned nothing, and it names which sources
were actually consulted, so an empty result from one source alone is never
mistaken for "no ports".

## A failure is not cached as an answer (v3.34.0)

The lookup is cached for six hours, and a source that failed used to be stored in
that row like one that answered: the failure was then served for the rest of the
six hours, so an operator who added a key, or an upstream that blipped for two
minutes, kept getting the old answer until the row expired.

Each `ok=false` source is now stamped in the cached row and honoured for at most
`app.utils.cache.NEGATIVE_TTL_SECONDS` (60 s). After that the next lookup
re-attempts **only** the sources that failed, merges them into the cached row,
recomputes the verdict, and rewrites the row without resetting its age (so a
permanently broken source cannot keep a row alive forever). Refresh ignores the
window and re-queries everything.

The same rule covers Domain Intel (per component: RDAP, WHOIS, DNS, CT, network),
the email analysis (a failed LLM call, which does not spend the daily cap) and
Threat Pulse (a down feed is asked again at most once a minute instead of on
every request). Covered by `tests/ip_sources/test_error_cache.py` and
`tests/unit/test_negative_cache.py`.

## Resilience

Every source call is wrapped so a timeout, 429, 401, or malformed response
becomes a per-source state, never an exception that blanks the card or 500s
`GET /api/ip/lookup/{ip}`. This is covered by a regression test
(`tests/ip_sources/test_endpoint_resilience.py`) that asserts the endpoint still
returns 200 with partial data when sources fail.
