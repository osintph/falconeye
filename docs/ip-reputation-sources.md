# IP Reputation sources

FalconEye v3.9.0 cross-references five threat-intelligence vendors on the IP
Reputation tab, forms a **consensus verdict**, merges port data, and surfaces
**geolocation disagreement** instead of asserting one country. Each source is
optional and degrades gracefully: a missing key, a quota hit, or an outage shows
an inline state on that source's sub-card and never blanks the result.

## The five sources

| Source | Signal | Free-tier limit | `.env` variable | Get a key |
|---|---|---|---|---|
| **AbuseIPDB** | abuse-confidence score, report count, categories | 1,000 checks/day | `ABUSEIPDB_KEY` | <https://www.abuseipdb.com/account/api> |
| **VirusTotal** | multi-vendor detection ratio + flagged vendors | 500/day, 4/min | `VT_KEY` | <https://www.virustotal.com/gui/my-apikey> |
| **AlienVault OTX** | community pulses + malware families | generous, key-gated | `OTX_API_KEY` | <https://otx.alienvault.com/api> |
| **Censys** | host services / open ports | host lookup on free tier | `CENSYS_PAT` | Platform → Personal Access Token |
| **ThreatFox** | IOC matches (malware family, confidence) | free | `ABUSECH_AUTH_KEY` (shared) | <https://auth.abuse.ch/> |

Notes:
- **ThreatFox reuses `ABUSECH_AUTH_KEY`** — the same auth.abuse.ch key URLhaus
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

- **MALICIOUS** — AbuseIPDB confidence ≥ 75, **or** VirusTotal malicious ≥ 3,
  **or** a ThreatFox IOC match, **or** OTX pulses ≥ 3.
- **SUSPICIOUS** — AbuseIPDB 25–74, **or** VirusTotal malicious 1–2, **or** OTX
  pulses 1–2, **or** GreyNoise classified malicious.
- **CLEAN** — nothing flagged it.

A source that errored, is missing a key, or hit its quota contributes nothing to
the verdict (it never counts as "clean" evidence — it counts as *unknown*).

## Geolocation consensus and why single-source geo is unreliable

IP geolocation is an estimate, and different providers disagree — especially for
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
is shown only when **both** sources returned nothing — and it names which sources
were actually consulted, so an empty result from one source alone is never
mistaken for "no ports".

## Resilience

Every source call is wrapped so a timeout, 429, 401, or malformed response
becomes a per-source state, never an exception that blanks the card or 500s
`GET /api/ip/lookup/{ip}`. This is covered by a regression test
(`tests/ip_sources/test_endpoint_resilience.py`) that asserts the endpoint still
returns 200 with partial data when sources fail.
