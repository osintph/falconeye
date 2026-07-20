# FalconEye

**Free, self-hosted OSINT investigator's toolkit.** Seventeen focused modules in one interface: crypto wallet tracing, phishing kit fingerprinting, domain intelligence, Telegram OSINT, IP reputation, email header forensics with LLM-powered scam detection, Google dork generation, suspicious script deobfuscation, URL expansion and redirect chain analysis, QR code decoding, commercial prospect dossiers, reverse image search, username enumeration across ~950 platforms, and a curated cyber news aggregator with a Philippines-focused threat pulse. The IP Reputation and Email Header tabs also compose abuse reports to the responsible provider (RDAP contact lookup, with optional Mailgun send).

Current version: **3.9.0**

Live instance: [falconeye.osintph.info](https://falconeye.osintph.info)

License: AGPL-3.0

---

## What it does

FalconEye is the workbench an OSINT investigator opens when a new lead arrives. Each tab does one thing well and connects to the others via one-click pivots — from "I have a wallet address" to "here are the related domains, email infrastructure, Telegram channel, and the script the phishing kit runs" without switching tools.

### Tabs

| Tab | What it does |
|---|---|
| **Home** | Landing page with PH Threat Pulse widget, example cards that prefill other tabs, and a curated news strip |
| **Crypto Workbench** | Trace Bitcoin, Ethereum, and USDT TRC20 addresses with D3 force-directed transaction graphs and labelled clusters |
| **Phishing Scanner** | Fingerprint phishing kits by URL or pasted HTML; identify the kit family; extract IOCs |
| **Domain Intelligence** | RDAP, DNS, certificate transparency logs (crt.sh + Cert Spotter fallback), RIPEstat ASN data |
| **Telegram Inspector** | Scrape public Telegram channels (t.me/s/) for messages and extract IOCs (URLs, wallets, contact details) |
| **IP Reputation** | Multi-source reputation with a consensus verdict (Clean/Suspicious/Malicious) from AbuseIPDB, VirusTotal, AlienVault OTX, Censys, and ThreatFox, plus Shodan InternetDB, GreyNoise, RIPEstat, URLhaus, reverse DNS. Merges Censys + Shodan ports and surfaces geolocation disagreement across sources. Composes an abuse report to the hosting provider's RDAP abuse-c contact (copy, or optional Mailgun send). |
| **Sandbox History** | URLhaus and MalwareBazaar lookup by URL or file hash |
| **URL Expander** | Follow a short URL's full redirect chain hop-by-hop with per-hop status codes, TLS certificate details, server headers, and timing. Flags shortener depth, TLD switches, punycode hostnames, and non-standard ports. Every hop is re-validated through `safe_fetch`'s SSRF guard. One-click pivot to the Phishing Scanner. |
| **QR Analyzer** | Decode one or more QR codes from an uploaded image or a base64 data URI (processed in memory, never stored). Categorizes payloads (HTTP, Bitcoin, Ethereum, UPI, WiFi, sms, tel, geo, text). One-click pivot of decoded URLs into the URL Expander. |
| **Image** | Reverse image search via Google Lens and Yandex in parallel. Paste a URL or upload a file (JPEG, PNG, WebP, GIF, max 10 MB). Shows visual match grids, cross-source domain corroboration, and EXIF metadata for uploads. Requires a SearchAPI.io key. Results cached 24 hours in Redis. |
| **Email Header** | Authentication checks (SPF/DKIM/DMARC), hop analysis with ASN attribution, body scam pattern detection. LLM-powered classification with validated, clamped output. Supports .eml and .msg file upload. Composes abuse reports to the sending IP's hoster and the sender domain's registrar. |
| **Dork Generator** | LLM-powered Google search query generator with preset categories and free-form natural-language input |
| **Script Decoder** | LLM-powered deobfuscation of suspicious PowerShell, JavaScript, VBA, Base64 blobs, and packed scripts. Returns deobfuscated code, IOCs, MITRE ATT&CK techniques, and detection suggestions |
| **Prospect** | Commercial intelligence dossier for any domain — identity resolution, news, job postings, and Google Ads Transparency data. Requires a SearchAPI.io key. Results cached 6 hours in Redis. |
| **Contact** | Feedback form for bug reports, feature requests, and new tab suggestions |
| **Username** | Check where a username appears across ~950 platforms using vendored WhatsMyName + Sherlock data. Dual-engine with cross-validation (hits in both engines are higher confidence). Quick (~280 sites) and Full scans, adult sites off by default, CSV export, Telegram pivot. |
| **News** | Cyber news RSS aggregator with PH-specific feeds and global outlets |

### LLM-powered tabs

Three tabs use Anthropic's Claude Haiku 4.5: **Email Header**, **Dork Generator**, and **Script Decoder**. The model is hardcoded in each router (not a configuration variable) and protected by four cost safeguards:

1. Anthropic Console spend limits at the API account level
2. Per-feature, per-IP daily rate limits (10 calls per 24-hour rolling window), keyed on `CF-Connecting-IP` so limits track real users behind Cloudflare, not edge nodes
3. Environment variable kill switches (`LLM_ANALYSIS_ENABLED`, `LLM_DORKGEN_ENABLED`, `LLM_DECODER_ENABLED`)
4. Prompt caching on system prompts (~90% input cost discount on repeated calls within 5 minutes)

LLM JSON output is schema-validated and clamped before use — numeric fields are type-coerced and range-clamped, string fields are truncated, enum fields (severity, intent, risk_level) are validated against known values, and finding lists are filtered to allowed keys only. LLM output is presented in the UI as model opinion, not as verified verdict.

Typical cost per LLM call: ~$0.003.

---

## Abuse Reporting

The IP Reputation and Email Header tabs can turn an identified piece of hostile infrastructure into an abuse report to the responsible provider. FalconEye resolves the abuse contact via RDAP, prefills a category-appropriate report from what it already knows, and offers two actions:

- **Copy to Clipboard** — always available, no configuration, no authentication. Paste into your own mail client and send from there.
- **Send via Mailgun** — optional. Gated behind admin HTTP Basic Auth, rate-limited per IP / per recipient / globally, and restricted to recipients FalconEye itself resolved via RDAP. Every send is written to an append-only audit log.

Compose-and-copy works out of the box. Enabling send requires reporter-identity and Mailgun environment variables plus an admin bcrypt hash. See **[docs/abuse-reporting.md](docs/abuse-reporting.md)** for the full setup guide, security posture, and current Mailgun free-tier state.

---

## Security posture

FalconEye is a public, unauthenticated OSINT tool with no login. The following controls are in place as of v3.5.0:

**SSRF prevention (Phishing Scanner + URL Expander).** All user-supplied URLs pass through the shared `safe_fetch` primitives before any HTTP request is made. `safe_fetch` resolves and validates every hop in a redirect chain independently against a complete blocklist: private/loopback/link-local/reserved/multicast/unspecified ranges (via the Python `ipaddress` stdlib), CGNAT (100.64.0.0/10), NAT64 (64:ff9b::/96), IPv4-mapped IPv6 (::ffff:a.b.c.d unwrapped before check), and the "this" network (0.0.0.0/8). The URL Expander re-runs this check (`resolve_and_check`) at the start of every hop and before its per-hop TLS grab, and rejects embedded userinfo; it does not add a second SSRF implementation. TLS certificate verification is enforced on all outbound fetches (`verify=True`). Fixed-host API calls (Shodan, RDAP, Telegram, etc.) are not routed through `safe_fetch` as they are not SSRF surfaces.

**Rate limiting.** All per-IP limits — including LLM cost controls and phishing scanner — are keyed on the `CF-Connecting-IP` header, which Cloudflare sets and nginx preserves. This header is trustworthy because nginx only accepts connections from Cloudflare IP ranges. The fallback for local development (no `CF-Connecting-IP`) is `request.client.host`.

**XSS.** Attacker-controlled strings from Telegram channel metadata, RDAP registration fields, RSS feeds, and threat intelligence APIs are escaped with `escapeHtml()` / `escapeAttr()` before any DOM insertion. The existing escape helpers are used consistently; no `innerHTML` is assigned with unescaped external data.

**Security headers.** The nginx server block sets: `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and `Strict-Transport-Security` with a one-year max-age. The CSP retains `script-src 'unsafe-inline'` for now because the frontend uses inline event handlers; removing it requires a frontend refactor to `addEventListener` bindings. `script-src` also allows `cdn.tailwindcss.com` for Tailwind and `cdnjs.cloudflare.com` for D3.

**Error isolation.** Exception strings from httpx and upstream APIs are logged server-side with `log.exception` and never echoed to the client. Client responses get generic messages only (`"Upstream service unavailable."`).

**LLM output validation.** Parsed LLM JSON is validated before any field is used in application logic. `clamp_int`, `safe_str`, and `validate_findings_list` in `app/utils/llm_response.py` prevent type errors from malformed model output reaching `max()`, `for` loops, or string operations.

**Input validation.** All SQL uses parameterized queries. The only subprocess is `whois` in list-arg form over a strictly validated domain. No `eval`, `exec`, `pickle`, `yaml.load`, or `shell=True` anywhere in the codebase.

**Origin protection.** nginx is configured to only accept inbound connections from Cloudflare IP ranges. The gunicorn listener binds to `127.0.0.1:8000` only.

---

## Stack

- **Backend**: Python 3.10+ (3.11 recommended), FastAPI, Uvicorn, Gunicorn
- **Database**: SQLite with WAL mode (caching and rate limits; no user data); Redis for Prospect and Image tab response caches
- **Frontend**: Tailwind CSS via CDN, vanilla JavaScript, D3.js for graph visualizations
- **Web server**: nginx with Cloudflare Origin Certificate; Cloudflare in front for TLS termination, DDoS protection, and edge caching
- **LLM**: Anthropic Claude Haiku 4.5 via the official Python SDK (`anthropic` package, install separately — see requirements.txt note)
- **Security**: CrowdSec community blocklist + firewall bouncer, fail2ban, ufw, SSH on non-standard port with keys-only auth

Memory footprint at idle: ~120 MB RAM. Disk: ~50 MB for code + ~20 MB SQLite cache.

---

## Self-hosting

### Prerequisites

- Ubuntu 22.04 or 24.04 VPS (1 vCPU, 1 GB RAM minimum; 2 GB recommended)
- A domain name pointed at the VPS
- Python 3.10 or later (3.11+ recommended)
- Redis installed and running locally (`sudo apt install redis-server`)
- Optional: Cloudflare account for TLS termination and DDoS protection
- Optional: Anthropic API key for LLM-powered tabs; the rest of the tool runs without it

### Quick install (automated)

```bash
sudo bash scripts/provision.sh
```

The provision script:
1. Creates `/opt/falconeye/{data,venv}` with correct ownership
2. Clones the repository to `/opt/falconeye/app_src`
3. Creates a virtualenv and installs dependencies from `requirements.txt`
4. Initializes the SQLite database
5. Installs and enables the systemd service
6. Installs the nginx vhost config

After provisioning, copy and configure the environment file:

```bash
sudo cp /opt/falconeye/app_src/.env.example /opt/falconeye/.env
sudo vi /opt/falconeye/.env   # fill in your API keys
sudo chmod 600 /opt/falconeye/.env
sudo systemctl restart falconeye
```

### Manual install

```bash
# 1. Clone
sudo mkdir -p /opt/falconeye
sudo chown $USER:$USER /opt/falconeye
cd /opt/falconeye
git clone https://github.com/osintph/falconeye.git app_src
cd app_src

# 2. Create venv and install deps
python3 -m venv /opt/falconeye/venv
/opt/falconeye/venv/bin/pip install -r requirements.txt
# Note: anthropic and extract-msg are not in requirements.txt (see below).
# Install them separately if you want LLM tabs or .msg file upload:
#   /opt/falconeye/venv/bin/pip install "anthropic>=0.25" "extract-msg>=0.28"

# 3. Configure environment
cp .env.example /opt/falconeye/.env
vi /opt/falconeye/.env      # set ANTHROPIC_API_KEY, IMAGE_UPLOAD_SECRET, etc.
chmod 600 /opt/falconeye/.env

# 4. Initialize the database
FALCONEYE_DB=/opt/falconeye/data/falconeye.db \
  /opt/falconeye/venv/bin/python scripts/db_init.py

# 5. Install systemd unit
sudo cp falconeye.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now falconeye

# 6. Install nginx vhost
sudo cp nginx/falconeye.conf /etc/nginx/sites-available/falconeye
sudo ln -sf /etc/nginx/sites-available/falconeye /etc/nginx/sites-enabled/falconeye
sudo nginx -t && sudo systemctl reload nginx
```

### Required and optional API keys

| Variable | Required | Used by | Notes |
|---|---|---|---|
| `ANTHROPIC_API_KEY` | For LLM tabs | Email Header, Dork Gen, Script Decoder | Free $5 credit on signup. Set a monthly spend limit in the Console. |
| `IMAGE_UPLOAD_SECRET` | If `IMAGE_SEARCH_ENABLED=true` | Image Search upload flow | Generate: `openssl rand -hex 32` |
| `SEARCHAPI_KEY` | For Prospect and Image tabs | Prospect dossier, Image reverse search | Free trial at searchapi.io |
| `GREYNOISE_API_KEY` | No | IP Reputation | Community tier is free |
| `ABUSECH_AUTH_KEY` | No | Sandbox History, IP Reputation | Free at auth.abuse.ch |

If a key is missing, the relevant feature degrades gracefully (returns an error card) without crashing the rest of the tool.

> **Note on `anthropic` and `extract-msg`:** These packages are not listed in `requirements.txt` because they were installed separately on the reference deployment. If you want the three LLM-powered tabs or `.msg` file upload to work, install them manually: `pip install "anthropic>=0.25" "extract-msg>=0.28"`. A future release will add them to `requirements.txt` with pinned versions.

---

## API endpoints

All write endpoints accept JSON. Rate limits are enforced per real client IP (`CF-Connecting-IP` behind Cloudflare, `request.client.host` otherwise).

| Endpoint | Method | Rate limit |
|---|---|---|
| `/api/crypto/lookup` | POST | None (upstream provider quotas apply) |
| `/api/scanner/scan` | POST | 10/minute per IP |
| `/api/domain/intel` | POST | None |
| `/api/telegram/inspect` | POST | None |
| `/api/ip/reputation` | POST | None |
| `/api/sandbox/lookup` | POST | None |
| `/api/email-header/analyze` | POST | LLM analysis: 10/IP/24h |
| `/api/email-header/upload` | POST | None |
| `/api/dork-generator/generate` | POST | 10/IP/24h |
| `/api/script-decoder/decode` | POST | 10/IP/24h |
| `/api/url/expand` | POST | 10/IP/24h |
| `/api/qr/decode` | POST | 10/IP/24h |
| `/api/news/feed` | GET | None |
| `/api/threat-pulse` | GET | None |
| `/api/image/search` | POST | 5/minute per IP |
| `/api/prospect/investigate` | POST | 10/IP/day |
| `/health` | GET | None |

OpenAPI docs are disabled in production (`FALCONEYE_PUBLIC_DOCS=false` by default).

---

## Development

```bash
cd /path/to/falconeye
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install "anthropic>=0.25" "extract-msg>=0.28"  # if you need LLM tabs locally

# Run the dev server with hot reload
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Then open `http://127.0.0.1:8000/`. Hot reload picks up Python and static file changes.

### Running tests

```bash
source .venv/bin/activate
pytest tests/ -v
```

Expected baseline: **122 passed, 3 skipped** (the 3 skips are JPEG EXIF fixture tests that need actual image files; 2 collection errors in test_routes.py modules are pre-existing Python 3.9 type-annotation incompatibilities that do not affect Python 3.10+ deployments).

### Project structure

```
falconeye/
├── app/
│   ├── main.py                  # FastAPI entry point, router registration
│   ├── config.py                # Environment variable loading
│   ├── routers/                 # One file per tab / feature
│   │   ├── crypto.py
│   │   ├── scanner.py           # Phishing Scanner — uses safe_fetch for user URLs
│   │   ├── domain_intel.py
│   │   ├── telegram_inspector.py
│   │   ├── ip_intel.py
│   │   ├── sandbox.py
│   │   ├── email_header.py
│   │   ├── dork_generator.py
│   │   ├── script_decoder.py
│   │   ├── news.py
│   │   └── threat_pulse.py
│   ├── prospect/                # Prospect tab (SearchAPI.io dossier)
│   ├── image_search/            # Image Search tab (Google Lens + Yandex)
│   └── utils/
│       ├── client_ip.py         # CF-Connecting-IP extraction
│       ├── safe_fetch.py        # SSRF-safe HTTP fetcher for user-supplied URLs
│       ├── llm_response.py      # LLM JSON validation helpers
│       ├── ssrf.py              # Legacy validate_url (used by crypto.py)
│       ├── domain.py
│       ├── indicator.py
│       └── telegram.py
├── app/static/                  # Single-page app shell (index.html, app.js, etc.)
├── scripts/
│   ├── provision.sh             # Automated VPS provisioning
│   └── db_init.py               # SQLite schema initializer
├── nginx/
│   └── falconeye.conf           # nginx vhost with security headers
├── falconeye.service            # systemd unit
├── requirements.txt
├── .env.example
├── LICENSE
├── CONTRIBUTING.md
└── README.md
```

### Adding a new tab

1. Create `app/routers/your_tab.py` with a FastAPI router
2. Register it in `app/main.py`
3. Add the tab button and content section in `app/static/index.html`
4. Add the JS handler in `app/static/app.js`
5. Add `'your_tab'` to the `VALID_TABS` array for hash routing
6. Update this README's tab table and the endpoint list above

If the tab fetches a user-supplied URL, route it through `safe_fetch` in `app/utils/safe_fetch.py` — do not use `httpx.AsyncClient` directly on user input.

If the tab uses an LLM, follow the pattern in `script_decoder.py`: hardcoded model constant, per-feature rate-limit table keyed on `CF-Connecting-IP`, environment kill switch, prompt caching, and output validation via `app/utils/llm_response.py`.

---

## Privacy posture

FalconEye does not maintain user accounts.

- Input is processed to produce analysis results and is not persisted beyond the moments needed
- Results are cached for 24 hours by SHA256 hash of the input (keyed by content, not by user)
- Uploaded .eml and .msg files are parsed in memory and discarded immediately
- Source IP is stored only for rate-limit enforcement with automatic cleanup after 48 hours
- No cookies set by FalconEye (Cloudflare sets its own security cookies)
- No third-party advertising or analytics

When you use the LLM-powered tabs, your input is sent to Anthropic's API. See [Anthropic's privacy policy](https://www.anthropic.com/legal/privacy). At time of writing, Anthropic does not train on API input by default.

---

## Roadmap

- IoC enrichment pipeline (one URL in, full report from all tabs out)
- Hash-based artifact deduplication across investigation history
- Maltego transform export for the crypto graph
- Public API tokens for trusted integrations

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

Bug reports and feature requests go to the [Contact tab](https://falconeye.osintph.info/#contact) or as a GitHub issue.

---

## License

AGPL-3.0. Strong copyleft: if you run a modified version as a network service, you must offer the modified source to users of that service. See [LICENSE](LICENSE).

---

## Acknowledgments

- abuse.ch (URLhaus, MalwareBazaar)
- GreyNoise (IP intelligence)
- Shodan InternetDB (free, no-key endpoint)
- crt.sh, Cert Spotter (certificate transparency)
- RDAP.org (RDAP queries)
- RIPEstat (ASN data)
- Blockstream, BlockCypher, TronGrid (blockchain APIs)
- Anthropic Claude Haiku 4.5 (LLM analysis)
- D3.js (graph visualization)
- Tailwind CSS (styling)

Built and maintained by [OSINT-PH](https://blog.osintph.info).
