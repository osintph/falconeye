# FalconEye

**Free, self-hosted OSINT investigator's toolkit.** Thirteen modules in one interface: crypto wallet tracing, phishing kit fingerprinting, domain intelligence, Telegram OSINT, IP reputation, email header forensics with LLM-powered scam detection, Google dork generation, suspicious script deobfuscation, commercial prospect dossiers, and a curated cyber news aggregator with a Philippines-focused threat pulse.

Live instance: [falconeye.osintph.info](https://falconeye.osintph.info)

License: AGPL-3.0

---

## What it does

FalconEye is the workbench an OSINT investigator opens when a new lead lands on the desk. Each tab is a focused tool that does one thing well and connects to the others via one-click pivots, so you can move from "I have a wallet address" to "here are the related domains, the email infrastructure, the Telegram channel, and the script the phishing kit runs" without switching applications.

### The thirteen tabs

| Tab | What it does |
|---|---|
| **Home** | Landing page with PH Threat Pulse widget, example cards that prefill other tabs, and a curated news strip |
| **Crypto Workbench** | Trace Bitcoin, Ethereum, and USDT TRC20 addresses with D3 force-directed transaction graphs and labelled clusters |
| **Phishing Scanner** | Fingerprint phishing kits by URL or pasted HTML, identify the kit family, extract IOCs |
| **Domain Intelligence** | RDAP, DNS, certificate transparency logs (crt.sh + Cert Spotter fallback), RIPEstat ASN data |
| **Telegram Inspector** | Scrape public Telegram channels (t.me/s/) for messages and extract IOCs (URLs, wallets, contact details) |
| **IP Reputation** | Shodan InternetDB, GreyNoise Community, RIPEstat, URLhaus, reverse DNS |
| **Sandbox History** | URLhaus and MalwareBazaar lookup by URL or file hash |
| **Email Header** | Authentication checks (SPF/DKIM/DMARC), hop analysis, scam pattern detection in body. LLM-powered classification of advance fee fraud, BEC, romance scams, crypto scams, credential phishing. Supports .eml and .msg file upload. |
| **Dork Generator** | LLM-powered Google search query generator with eleven preset categories (exposed files, admin panels, credential leaks, cloud buckets, VPN portals, etc) and free-form natural-language input |
| **Script Decoder** | LLM-powered deobfuscation of suspicious PowerShell, JavaScript, VBA, Base64 blobs, and packed scripts. Returns deobfuscated code, IOCs, MITRE ATT&CK techniques, and detection suggestions |
| **Prospect** | Commercial intelligence dossier for any domain — Google About This Domain identity (knowledge graph, company info) and Google Ads Transparency Center (ad count, advertiser ID, creative thumbnails, date range). Requires a SearchAPI.io key. Results cached 6 hours in Redis. |
| **Contact** | Feedback form for bug reports, feature requests, and new tab suggestions |
| **News** | Cyber news RSS aggregator with PH-specific feeds (Rappler, Inquirer, GMA, Philstar, Manila Times) and global outlets |

### LLM-powered features

Three tabs use Anthropic's Claude Haiku 4.5 for analysis: **Email Header**, **Dork Generator**, and **Script Decoder**. The model is hardcoded in code (not configurable, intentionally) and protected by four cost safeguards:

1. Anthropic Console spend limits at the API account level
2. Per-feature, per-IP rate limits (10 generations per 24-hour rolling window)
3. Environment variable kill switches (`LLM_ANALYSIS_ENABLED`, `LLM_DORKGEN_ENABLED`, `LLM_DECODER_ENABLED`)
4. Prompt caching on the system prompt (90% input cost discount on repeated calls within 5 minutes)

Typical cost per LLM call: ~$0.003. The live instance runs on $5 of prepaid Anthropic credits with a $4/month hard cap.

---

## Privacy posture

FalconEye does not maintain user accounts and stores only short-lived caches keyed by content hash, not by user identity.

- Input you submit is processed to produce analysis results
- Results are cached for 24 hours by SHA256 hash of the input
- The raw input itself is not persisted beyond the moments needed to process it
- Uploaded .eml and .msg files are parsed in memory and discarded immediately
- Source IP is stored only for rate-limit enforcement, with automatic cleanup after 48 hours
- No cookies set by FalconEye (Cloudflare may set its own for security)
- No third-party advertising or analytics
- Full privacy policy accessible from the footer link on every tab

When you use the LLM-powered tabs, your input is sent to Anthropic's API. See [Anthropic's privacy policy](https://www.anthropic.com/legal/privacy). At time of writing, Anthropic does not use API input to train their models by default.

---

## Stack

- **Backend**: Python 3.11+, FastAPI, Uvicorn, Gunicorn
- **Database**: SQLite with WAL mode (for caching and rate limits only, no user data); Redis for Prospect tab response cache
- **Frontend**: Tailwind CSS via CDN, vanilla JavaScript, D3.js for graph visualizations
- **Web server**: nginx with Cloudflare Origin Certificate
- **CDN / DDoS**: Cloudflare (Free tier, with Cache Rules for static assets)
- **LLM**: Anthropic Claude Haiku 4.5 via the official Python SDK
- **Security**: CrowdSec community blocklist + firewall bouncer, fail2ban, ufw, SSH on non-standard port with keys-only auth

Memory footprint at idle: ~120 MB RAM. Disk: ~50 MB for code + ~20 MB SQLite cache that auto-trims.

---

## Self-hosting

### Prerequisites

- Ubuntu 22.04 / 24.04 VPS (1 vCPU, 1 GB RAM minimum, 2 GB recommended)
- A domain name pointed at the VPS
- Python 3.11+
- Optional: Cloudflare account for TLS and DDoS protection
- Optional: Anthropic API key if you want the LLM-powered tabs to work (free tier of FalconEye runs fine without)

### Install

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

# 3. Configure environment
cp .env.example /opt/falconeye/.env
vi /opt/falconeye/.env
# Set ANTHROPIC_API_KEY if you want LLM tabs to work
# Set SHODAN_API_KEY, GREYNOISE_API_KEY for IP Reputation (free tiers available)
# Set ABUSECH_AUTH_KEY for Sandbox History (free at abuse.ch)
chmod 600 /opt/falconeye/.env

# 4. Initialize the database
/opt/falconeye/venv/bin/python -c "from app.main import app; print('DB ready')"

# 5. Install systemd unit (sample provided in deploy/)
sudo cp deploy/falconeye.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now falconeye

# 6. nginx vhost (sample in deploy/)
sudo cp deploy/falconeye.nginx /etc/nginx/sites-available/falconeye
sudo ln -s /etc/nginx/sites-available/falconeye /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

### Required API keys

All free tiers are sufficient for personal use.

| Service | Used by | Get a key |
|---|---|---|
| **Anthropic** | Email Header (LLM), Dork Gen, Script Decoder | https://console.anthropic.com |
| **Shodan** | IP Reputation, Phishing Scanner | https://account.shodan.io |
| **GreyNoise** | IP Reputation | https://viz.greynoise.io/account |
| **abuse.ch (URLhaus/MalwareBazaar)** | Sandbox History, IP Reputation | https://auth.abuse.ch |

If you do not provide a key, the relevant tab degrades gracefully (returns "API key not configured" without crashing).

### Optional but recommended

- **CrowdSec** for community-driven IP blocklists (`curl -s https://install.crowdsec.net | sudo sh`)
- **GoAccess** for nginx log analytics
- **fail2ban** for SSH brute-force protection
- **Cloudflare** in front for TLS, DDoS protection, and edge caching

---

## API endpoints

All endpoints accept JSON POST. Rate limits noted where applicable.

| Endpoint | Method | Rate limit |
|---|---|---|
| `/api/crypto/lookup` | POST | None (relies on upstream provider quotas) |
| `/api/scanner/scan` | POST | None |
| `/api/domain/intel` | POST | None |
| `/api/telegram/inspect` | POST | None |
| `/api/ip/reputation` | POST | None |
| `/api/sandbox/lookup` | POST | None |
| `/api/email-header/analyze` | POST | LLM body analysis: 10/IP/24h |
| `/api/email-header/upload` | POST | None |
| `/api/dork-generator/generate` | POST | 10/IP/24h |
| `/api/script-decoder/decode` | POST | 10/IP/24h |
| `/api/news/feed` | GET | None |
| `/api/threat-pulse` | GET | None |

---

## Development

```bash
cd app_src
/opt/falconeye/venv/bin/uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Then point your browser at http://127.0.0.1:8000/. Hot reload picks up Python and static file changes automatically.

### Project structure

```
app_src/
├── app/
│   ├── main.py              # FastAPI entrypoint, router registration
│   ├── config.py            # Environment variable loading
│   ├── routers/             # One file per tab
│   │   ├── crypto.py
│   │   ├── scanner.py
│   │   ├── domain_intel.py
│   │   ├── telegram_inspector.py
│   │   ├── ip_intel.py
│   │   ├── sandbox.py
│   │   ├── email_header.py
│   │   ├── dork_generator.py
│   │   ├── script_decoder.py
│   │   ├── news.py
│   │   └── threat_pulse.py
│   └── static/
│       ├── index.html       # Single-page app shell
│       ├── app.js           # All client-side logic
│       ├── style.css
│       ├── favicon.svg
│       ├── robots.txt
│       └── sitemap.xml
├── deploy/                  # Sample systemd unit, nginx vhost
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
6. Update this README's tab table and the sitemap

If your tab uses an LLM, copy the safeguard pattern from `script_decoder.py`: hardcoded model constant, per-feature rate-limit table, environment kill switch, prompt caching, defensive JSON parsing.

---

## Roadmap

Things on the list but not yet built. Pull requests welcome.

- IoC enrichment pipeline (one URL in, full report from all tabs out)
- Hash-based artifact deduplication across investigation history
- Maltego transform export for the crypto graph
- Public API tokens for trusted integrations (with proper rate limits)
- Webhook support for News and Threat Pulse subscriptions

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

Bug reports, feature requests, and new tab suggestions go to the [Contact tab](https://falconeye.osintph.info/#contact) on the live site or as a GitHub issue.

---

## License

AGPL-3.0. Strong copyleft. If you run a modified version as a network service, you must offer the source code of your modified version to the users of that service. See [LICENSE](LICENSE) for the full text.

---

## Acknowledgments

FalconEye builds on the work of many open services and tools, all linked from the footer of the live site:

- abuse.ch (URLhaus, MalwareBazaar)
- Shodan, GreyNoise (IP intelligence)
- crt.sh, Cert Spotter (certificate transparency)
- RDAP.org (RDAP queries)
- RIPEstat (ASN data)
- Blockstream, BlockCypher, TronGrid (blockchain APIs)
- Anthropic Claude Haiku 4.5 (LLM analysis)
- D3.js (graph visualization)
- Tailwind CSS (styling)

Built and maintained by [OSINT-PH](https://blog.osintph.info).
