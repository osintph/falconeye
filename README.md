# FalconEye

**An investigator's toolkit for the open web.**

Self-hosted OSINT workbench built for Philippine cyber threat researchers. Eight tabs, zero sign-up, one command to deploy.

[![Live Demo](https://img.shields.io/badge/live-falconeye.osintph.info-fbbf24?style=flat-square)](https://falconeye.osintph.info)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue?style=flat-square)](https://python.org)
[![Platform](https://img.shields.io/badge/platform-Ubuntu%2024.04-orange?style=flat-square)](scripts/provision.sh)

---

![FalconEye landing page](docs/screenshots/landing.png)

---

## What it does

| Tab | Purpose |
|-----|---------|
| **Home** | PH Threat Pulse — live URLhaus feed stats for Philippines-hosted phishing, with top targeted brands and latest indicators |
| **Crypto** | Trace BTC, ETH, and USDT TRC20 wallets. Interactive D3 transaction graph, balance, risk flags, connected exchange detection |
| **Scanner** | Phishing kit fingerprinting. Submit a live URL and extract kit indicators: Telegram bot IDs, exfil endpoints, brand targeting |
| **Domain** | Full domain intelligence — RDAP registrar data, passive DNS, WHOIS, Certificate Transparency timeline, ASN/network enrichment |
| **Telegram** | Public Telegram channel inspector. Scrapes the web preview, extracts crypto addresses, phone numbers, links, pivots to scanners |
| **IP** | IP reputation enrichment — GreyNoise classification, Shodan open ports and CVEs, AbuseIPDB score, ASN and geolocation |
| **Sandbox** | File and URL sandbox history — URLScan, VirusTotal, MalwareBazaar, Any.run lookups in one panel |
| **News** | Aggregated cyber news across Global Cyber, Southeast Asia Threats, and Philippines Cyber categories |

---

## Screenshots

| | |
|--|--|
| ![Crypto Workbench](docs/screenshots/crypto-result.png) | ![Domain Intelligence](docs/screenshots/domain-intel.png) |
| Crypto Workbench — wallet graph + risk flags | Domain Intelligence — RDAP, DNS, CT timeline |
| ![Telegram Inspector](docs/screenshots/telegram-inspector.png) | ![IP Reputation](docs/screenshots/ip-reputation.png) |
| Telegram Inspector — IOC extraction | IP Reputation — GreyNoise + Shodan |

---

## Stack

- **Backend**: FastAPI + Gunicorn (UvicornWorker), Python 3.11
- **Storage**: SQLite with WAL mode, per-endpoint caching
- **Frontend**: Vanilla JS, Tailwind CSS (CDN), D3.js for the transaction graph
- **Proxy**: nginx with Cloudflare Origin SSL
- **Rate limiting**: slowapi (token bucket per IP)
- **No build step**: static files served as-is, zero bundler

---

## Self-hosting

### Requirements

- Ubuntu 24.04 VPS (tested on OVHcloud VPS Starter, 2 GB RAM)
- Python 3.11+
- nginx pre-installed
- Domain with Cloudflare as DNS/proxy (optional but assumed by the provision script)

### Quick deploy

```bash
git clone https://github.com/osintph/falconeye.git
cd falconeye

# Create virtualenv and install deps
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Init the database
python scripts/db_init.py

# Copy and edit the systemd service
sudo cp falconeye.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now falconeye

# Copy nginx config (edit server_name to match your domain)
sudo cp nginx/falconeye /etc/nginx/sites-available/falconeye
sudo ln -s /etc/nginx/sites-available/falconeye /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

See [`scripts/provision.sh`](scripts/provision.sh) for the full automated setup.

### Environment variables

Set these in `/etc/systemd/system/falconeye.service` under `[Service]`. All are optional — the tool degrades gracefully without API keys.

```env
FALCONEYE_DB=/opt/falconeye/data/falconeye.db

ABUSECH_AUTH_KEY=       # URLhaus authenticated lookups
GREYNOISE_API_KEY=      # GreyNoise Community API
SHODAN_API_KEY=         # Shodan InternetDB or full API
VIRUSTOTAL_API_KEY=     # VirusTotal file/URL lookups
URLSCAN_API_KEY=        # URLScan.io submissions
ANYRUN_API_KEY=         # Any.run sandbox API
```

---

## Data sources

| Source | Used for |
|--------|----------|
| [URLhaus](https://urlhaus.abuse.ch) | PH Threat Pulse phishing feed |
| [GreyNoise](https://greynoise.io) | IP noise classification |
| [Shodan](https://shodan.io) | Open ports, banners, CVEs |
| [AbuseIPDB](https://abuseipdb.com) | IP abuse score |
| [URLScan.io](https://urlscan.io) | URL sandbox history |
| [VirusTotal](https://virustotal.com) | File and URL reputation |
| [MalwareBazaar](https://bazaar.abuse.ch) | Malware sample lookup |
| [Any.run](https://any.run) | Sandbox task history |
| [Certspotter](https://sslmate.com/certspotter) | Certificate Transparency logs |
| [RIPEstat](https://stat.ripe.net) | ASN and BGP data |
| [BlockCypher](https://blockcypher.com) | BTC/ETH blockchain data |
| [TronScan](https://tronscan.org) | USDT TRC20 wallet data |

---

## Why FalconEye

Most OSINT dashboards are either too generic (built for global SOC teams) or paywalled. FalconEye is scoped to the threat landscape that matters in the Philippines — GCash, Maya, BPI, Lazada phishing; Telegram-coordinated fraud; crypto wallets used in local scam operations.

It runs on a $6/month VPS, needs no external services beyond API keys you already have, and exposes everything through a single self-hosted URL your team can bookmark.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

[GNU Affero General Public License v3.0](LICENSE) — if you run a modified version as a network service, you must publish your changes under the same license.
