# Contributing to FalconEye

FalconEye is an open-source OSINT workbench maintained by [OSINT-PH](https://osintph.info). Contributions are welcome within the scope described below.

---

## What is welcome

- **New data source integrations** — additional lookup APIs behind existing tabs (IP, domain, sandbox, crypto). Prefer free-tier or key-optional APIs so the tool stays accessible without accounts.
- **Bug fixes** — broken lookups, parsing failures, UI rendering issues.
- **PH Threat Pulse improvements** — better brand detection patterns, additional Philippine-specific indicators.
- **Performance fixes** — caching improvements, reducing unnecessary API round-trips.
- **Accessibility** — keyboard navigation, contrast, screen reader support.
- **Documentation** — corrections, clearer setup instructions, new deployment environments.

## What is not welcome

- Features requiring paid API keys as a hard dependency (no key = tool breaks).
- Removing or breaking existing lookups to add new ones.
- Frontend framework rewrites. The vanilla JS + Tailwind CDN stack is intentional: zero build step, easy deployment, readable source.
- Backend ORM migrations. SQLite + raw SQL is intentional.
- Features unrelated to threat intelligence, OSINT, or cyber investigation.

---

## Architecture overview

```
app/
  main.py                 — FastAPI app init, router mounts, rate limiter
  config.py               — env-var config (DB path, API keys)
  database.py             — SQLite connection factory
  routers/
    crypto.py             — BTC/ETH/USDT blockchain lookups + D3 graph data
    domain_intel.py       — RDAP, DNS, WHOIS, CT logs, network enrichment
    ip_intel.py           — GreyNoise, Shodan, AbuseIPDB, ASN lookup
    scanner.py            — Phishing kit fingerprinting
    telegram_inspector.py — Telegram public channel web scrape + IOC extraction
    sandbox.py            — URLScan, VirusTotal, MalwareBazaar, Any.run history
    news.py               — RSS/Atom feed aggregator with SQLite cache
    threat_pulse.py       — URLhaus PH country feed aggregator
  static/
    index.html            — Single-page app shell (tab layout)
    app.js                — All frontend logic (tab routing, API calls, D3 graph)
    style.css             — Minimal custom styles (Tailwind handles the rest)
scripts/
  db_init.py              — Creates all SQLite tables
  provision.sh            — Ubuntu 24.04 VPS setup (nginx, gunicorn, systemd)
```

All lookups go through FastAPI endpoints. The frontend never calls third-party APIs directly — everything is proxied through the backend, which handles rate limiting and caching.

---

## Development setup

```bash
git clone https://github.com/osintph/falconeye.git
cd falconeye
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Init the database (defaults to /opt/falconeye/data/falconeye.db)
# Override with FALCONEYE_DB env var for local dev:
export FALCONEYE_DB=./falconeye.db
python scripts/db_init.py

# Run the dev server
uvicorn app.main:app --reload --port 8000
```

Open `http://localhost:8000` in a browser.

Optional API keys (set as environment variables — the tool degrades gracefully without them):

```
ABUSECH_AUTH_KEY      — URLhaus authenticated lookups
GREYNOISE_API_KEY     — GreyNoise Community API
SHODAN_API_KEY        — Shodan InternetDB or full API
VIRUSTOTAL_API_KEY    — VirusTotal file/URL lookups
URLSCAN_API_KEY       — URLScan.io submissions
ANYRUN_API_KEY        — Any.run sandbox API
```

---

## Submitting changes

1. Fork the repo and create a branch from `main`.
2. Make the smallest change that addresses the issue. One concern per PR.
3. Test manually against the live endpoints you changed.
4. Open a PR with a clear description: what changed, why, and how you tested it.

There is no automated test suite currently. Manual verification against real indicators is the standard.

---

## License

By contributing you agree that your changes will be licensed under [AGPL-3.0](LICENSE).
