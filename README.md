# FalconEye v2

Philippine-scoped counter-fraud intelligence platform.

## Modules

- **Phishing Kit Scanner** — fingerprints PH phishing kit indicators from URL or raw HTML
- **Scam Text Repository** — crowdsourced archive of PH-targeted smishing messages

## Stack

FastAPI, Uvicorn/Gunicorn, SQLite (WAL), nginx, Cloudflare Origin SSL

## Deployment

See `scripts/provision.sh`. Requires Ubuntu 24.04, nginx pre-installed.

## v2 Scope

Receipt analyzer is explicitly deferred to v3. Do not add it to this codebase.
