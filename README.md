# FalconEye

Continuous threat intelligence and vulnerability watchdog for Philippine digital infrastructure.

FalconEye monitors authoritative global threat feeds and vulnerability catalogs, filters them to surface entries with PH relevance (.ph TLDs, PH-allocated ASNs, local brand strings, and technology stacks heavily deployed in PH government and financial sectors), and publishes the filtered result as a public, static, zero-attack-surface dashboard.

Part of the [OSINT-PH](https://osintph.info) tool suite.

## Status

**v0.1: in active development.** Public dashboard is not yet live. See the [project spec](SPEC.md) for the design and the [implementation notes](IMPLEMENTATION_NOTES.md) for operational details.

## What it does

- Ingests four authoritative free threat intelligence and vulnerability sources every 15 minutes to 24 hours
- Filters records against PH-specific criteria: ASN allocations from APNIC, .ph TLD, PH brand string watchlist, PH-relevant CPE inventory
- Generates a static HTML dashboard, RSS feed, JSON feed, and corpus manifest
- Serves everything via nginx as static files (no dynamic application code in the public request path)
- Maintains chain-of-custody provenance for every record (source feed, fetch timestamp, source URL, manifest version)

## Data sources (v0.1)

| Source | What it provides |
|---|---|
| [abuse.ch URLhaus](https://urlhaus.abuse.ch/) | Active malicious URL feed |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known exploited vulnerabilities |
| [NVD CVE 2.0](https://nvd.nist.gov/) | All CVE records |
| [APNIC delegated stats](https://ftp.apnic.net/apnic/stats/apnic/) | PH ASN and IP prefix allocations |

All sources are free, require no credit card, and use stable JSON/CSV/text endpoints with versioned schemas.

## Roadmap

- **v0.1 (in progress):** ingest + static dashboard + RSS + JSON
- **v0.2 (planned):** FalconEye-Match analyst lookup tool with Bloom filter prefilter, 2-hex sharded indices, and a `falconeye-cli` for bulk and offline lookups. k-anonymous request model.
- **v0.3 (planned):** Brotli precompression, TAXII 2.1 server endpoint, EPSS API integration, additional ingest sources.

See [SPEC.md](SPEC.md) for full design details.

## Self-hosting

A `docker-compose.yml` will be published when v0.1 ships. The canonical deployment is bare systemd plus nginx on Ubuntu 24.04 LTS, documented in [IMPLEMENTATION_NOTES.md](IMPLEMENTATION_NOTES.md). Minimum VPS specs: 2 vCPU, 4 GB RAM, 40 GB SSD.

You need free API keys from:

- [abuse.ch](https://auth.abuse.ch/) for URLhaus
- [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key) for NVD (technically optional, but rate limits are punishing without one)

Neither requires a payment method.

## Defensive use only

FalconEye is built to help PH defenders. It is not a target acquisition tool, it does not perform any active scanning, and it does not enumerate vulnerabilities in PH systems beyond what the upstream sources have already publicly disclosed. The intended audience is PH government CERTs, bank SOCs, ISP security teams, MSPs, and independent investigators working on PH incidents.

If you are a PH organization and want a specific brand string added to the watchlist, please open a GitHub issue or contact the maintainer.

## License

[AGPL v3](LICENSE)

## Acknowledgments

FalconEye stands on the shoulders of free public threat intelligence projects. abuse.ch, CISA, NIST NVD, and APNIC all publish their data in machine-consumable formats specifically so tools like this can exist. Their work is the foundation; FalconEye is the regional filter.

## Maintainer

Sigmund Brandstaetter, OSINT-PH. Reach me at [sigmund@osintph.net](mailto:sigmund@osintph.net) or via the [OSINT-PH blog](https://blog.osintph.info).

Part of the OSINT-PH suite alongside Bantay-Eye and related defensive tools.
