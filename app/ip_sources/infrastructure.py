"""
Addresses that belong to widely-used shared infrastructure.

WHY THIS EXISTS
---------------
`9.9.9.9` and `185.199.110.153` were reported as MALICIOUS by this tool. The
first is Quad9's public resolver, the second is one of the four addresses GitHub
tells every Pages user to point their apex domain at. Both are used on purpose by
millions of people.

Part of that was a verdict bug (see reputation.py: an OTX pulse count was being
treated as a finding). The other part is this: an abuse report against a shared
address is a report about **one tenant or one resolver client**, not about the
address. A CDN edge serves a phishing page and a hospital's website from the same
IP; a public resolver answers a botnet's queries and a school's. Reporting that
address as malicious is wrong in the way that matters, because the operator
reading the card will block it.

So a match here caps the verdict at SUSPICIOUS and says why. It never hides the
evidence, and it never raises a verdict: an address with nothing against it stays
CLEAN.

WHAT GOES IN, AND WHAT DOES NOT
-------------------------------
Only addresses the operator of the service **publishes** as its own, with the URL
recorded below and the date it was checked. That is the whole admission rule. No
"looks like a CDN" heuristics, no ASN guesses, no third-party aggregations: an
allowlist that suppresses findings has to be auditable, and every entry here has
to be checkable against a page its vendor controls.

Deliberately NOT included:

- **AWS CloudFront, Akamai, Azure Front Door.** Their published ranges are large,
  change often, and are distributed as files meant to be fetched and refreshed
  (AWS ships `ip-ranges.json` with a `syncToken`). Pinning a snapshot here would
  be stale within weeks and wrong in the silent direction. If they are wanted,
  they need a fetcher with a refresh job, not a literal.
- **Hosting and VPS ranges.** A VPS address is used by one customer, so abuse
  reports against it are about that customer. That is the case where the report
  is right and the operator should see MALICIOUS.

Cloudflare's edge ranges are reused from `app/utils/cloudflare_ips.py`, which
already holds the published list and is tested against the nginx allowlist, so
there is one copy in the tree rather than two that can drift.
"""
import ipaddress

from app.utils.cloudflare_ips import CLOUDFLARE_IPV4, CLOUDFLARE_IPV6

# Every entry carries the vendor page it was read from and the date it was
# checked. `kind` is what the address is, in the words the card uses.
ENTRIES = (
    {
        "label": "Google Public DNS",
        "kind": "resolver",
        "source": "https://developers.google.com/speed/public-dns/docs/using",
        "verified": "2026-09-27",
        "addresses": (
            "8.8.8.8", "8.8.4.4",
            "2001:4860:4860::8888", "2001:4860:4860::8844",
        ),
        "cidrs": (),
    },
    {
        "label": "Cloudflare 1.1.1.1 resolver",
        "kind": "resolver",
        "source": "https://developers.cloudflare.com/1.1.1.1/ip-addresses/",
        "verified": "2026-09-27",
        # Standard, plus the two "for Families" variants, all published on that
        # page. People configure all three.
        "addresses": (
            "1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001",
            "1.1.1.2", "1.0.0.2", "2606:4700:4700::1112", "2606:4700:4700::1002",
            "1.1.1.3", "1.0.0.3", "2606:4700:4700::1113", "2606:4700:4700::1003",
        ),
        "cidrs": (),
    },
    {
        "label": "Quad9",
        "kind": "resolver",
        "source": "https://quad9.net/service/service-addresses-and-features/",
        "verified": "2026-09-27",
        # Secured, secured with ECS, and unsecured, as published.
        "addresses": (
            "9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9",
            "9.9.9.11", "149.112.112.11", "2620:fe::11", "2620:fe::fe:11",
            "9.9.9.10", "149.112.112.10", "2620:fe::10", "2620:fe::fe:10",
        ),
        "cidrs": (),
    },
    {
        "label": "OpenDNS",
        "kind": "resolver",
        "source": "https://www.opendns.com/setupguide/",
        "verified": "2026-09-27",
        # The setup guide publishes IPv4 only, so that is what is listed.
        "addresses": (
            "208.67.222.222", "208.67.220.220",
            "208.67.222.123", "208.67.220.123",
        ),
        "cidrs": (),
    },
    {
        "label": "GitHub Pages",
        "kind": "cdn",
        # noqa: E501 - kept on one line so the citation is greppable
        "source": "https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/managing-a-custom-domain-for-your-github-pages-site",
        "verified": "2026-09-27",
        # The exact A and AAAA records GitHub tells apex domains to use. Not the
        # surrounding /22: only these are published.
        "addresses": (
            "185.199.108.153", "185.199.109.153", "185.199.110.153", "185.199.111.153",
            "2606:50c0:8000::153", "2606:50c0:8001::153",
            "2606:50c0:8002::153", "2606:50c0:8003::153",
        ),
        "cidrs": (),
    },
    {
        "label": "Cloudflare edge",
        "kind": "cdn",
        "source": "https://www.cloudflare.com/ips/",
        "verified": "2026-09-27",
        "addresses": (),
        # Shared with the origin-trust list rather than copied, see the module
        # docstring.
        "cidrs": tuple(CLOUDFLARE_IPV4) + tuple(CLOUDFLARE_IPV6),
    },
    {
        "label": "Fastly edge",
        "kind": "cdn",
        "source": "https://api.fastly.com/public-ip-list",
        "verified": "2026-09-27",
        "addresses": (),
        "cidrs": (
            "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24",
            "103.245.222.0/23", "103.245.224.0/24", "104.156.80.0/20",
            "140.248.64.0/18", "140.248.128.0/17", "146.75.0.0/17",
            "151.101.0.0/16", "157.52.64.0/18", "167.82.0.0/17",
            "167.82.128.0/20", "167.82.160.0/20", "167.82.224.0/20",
            "172.111.64.0/18", "185.31.16.0/22", "199.27.72.0/21",
            "199.232.0.0/16",
            "2a04:4e40::/32", "2a04:4e42::/32",
        ),
    },
)


def _compile():
    """(exact address -> entry, [(network, entry)]) built once at import."""
    exact: dict = {}
    networks: list = []
    for entry in ENTRIES:
        for address in entry["addresses"]:
            try:
                exact[ipaddress.ip_address(address)] = entry
            except ValueError:  # pragma: no cover - a typo in the literals above
                continue
        for cidr in entry["cidrs"]:
            try:
                networks.append((ipaddress.ip_network(cidr), entry))
            except ValueError:  # pragma: no cover
                continue
    return exact, networks


_EXACT, _NETWORKS = _compile()


def classify(ip) -> dict | None:
    """What this address is, or None if it is not published infrastructure.

    Returns a small dict the verdict and the card can both use:
    ``{"label", "kind", "source"}``. Never raises: an unparseable value is simply
    not infrastructure.
    """
    if not ip or not isinstance(ip, str):
        return None
    try:
        address = ipaddress.ip_address(ip.strip())
    except ValueError:
        return None

    entry = _EXACT.get(address)
    if entry is None:
        for network, candidate in _NETWORKS:
            if address.version == network.version and address in network:
                entry = candidate
                break
    if entry is None:
        return None
    return {"label": entry["label"], "kind": entry["kind"], "source": entry["source"]}
