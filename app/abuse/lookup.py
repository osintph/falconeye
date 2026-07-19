"""
RDAP-based abuse contact resolution for IPs and domains.

Bootstrap via rdap.org, which 3xx-redirects to the authoritative RIR (for IPs)
or registry/registrar (for domains). Every hop is validated by
app.utils.safe_fetch — rdap.org is trusted, but outbound fetches all go through
the one SSRF primitive by policy (no second guard).

RDAP JSON is untrusted input: the abuse email is validated against a strict
regex before it is ever displayed or handed to the send layer, and lookups
NEVER raise — on any error they return the result dict with `error` populated
and the rest None.
"""
import ipaddress
import json
import logging
import re
from urllib.parse import urlparse

from app.abuse import store
from app.utils.domain import normalize_domain
from app.utils.safe_fetch import safe_fetch, SafeFetchError

log = logging.getLogger("falconeye.abuse")

RDAP_TIMEOUT = 10.0
USER_AGENT = "FalconEye/3.7 (osintph.info; abuse contact lookup)"

# Strict per the plan; rejects display names, comments, and multiple addresses.
EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")

# host substring -> RIR label
_RIR_BY_HOST = (
    ("arin", "ARIN"),
    ("ripe", "RIPE"),
    ("apnic", "APNIC"),
    ("lacnic", "LACNIC"),
    ("afrinic", "AFRINIC"),
)


def _valid_email(email) -> bool:
    return isinstance(email, str) and len(email) <= 254 and bool(EMAIL_RE.match(email))


def _clean_str(value, cap: int = 200):
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value[:cap] if value else None


def _rir_from_url(url: str) -> str:
    host = (urlparse(url).hostname or "").lower()
    for needle, name in _RIR_BY_HOST:
        if needle in host:
            return name
    return host or "unknown"


def _vcard_props(vcard_array, name: str) -> list:
    """Return the values of jCard properties named `name`.

    A jCard is ["vcard", [ [prop_name, params, type, value], ... ]].
    """
    out = []
    try:
        entries = vcard_array[1]
        for prop in entries:
            if isinstance(prop, list) and len(prop) >= 4 and prop[0] == name:
                out.append(prop[3])
    except (TypeError, IndexError):
        pass
    return out


def _collect_entities(entities, want_role: str, acc: list) -> None:
    """Recursively collect entities whose `roles` include want_role (handles nesting)."""
    if not isinstance(entities, list):
        return
    for ent in entities:
        if not isinstance(ent, dict):
            continue
        if want_role in (ent.get("roles") or []):
            acc.append(ent)
        _collect_entities(ent.get("entities"), want_role, acc)


def _extract_abuse_email(data: dict):
    """Best abuse email from an RDAP object, or None."""
    abuse_ents: list = []
    _collect_entities(data.get("entities"), "abuse", abuse_ents)
    for ent in abuse_ents:
        for val in _vcard_props(ent.get("vcardArray"), "email"):
            email = val.strip() if isinstance(val, str) else None
            if _valid_email(email):
                return email
    # Fallback: some registries only expose an "abuse@"-style address on the
    # registrant/technical/registrar contact rather than a dedicated abuse role.
    for role in ("registrar", "technical", "administrative", "registrant"):
        ents: list = []
        _collect_entities(data.get("entities"), role, ents)
        for ent in ents:
            for val in _vcard_props(ent.get("vcardArray"), "email"):
                email = val.strip() if isinstance(val, str) else None
                if _valid_email(email) and email.lower().startswith("abuse"):
                    return email
    return None


def _extract_abuse_phone(data: dict):
    abuse_ents: list = []
    _collect_entities(data.get("entities"), "abuse", abuse_ents)
    for ent in abuse_ents:
        for val in _vcard_props(ent.get("vcardArray"), "tel"):
            if isinstance(val, str) and val.strip():
                return val.strip()[:60]
    return None


def _extract_registrar(data: dict):
    ents: list = []
    _collect_entities(data.get("entities"), "registrar", ents)
    for ent in ents:
        for val in _vcard_props(ent.get("vcardArray"), "fn"):
            if isinstance(val, str) and val.strip():
                return val.strip()[:200]
    return None


def _trim_entities(data: dict) -> list:
    """A small, safe summary of entities for debugging (no raw dump)."""
    out = []
    for ent in (data.get("entities") or [])[:8]:
        if not isinstance(ent, dict):
            continue
        emails = [v for v in _vcard_props(ent.get("vcardArray"), "email") if isinstance(v, str)]
        fns = [v for v in _vcard_props(ent.get("vcardArray"), "fn") if isinstance(v, str)]
        out.append({
            "roles": ent.get("roles") or [],
            "name": (fns[0][:120] if fns else None),
            "emails": emails[:3],
        })
    return out


def _safe_error(exc: Exception) -> str:
    msg = str(exc).strip()
    if not msg:
        return f"lookup failed ({type(exc).__name__})"
    return msg[:200]


async def _rdap_fetch(url: str) -> tuple[dict, str]:
    res = await safe_fetch(
        url,
        method="GET",
        timeout=RDAP_TIMEOUT,
        max_redirects=5,
        headers={"Accept": "application/rdap+json, application/json", "User-Agent": USER_AGENT},
    )
    status = res.get("status")
    if status != 200:
        raise SafeFetchError(f"RDAP endpoint returned HTTP {status}")
    body = res.get("body") or ""
    data = json.loads(body)
    if not isinstance(data, dict):
        raise ValueError("RDAP response was not a JSON object")
    return data, res.get("url_final") or url


def _blank_result(target: str, target_type: str) -> dict:
    result = {
        "target": target,
        "target_type": target_type,
        "abuse_email": None,
        "abuse_phone": None,
        "network_name": None,
        "network_handle": None,
        "asn": None,
        "country": None,
        "rir": None,
        "source_url": None,
        "raw_entities": [],
        "error": None,
        "cache_hit": False,
    }
    if target_type == "domain":
        result["registrar"] = None
    return result


async def lookup_ip_abuse(ip: str) -> dict:
    target = (ip or "").strip()
    cached = store.get_cached_contact(target, "ip")
    if cached:
        return cached

    result = _blank_result(target, "ip")

    # Non-public IPs have no abuse contact — skip the network call entirely.
    try:
        parsed = ipaddress.ip_address(target)
        if parsed.is_private or parsed.is_loopback or parsed.is_link_local or \
           parsed.is_multicast or parsed.is_reserved or parsed.is_unspecified:
            result["error"] = "IP address is private, reserved, or non-routable; no abuse contact exists."
            return result
    except ValueError:
        result["error"] = "Not a valid IP address."
        return result

    try:
        data, final_url = await _rdap_fetch(f"https://rdap.org/ip/{target}")
    except Exception as exc:
        result["error"] = _safe_error(exc)
        return result

    result["source_url"] = final_url
    result["rir"] = _rir_from_url(final_url)
    result["network_name"] = _clean_str(data.get("name"))
    result["network_handle"] = _clean_str(data.get("handle"))
    result["country"] = _clean_str(data.get("country"), cap=10)
    result["abuse_email"] = _extract_abuse_email(data)
    result["abuse_phone"] = _extract_abuse_phone(data)
    result["raw_entities"] = _trim_entities(data)
    if not result["abuse_email"]:
        result["error"] = "No abuse contact found in the RDAP record for this IP."

    store.store_cached_contact(target, "ip", result["abuse_email"], result["network_name"], result)
    return result


async def lookup_domain_abuse(domain: str) -> dict:
    normalized = normalize_domain(domain or "")
    target = normalized or (domain or "").strip().lower()

    cached = store.get_cached_contact(target, "domain")
    if cached:
        return cached

    result = _blank_result(target, "domain")

    if not normalized:
        result["error"] = "Not a valid domain name."
        return result

    try:
        data, final_url = await _rdap_fetch(f"https://rdap.org/domain/{normalized}")
    except Exception as exc:
        result["error"] = _safe_error(exc)
        # Cache negative domain results briefly too, to avoid hammering RDAP for
        # TLDs that don't support it.
        store.store_cached_contact(target, "domain", None, None, result)
        return result

    result["source_url"] = final_url
    result["rir"] = _rir_from_url(final_url)
    result["network_name"] = _clean_str(data.get("ldhName")) or _clean_str(data.get("handle"))
    result["network_handle"] = _clean_str(data.get("handle"))
    result["registrar"] = _extract_registrar(data)
    result["abuse_email"] = _extract_abuse_email(data)
    result["abuse_phone"] = _extract_abuse_phone(data)
    result["raw_entities"] = _trim_entities(data)
    if not result["abuse_email"]:
        result["error"] = "No abuse contact found in the RDAP record for this domain."

    store.store_cached_contact(target, "domain", result["abuse_email"], result["network_name"], result)
    return result
