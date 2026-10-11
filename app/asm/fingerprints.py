"""Subdomain-takeover fingerprints, vendored from EdOverflow/can-i-take-over-xyz.

The data (data/takeover_fingerprints.json, CC BY 4.0) lists, per service, the
CNAME targets that point at it and a response body fingerprint that shows the
backing resource is unclaimed. A host with a dangling CNAME whose response body
carries one of these fingerprints is a takeover candidate.

That project is only patchily maintained, so findings.py also flags the plainer
case on its own: a CNAME that resolves to NXDOMAIN, which is a dangling pointer
regardless of any fingerprint. Attribution is required by the licence and is
printed on the report (ATTRIBUTION). No em dashes in this module.
"""
from __future__ import annotations

import json
import logging
import pathlib
from typing import Optional

log = logging.getLogger("falconeye.asm.fingerprints")

_DATA = pathlib.Path(__file__).resolve().parent / "data" / "takeover_fingerprints.json"

ATTRIBUTION = "Subdomain takeover fingerprints from EdOverflow/can-i-take-over-xyz (CC BY 4.0)."


def _load() -> list:
    try:
        data = json.loads(_DATA.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - a missing list disables the check, never 500s
        log.warning("asm.fingerprints: could not load data: %s", exc)
        return []
    return data if isinstance(data, list) else []


_ENTRIES = _load()


def _cname_matches(cname: str, patterns) -> bool:
    host = (cname or "").strip().rstrip(".").lower()
    if not host:
        return False
    for pat in patterns or []:
        pat = (pat or "").strip().rstrip(".").lower()
        if not pat:
            continue
        if host == pat or host.endswith("." + pat) or host.endswith(pat):
            return True
    return False


def match(cname: str, http_body: str = "", cname_nxdomain: bool = False) -> Optional[dict]:
    """A takeover candidate for this host, or None.

    A match needs the CNAME to point at a known service AND either the service's
    body fingerprint to be present in the fetched page, or the CNAME target to be
    NXDOMAIN when that service is known to be vulnerable on a dangling pointer.
    """
    body = http_body or ""
    for entry in _ENTRIES:
        if not _cname_matches(cname, entry.get("cname")):
            continue
        service = entry.get("service") or "unknown service"
        status = (entry.get("status") or "").strip() or "Unknown"
        vulnerable = bool(entry.get("vulnerable"))
        fp = (entry.get("fingerprint") or "").strip()
        if fp and fp in body:
            return {"service": service, "status": status, "vulnerable": vulnerable,
                    "reason": "response fingerprint matched"}
        if cname_nxdomain and (vulnerable or entry.get("nxdomain")):
            return {"service": service, "status": status, "vulnerable": vulnerable,
                    "reason": "CNAME target does not resolve (NXDOMAIN)"}
    return None
