import asyncio
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse

from app.prospect.client import SearchAPIClient
from app.image_search.engines import google_lens, yandex_reverse_image

log = logging.getLogger("falconeye.image_search.service")


def _bare_domain(url_or_domain: str) -> str:
    """Return a bare domain (no www. prefix) from a URL or plain domain string."""
    s = url_or_domain.strip()
    if not s:
        return ""
    if "://" in s:
        host = urlparse(s).netloc.lower()
    else:
        host = s.lower()
    return host.lstrip("www.") if host.startswith("www.") else host


def _lens_domains(lens: dict) -> set:
    domains: set = set()
    for m in lens.get("visual_matches") or []:
        src = _bare_domain(m.get("source") or "")
        if src:
            domains.add(src)
        lnk = _bare_domain(m.get("link") or "")
        if lnk:
            domains.add(lnk)
    return domains


def _yandex_domains(yandex: dict) -> set:
    domains: set = set()
    for m in yandex.get("visual_matches") or []:
        src = _bare_domain(m.get("source") or "")
        if src:
            domains.add(src)
        lnk = _bare_domain(m.get("link") or "")
        if lnk:
            domains.add(lnk)
    for group in (yandex.get("image_sizes") or {}).values():
        for item in (group if isinstance(group, list) else []):
            lnk = _bare_domain(item.get("link") or "")
            if lnk:
                domains.add(lnk)
    return domains


async def search_image(image_url: str, include_yandex: bool = True) -> dict:
    client = SearchAPIClient()

    coros = [google_lens(client, image_url)]
    if include_yandex:
        coros.append(yandex_reverse_image(client, image_url))

    raw = await asyncio.gather(*coros, return_exceptions=True)

    lens_raw = raw[0]
    yandex_raw = raw[1] if include_yandex else None

    sections: dict = {}
    errors: list = []

    if isinstance(lens_raw, Exception):
        sections["google_lens"] = None
        errors.append({"section": "google_lens", "message": str(lens_raw)})
        lens_raw = None
    else:
        sections["google_lens"] = lens_raw

    if not include_yandex:
        sections["yandex"] = None
    elif isinstance(yandex_raw, Exception):
        sections["yandex"] = None
        errors.append({"section": "yandex", "message": str(yandex_raw)})
        yandex_raw = None
    else:
        sections["yandex"] = yandex_raw

    ld = _lens_domains(lens_raw) if lens_raw else set()
    yd = _yandex_domains(yandex_raw) if yandex_raw else set()
    sections["cross_source_domains"] = sorted(ld & yd)

    return {
        "queried_url": image_url,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sections": sections,
        "errors": errors,
    }
