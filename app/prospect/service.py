import asyncio
import re
from datetime import datetime, timezone

from app.prospect.client import SearchAPIClient
from app.prospect.engines import (
    about_domain,
    ads_transparency,
    ads_transparency_historical,
    google_jobs_search,
    google_news_search,
    meta_ads,
    meta_page_search,
)

_SUFFIX_RE = re.compile(
    r"\s*,?\s*(Inc|LLC|Ltd|LTD|GmbH|Corp|Corporation|Co|PLC|AG|BV|SAS|SRL|SA|NV)\b\.?$",
    re.IGNORECASE,
)


def derive_company_name(domain: str, about_data: dict) -> str:
    """Return the best human-readable company name for use in downstream queries."""
    if about_data:
        kg = about_data.get("knowledge_graph", {})
        if kg.get("title"):
            return kg["title"]
        atr = about_data.get("about_this_result", {})
        if atr.get("title"):
            name = _SUFFIX_RE.sub("", atr["title"]).strip()
            if name:
                return name
    root = domain.split(".")[0]
    return root.capitalize()


def _section(sections, errors, name, result, optional=False):
    """Populate sections/errors from a gather result. optional=True means no error on None."""
    if result is None and optional:
        sections[name] = None
    elif isinstance(result, Exception):
        sections[name] = None
        errors.append({"section": name, "message": str(result)})
    else:
        sections[name] = result


async def build_dossier(domain: str) -> dict:
    client = SearchAPIClient()

    # Seed query from domain root; updated with proper name after wave 1
    seed_name = domain.split(".")[0].capitalize()

    # Wave 1: five calls in parallel
    wave1 = await asyncio.gather(
        about_domain(client, domain),
        ads_transparency(client, domain),
        meta_page_search(client, seed_name),
        google_news_search(client, seed_name),
        google_jobs_search(client, seed_name),
        return_exceptions=True,
    )
    about_res, ads_30d_res, meta_search_res, news_res, jobs_res = wave1

    about_data = about_res if not isinstance(about_res, Exception) else None
    company_name = derive_company_name(domain, about_data)

    # Derive IDs for wave 2 from wave 1 results
    advertiser_id = None
    if not isinstance(ads_30d_res, Exception) and ads_30d_res:
        creatives = ads_30d_res.get("ad_creatives") or []
        if creatives and (creatives[0].get("advertiser") or {}).get("id"):
            advertiser_id = creatives[0]["advertiser"]["id"]

    page_id = None
    if not isinstance(meta_search_res, Exception) and meta_search_res:
        pages = meta_search_res.get("page_results") or []
        if pages:
            page_id = pages[0].get("page_id")

    # Wave 2: chains from wave 1 results (ads historical and meta ads)
    wave2_keys = []
    wave2_coros = []
    if advertiser_id:
        wave2_coros.append(ads_transparency_historical(client, advertiser_id))
        wave2_keys.append("ads_transparency_historical")
    if page_id:
        wave2_coros.append(meta_ads(client, page_id))
        wave2_keys.append("meta_ads")

    wave2_by_key = {}
    if wave2_coros:
        wave2_raw = await asyncio.gather(*wave2_coros, return_exceptions=True)
        wave2_by_key = dict(zip(wave2_keys, wave2_raw))

    sections = {}
    errors = []

    _section(sections, errors, "about_domain", about_res)
    _section(sections, errors, "ads_transparency", ads_30d_res)
    _section(sections, errors, "meta_page_search", meta_search_res)
    _section(sections, errors, "google_news", news_res)
    _section(sections, errors, "google_jobs", jobs_res)

    # Wave 2 sections (absent if prerequisite was missing)
    _section(
        sections, errors,
        "ads_transparency_historical",
        wave2_by_key.get("ads_transparency_historical"),
        optional=advertiser_id is None,
    )
    _section(
        sections, errors,
        "meta_ads",
        wave2_by_key.get("meta_ads"),
        optional=page_id is None,
    )

    return {
        "domain": domain,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "derived": {"company_name": company_name},
        "sections": sections,
        "errors": errors,
    }
