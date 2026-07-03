"""
Company tab service layer.

Wave structure:
  Preliminary: about_domain (sequential; drives identity resolution)
  Wave 1:      ads_transparency, meta_page_search, google_news, google_jobs (parallel)
  Wave 2:      ads_transparency_historical, meta_ads (parallel; chain from wave 1)

Query construction and result filtering are driven by the resolved CompanyIdentity.
"""
import asyncio
import logging
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
from app.prospect.resolver import CompanyIdentity, resolve_identity

log = logging.getLogger("falconeye.prospect.service")

try:
    from rapidfuzz.fuzz import partial_ratio as _partial_ratio
    _HAVE_RAPIDFUZZ = True
except ImportError:
    _HAVE_RAPIDFUZZ = False
    log.warning("rapidfuzz not installed; jobs validation disabled")


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _validation_tokens(identity: CompanyIdentity) -> set:
    """Build a set of lowercase strings used to judge result relevance."""
    tokens = set()
    for word in identity.canonical_name.replace(",", " ").split():
        if len(word) > 3:
            tokens.add(word.lower())
    for alias in identity.aliases:
        if not alias:
            continue
        tokens.add(alias.lower())
        for word in alias.replace(",", " ").split():
            if len(word) > 2:
                tokens.add(word.lower())
    return tokens


def _article_relevant(article: dict, tokens: set) -> bool:
    text = (
        (article.get("title") or "") + " " + (article.get("snippet") or "")
    ).lower()
    return any(t in text for t in tokens)


async def _fetch_news(
    client: SearchAPIClient,
    query: str,
    domain: str,
    identity: CompanyIdentity,
) -> dict:
    """Fetch and validate news. Retries with site-scoped query if drop rate >60%."""
    result = await google_news_search(client, query)
    articles = result.get("organic_results") or []

    if not articles or identity.confidence == "low":
        return result

    tokens = _validation_tokens(identity)

    passed = []
    dropped = 0
    for a in articles:
        if _article_relevant(a, tokens):
            passed.append(a)
        else:
            dropped += 1
            log.info(
                "news.drop domain=%s title=%r reason=no_identity_token",
                domain, (a.get("title") or "")[:80],
            )

    if articles and dropped / len(articles) > 0.6:
        log.warning(
            "news.high_drop domain=%s drop_pct=%d%% retrying_stricter",
            domain, int(dropped / len(articles) * 100),
        )
        retry_query = f'"{identity.canonical_name}" site:{domain}'
        try:
            result2 = await google_news_search(client, retry_query)
            articles2 = result2.get("organic_results") or []
            if articles2:
                result = result2
                passed = [a for a in articles2 if _article_relevant(a, tokens)]
        except Exception as exc:
            log.warning("news.retry_failed domain=%s error=%s", domain, exc)

    out = dict(result)
    out["organic_results"] = passed
    out["_validation_dropped"] = dropped
    return out


def _filter_jobs(jobs: list, identity: CompanyIdentity, domain: str) -> list:
    """Drop jobs whose company_name does not fuzzy-match the resolved identity."""
    if not _HAVE_RAPIDFUZZ:
        return jobs

    targets = [identity.canonical_name] + [a for a in identity.aliases if a]
    kept = []
    for job in jobs:
        jc = (job.get("company_name") or "").strip()
        if not jc:
            log.info("jobs.drop domain=%s reason=missing_company_name", domain)
            continue
        if any(_partial_ratio(jc.lower(), t.lower()) >= 75 for t in targets):
            kept.append(job)
        else:
            log.info(
                "jobs.drop domain=%s job_company=%r reason=fuzzy_mismatch",
                domain, jc,
            )
    return kept


# ---------------------------------------------------------------------------
# Section helper
# ---------------------------------------------------------------------------

def _section(sections: dict, errors: list, name: str, result, optional: bool = False) -> None:
    if result is None and optional:
        sections[name] = None
    elif isinstance(result, Exception):
        sections[name] = None
        errors.append({"section": name, "message": str(result)})
    else:
        sections[name] = result


# ---------------------------------------------------------------------------
# Main dossier builder
# ---------------------------------------------------------------------------

async def build_dossier(domain: str) -> dict:
    client = SearchAPIClient()

    # ------------------------------------------------------------------
    # Preliminary: about_domain drives identity resolution
    # ------------------------------------------------------------------
    about_exc = None
    about_result = None
    try:
        about_result = await about_domain(client, domain)
    except Exception as exc:
        about_exc = exc

    identity = resolve_identity(domain, about_result)

    # ------------------------------------------------------------------
    # Query construction from resolved identity
    # ------------------------------------------------------------------
    if identity.confidence in ("high", "medium"):
        news_query = f'"{identity.canonical_name}" OR site:{domain}'
        jobs_query = f'"{identity.canonical_name}"'
        run_jobs = True
    else:
        news_query = f"site:{domain}"
        jobs_query = None
        run_jobs = False

    # Prefer the shorter display_name for page-name search on Meta
    meta_query = identity.display_name

    # ------------------------------------------------------------------
    # Wave 1: ads, meta_page_search, news, optional jobs
    # ------------------------------------------------------------------
    wave1_coros = [
        ads_transparency(client, domain),
        meta_page_search(client, meta_query),
        _fetch_news(client, news_query, domain, identity),
    ]
    wave1_keys = ["ads_transparency", "meta_page_search", "google_news"]

    if run_jobs:
        wave1_coros.append(google_jobs_search(client, jobs_query))
        wave1_keys.append("google_jobs")

    wave1_raw = await asyncio.gather(*wave1_coros, return_exceptions=True)
    wave1 = dict(zip(wave1_keys, wave1_raw))

    # Validate jobs when call was made
    jobs_result = wave1.get("google_jobs")
    if run_jobs and not isinstance(jobs_result, Exception) and isinstance(jobs_result, dict):
        raw_jobs = jobs_result.get("jobs") or []
        wave1["google_jobs"] = dict(jobs_result, jobs=_filter_jobs(raw_jobs, identity, domain))

    # ------------------------------------------------------------------
    # Wave 2: ads_historical and meta_ads (dependent on wave 1)
    # ------------------------------------------------------------------
    ads_30d = wave1.get("ads_transparency")
    meta_search = wave1.get("meta_page_search")

    advertiser_id = None
    if not isinstance(ads_30d, Exception) and ads_30d:
        creatives = ads_30d.get("ad_creatives") or []
        if creatives and (creatives[0].get("advertiser") or {}).get("id"):
            advertiser_id = creatives[0]["advertiser"]["id"]

    page_id = None
    if not isinstance(meta_search, Exception) and meta_search:
        pages = meta_search.get("page_results") or []
        if pages:
            page_id = pages[0].get("page_id")

    wave2_coros, wave2_keys = [], []
    if advertiser_id:
        wave2_coros.append(ads_transparency_historical(client, advertiser_id))
        wave2_keys.append("ads_transparency_historical")
    if page_id:
        wave2_coros.append(meta_ads(client, page_id))
        wave2_keys.append("meta_ads")

    wave2 = {}
    if wave2_coros:
        wave2_raw = await asyncio.gather(*wave2_coros, return_exceptions=True)
        wave2 = dict(zip(wave2_keys, wave2_raw))

    # ------------------------------------------------------------------
    # Build sections and errors
    # ------------------------------------------------------------------
    sections: dict = {}
    errors: list = []

    if about_exc:
        sections["about_domain"] = None
        errors.append({"section": "about_domain", "message": str(about_exc)})
    else:
        sections["about_domain"] = about_result

    _section(sections, errors, "ads_transparency", wave1.get("ads_transparency"))
    _section(sections, errors, "meta_page_search", wave1.get("meta_page_search"))
    _section(sections, errors, "google_news", wave1.get("google_news"))

    if run_jobs:
        _section(sections, errors, "google_jobs", wave1.get("google_jobs"))
    else:
        sections["google_jobs"] = None

    _section(
        sections, errors,
        "ads_transparency_historical",
        wave2.get("ads_transparency_historical"),
        optional=advertiser_id is None,
    )
    _section(
        sections, errors,
        "meta_ads",
        wave2.get("meta_ads"),
        optional=page_id is None,
    )

    return {
        "domain": domain,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "derived": {
            "company_name": identity.display_name,
            "canonical_name": identity.canonical_name,
            "confidence": identity.confidence,
            "source": identity.source,
            "aliases": identity.aliases,
        },
        "sections": sections,
        "errors": errors,
    }
