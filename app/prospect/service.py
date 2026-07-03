"""
Company tab service layer.

Wave structure:
  Preliminary: about_domain (sequential; drives identity resolution)
  Wave 1:      ads_transparency, meta_page_search, google_news, google_jobs (parallel)
  Wave 2:      ads_transparency_historical (top-3 advertisers), meta_ads (parallel; chain from wave 1)

Query construction and result filtering are driven by the resolved CompanyIdentity.
"""
import asyncio
import logging
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
from app.prospect.resolver import CompanyIdentity, resolve_identity

log = logging.getLogger("falconeye.prospect.service")

try:
    from rapidfuzz.fuzz import partial_ratio as _partial_ratio
    _HAVE_RAPIDFUZZ = True
except ImportError:
    def _partial_ratio(a, b): return 0  # noqa: E731
    _HAVE_RAPIDFUZZ = False
    log.warning("rapidfuzz not installed; jobs and meta page validation disabled")


# ---------------------------------------------------------------------------
# Category boost mapping for Meta page selection (Fix 1)
# ---------------------------------------------------------------------------

_CATEGORY_FAMILIES = [
    (
        {"oil", "petroleum", "energy", "gas", "fuel"},
        {"energy", "petroleum", "oil", "gas", "fuel"},
    ),
    (
        {"technology", "tech", "computer", "software", "electronics", "information technology"},
        {"product/service", "computers", "software", "tech", "electronics"},
    ),
    (
        {"financial", "bank", "insurance", "investment", "payments"},
        {"bank", "financial", "insurance", "investment", "business service"},
    ),
    (
        {"media", "broadcast", "news", "entertainment", "radio", "television"},
        {"media", "broadcast", "news", "entertainment", "television", "radio", "streaming"},
    ),
]


def _category_boost(category_hint: str, page_category: str) -> int:
    hint_lower = (category_hint or "").lower()
    cat_lower = (page_category or "").lower()
    if not hint_lower or not cat_lower:
        return 0
    for hint_kws, cat_kws in _CATEGORY_FAMILIES:
        if any(k in hint_lower for k in hint_kws):
            if any(k in cat_lower for k in cat_kws):
                return 20
    return 0


def _select_meta_page(pages: list, identity: CompanyIdentity):
    """
    Filter and rank Meta page results by identity match.

    1. Whole-word match of any identity name in page name (eliminates BPI for BP).
    2. rapidfuzz partial_ratio >= 70 against all identity names.
    3. Category boost +20 when page category aligns with company's industry.
    4. Rank by (score, followers) descending.
    5. Returns None when no pages survive filtering.
    """
    if not pages:
        return None

    # Build whole-word patterns for all identity name tokens
    names = list({identity.canonical_name, identity.display_name} | set(identity.aliases))
    patterns = [
        re.compile(r"\b" + re.escape(n) + r"\b", re.IGNORECASE)
        for n in names if n
    ]

    scored = []
    for page in pages:
        pname = (page.get("name") or "").strip()
        if not pname:
            continue

        # Step 1: whole-word filter
        if not any(pat.search(pname) for pat in patterns):
            log.info(
                "meta.page_drop name=%r reason=no_whole_word_match candidates=%r",
                pname, [n for n in names if n],
            )
            continue

        # Step 2: fuzzy score against canonical and display names only.
        # Short aliases (e.g. "Stripe") match too broadly via partial_ratio;
        # they are used for the whole-word filter above, not for scoring.
        score_names = list({identity.canonical_name, identity.display_name})
        if _HAVE_RAPIDFUZZ:
            score = max(_partial_ratio(pname.lower(), n.lower()) for n in score_names if n)
        else:
            score = 75  # allow through when rapidfuzz absent

        if score < 75:
            log.info("meta.page_drop name=%r reason=low_fuzzy_score score=%d threshold=75", pname, score)
            continue

        # Step 3: category boost
        boost = _category_boost(identity.category_hint, page.get("category") or "")
        total = score + boost
        followers = page.get("likes") or 0
        scored.append((total, followers, page))
        log.info(
            "meta.page_keep name=%r score=%d boost=%d followers=%d",
            pname, score, boost, followers,
        )

    if not scored:
        log.info(
            "meta.page_none domain identity=%r no pages survived filtering",
            identity.canonical_name,
        )
        return None

    scored.sort(key=lambda x: (x[0], x[1]), reverse=True)
    return scored[0][2]


# ---------------------------------------------------------------------------
# Advertiser extraction (Fix 3)
# ---------------------------------------------------------------------------

def _extract_advertisers(creatives: list) -> list:
    """Return list of {id, name, location, count} sorted by count descending."""
    amap: dict = {}
    for c in creatives:
        adv = c.get("advertiser") or {}
        aid = (adv.get("id") or "").strip()
        if not aid:
            continue
        if aid not in amap:
            amap[aid] = {
                "id": aid,
                "name": (adv.get("name") or "").strip(),
                "location": (adv.get("location") or "").strip(),
                "count": 0,
            }
        amap[aid]["count"] += 1
    return sorted(amap.values(), key=lambda x: -x["count"])


# ---------------------------------------------------------------------------
# News validation helpers
# ---------------------------------------------------------------------------

def _validation_tokens(identity: CompanyIdentity) -> set:
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


# ---------------------------------------------------------------------------
# Jobs validation
# ---------------------------------------------------------------------------

def _filter_jobs(jobs: list, identity: CompanyIdentity, domain: str) -> list:
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

    # Validate jobs
    jobs_result = wave1.get("google_jobs")
    if run_jobs and not isinstance(jobs_result, Exception) and isinstance(jobs_result, dict):
        raw_jobs = jobs_result.get("jobs") or []
        wave1["google_jobs"] = dict(jobs_result, jobs=_filter_jobs(raw_jobs, identity, domain))

    # ------------------------------------------------------------------
    # Post-wave-1 enrichment: advertisers and meta page selection
    # ------------------------------------------------------------------
    ads_30d = wave1.get("ads_transparency")
    advertisers: list = []
    top3_ids: list = []
    if not isinstance(ads_30d, Exception) and ads_30d:
        creatives = ads_30d.get("ad_creatives") or []
        advertisers = _extract_advertisers(creatives)
        top3_ids = [a["id"] for a in advertisers[:3] if a["id"]]
        if advertisers:
            wave1["ads_transparency"] = dict(ads_30d, _advertisers=advertisers)

    meta_search = wave1.get("meta_page_search")
    page_id = None
    if not isinstance(meta_search, Exception) and meta_search:
        pages = meta_search.get("page_results") or []
        best_page = _select_meta_page(pages, identity)
        if best_page:
            page_id = best_page.get("page_id")
            wave1["meta_page_search"] = dict(meta_search, _selected_page=best_page)
        else:
            wave1["meta_page_search"] = dict(meta_search, _selected_page=None)

    # ------------------------------------------------------------------
    # Wave 2: ads_historical (top-3 advertisers) + meta_ads
    # ------------------------------------------------------------------
    wave2_coros: list = []
    wave2_keys: list = []
    for adv_id in top3_ids:
        wave2_coros.append(ads_transparency_historical(client, adv_id))
        wave2_keys.append(f"ads_hist_{adv_id}")
    if page_id:
        wave2_coros.append(meta_ads(client, page_id))
        wave2_keys.append("meta_ads")

    wave2: dict = {}
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

    # ads_transparency_historical: dict keyed by advertiser_id
    hist_dict: dict = {}
    for adv_id in top3_ids:
        key = f"ads_hist_{adv_id}"
        result = wave2.get(key)
        if result is None:
            pass
        elif isinstance(result, Exception):
            errors.append({
                "section": "ads_transparency_historical",
                "message": str(result),
            })
        else:
            hist_dict[adv_id] = result
    sections["ads_transparency_historical"] = hist_dict if hist_dict else None

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
            "category_hint": identity.category_hint,
        },
        "sections": sections,
        "errors": errors,
    }
