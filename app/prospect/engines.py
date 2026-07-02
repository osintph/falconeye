from app.prospect.client import SearchAPIClient


async def about_domain(client: SearchAPIClient, domain: str) -> dict:
    return await client.search("google_about_this_domain", {"domain": domain})


async def ads_transparency(
    client: SearchAPIClient, domain: str, time_period: str = "last_30_days"
) -> dict:
    return await client.search(
        "google_ads_transparency_center",
        {"domain": domain, "time_period": time_period},
    )


async def ads_transparency_historical(
    client: SearchAPIClient, advertiser_id: str
) -> dict:
    return await client.search(
        "google_ads_transparency_center",
        {"advertiser_id": advertiser_id, "region": "anywhere"},
    )


async def meta_page_search(
    client: SearchAPIClient, query: str, country: str = "ALL"
) -> dict:
    return await client.search(
        "meta_ad_library_page_search",
        {"q": query, "country": country},
    )


async def meta_ads(
    client: SearchAPIClient,
    page_id: str,
    ad_type: str = "all",
    country: str = "ALL",
) -> dict:
    return await client.search(
        "meta_ad_library",
        {"page_id": page_id, "ad_type": ad_type, "country": country},
    )


async def google_news_search(
    client: SearchAPIClient, query: str, time_period: str = "last_year"
) -> dict:
    return await client.search(
        "google_news",
        {"q": query, "time_period": time_period},
    )


async def google_jobs_search(client: SearchAPIClient, query: str) -> dict:
    return await client.search("google_jobs", {"q": query})
