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
