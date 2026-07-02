import asyncio
from datetime import datetime, timezone

from app.prospect.client import SearchAPIClient
from app.prospect.engines import about_domain, ads_transparency


async def build_dossier(domain: str) -> dict:
    client = SearchAPIClient()

    results = await asyncio.gather(
        about_domain(client, domain),
        ads_transparency(client, domain),
        return_exceptions=True,
    )

    sections = {}
    errors = []
    names = ["about_domain", "ads_transparency"]

    for name, result in zip(names, results):
        if isinstance(result, Exception):
            sections[name] = None
            errors.append({"section": name, "message": str(result)})
        else:
            sections[name] = result

    return {
        "domain": domain,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sections": sections,
        "errors": errors,
    }
