import asyncio
import logging
import os

import httpx

_BASE_URL = "https://www.searchapi.io/api/v1/search"
log = logging.getLogger("falconeye.prospect.client")


class SearchAPIClient:
    def __init__(self):
        self._key = os.environ["SEARCHAPI_KEY"]

    async def search(self, engine: str, params: dict) -> dict:
        headers = {"Authorization": f"Bearer {self._key}"}
        query = {"engine": engine, **params}
        five_xx_count = 0

        async with httpx.AsyncClient(timeout=30.0) as client:
            while True:
                resp = await client.get(_BASE_URL, headers=headers, params=query)

                if resp.status_code == 429:
                    wait = 2 ** min(five_xx_count, 4)
                    log.warning("SearchAPI 429, backoff %ss", wait)
                    await asyncio.sleep(wait)
                    continue

                if 500 <= resp.status_code < 600:
                    five_xx_count += 1
                    if five_xx_count <= 3:
                        wait = 2 ** (five_xx_count - 1)
                        log.warning(
                            "SearchAPI %s, retry %s/3 in %ss",
                            resp.status_code, five_xx_count, wait,
                        )
                        await asyncio.sleep(wait)
                        continue
                    resp.raise_for_status()

                if 400 <= resp.status_code < 500:
                    resp.raise_for_status()

                return resp.json()
