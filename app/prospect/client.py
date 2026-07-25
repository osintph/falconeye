import asyncio
import logging
import os

import httpx

_BASE_URL = "https://www.searchapi.io/api/v1/search"
log = logging.getLogger("falconeye.prospect.client")

class SearchAPINotConfigured(RuntimeError):
    """Raised when SEARCHAPI_KEY is not set. A registered exception handler
    converts it to a clean 503, replacing the old os.environ[...] KeyError -> 500."""


class SearchAPIClient:
    def __init__(self):
        key = os.getenv("SEARCHAPI_KEY")
        if not key:
            raise SearchAPINotConfigured("SEARCHAPI_KEY is not configured")
        self._key = key

    async def search(self, engine: str, params: dict) -> dict:
        headers = {"Authorization": f"Bearer {self._key}"}
        query = {"engine": engine, **params}
        five_xx_count = 0
        rl_count = 0

        async with httpx.AsyncClient(timeout=30.0) as client:
            while True:
                resp = await client.get(_BASE_URL, headers=headers, params=query)

                if resp.status_code == 429:
                    rl_count += 1
                    if rl_count > 3:
                        # Cap 429 retries like 5xx — a persistent upstream throttle
                        # must not spin a worker indefinitely (the counter used to
                        # never increment, so wait stayed 1s forever).
                        log.warning("SearchAPI 429, retries exhausted (3/3), giving up")
                        resp.raise_for_status()
                    wait = 2 ** min(rl_count, 4)
                    log.warning("SearchAPI 429, backoff %ss (retry %s/3)", wait, rl_count)
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
