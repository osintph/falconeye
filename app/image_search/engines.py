from app.prospect.client import SearchAPIClient


async def google_lens(client: SearchAPIClient, image_url: str, search_type: str = "all") -> dict:
    return await client.search("google_lens", {"url": image_url, "search_type": search_type})


async def yandex_reverse_image(client: SearchAPIClient, image_url: str) -> dict:
    return await client.search("yandex_reverse_image", {"url": image_url})
