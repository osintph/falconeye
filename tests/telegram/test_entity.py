from app.telegram import entity


def test_normalize_query_variants():
    assert entity.normalize_query("@durov") == "durov"
    assert entity.normalize_query("durov") == "durov"
    assert entity.normalize_query("https://t.me/durov") == "durov"
    assert entity.normalize_query("t.me/durov") == "durov"
    assert entity.normalize_query("https://t.me/s/durov") == "durov"
    assert entity.normalize_query("t.me/durov?start=1") == "durov"


def test_normalize_query_rejects_invalid():
    for bad in ["", "  ", "a", "ab", "has space", "semi;colon", "sla/sh", "@"]:
        assert entity.normalize_query(bad) is None


def test_extract_iocs_urls_and_telegram_links_are_separate_buckets():
    text = "check https://example.com/x and https://t.me/otherchannel also @another_handle"
    iocs = entity.extract_iocs(text)
    assert "https://example.com/x" in iocs["urls"]
    assert not any("t.me" in u for u in iocs["urls"])
    assert "https://t.me/otherchannel" in iocs["telegram_links"]
    assert "otherchannel" in iocs["telegram_handles"]
    assert "another_handle" in iocs["telegram_handles"]


def test_extract_iocs_excludes_own_handle():
    text = "join @myhandle for updates, or t.me/myhandle"
    iocs = entity.extract_iocs(text, exclude_handle="myhandle")
    assert "myhandle" not in iocs["telegram_handles"]
    assert "https://t.me/myhandle" not in iocs["telegram_links"]


def test_extract_iocs_crypto_and_contact_patterns():
    text = "BTC: 1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX email me@example.com or 09171234567"
    iocs = entity.extract_iocs(text)
    assert "1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX" in iocs["crypto_btc"]
    assert "me@example.com" in iocs["emails"]
    assert "09171234567" in iocs["phones_ph"]


def test_aggregate_iocs_merges_and_dedupes_across_blobs():
    blobs = ["visit @same_handle", "also @same_handle and @other_one"]
    agg = entity.aggregate_iocs(blobs)
    assert agg["telegram_handles"] == ["other_one", "same_handle"]
