"""v3.38.18 coverage: PSL-private platform subdomains, the local NRD store, and
urlscan pagination with the age-window stop."""
import asyncio
import datetime as dt

from app import config
from app.hunt import platforms, sources
from app.scanner.scope import is_platform_suffix, registrable


def test_private_registrable_keeps_platform_subdomain():
    assert registrable("bdo-online-update-account.pages.dev", private=True) == \
        "bdo-online-update-account.pages.dev"
    assert registrable("bdo-online-update-account.pages.dev") == "pages.dev"
    assert registrable("foo.blogspot.com", private=True) == "foo.blogspot.com"
    # A normal domain is unchanged either way.
    assert registrable("mmda-ltoncap.net", private=True) == "mmda-ltoncap.net"


def test_is_platform_suffix_only_the_apex():
    assert is_platform_suffix("pages.dev")
    assert is_platform_suffix("workers.dev")
    assert not is_platform_suffix("x.pages.dev")  # a subdomain is a candidate
    assert not is_platform_suffix("mmda.gov.ph")


def test_platform_abuse_table():
    assert platforms.platform_suffix("bdo-online-update-account.pages.dev") == "pages.dev"
    assert platforms.platform_abuse("x.pages.dev") == "abuse@cloudflare.com"
    assert platforms.platform_suffix("pages.dev") is None  # apex is not a candidate
    assert platforms.platform_suffix("mmda-ltoncap.net") is None


def test_nrd_local_reads_rolling_store(tmp_path, monkeypatch):
    (tmp_path / "2026-10-11.txt").write_text("gcash-login.online\nunrelated.com\nbdo-verify.xyz\n")
    (tmp_path / "2026-10-10.txt").write_text("notrelevant.net\nmybdo-secure.top\n")
    monkeypatch.setattr(config, "HUNT_NRD_DIR", str(tmp_path))
    monkeypatch.setattr(config, "HUNT_NRD_ENABLED", True)
    monkeypatch.setattr(config, "HUNT_NRD_URL", None)
    hosts, status = sources._nrd_local("bdo")
    assert "bdo-verify.xyz" in hosts and "mybdo-secure.top" in hosts
    assert "gcash-login.online" not in hosts
    assert status.startswith("answered")


def test_nrd_local_empty_when_no_data(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "HUNT_NRD_DIR", str(tmp_path))
    hosts, status = sources._nrd_local("bdo")
    assert hosts == set() and "no local data" in status


class _Resp:
    def __init__(self, results):
        self.status_code = 200
        self._results = results

    def json(self):
        return {"results": self._results, "has_more": True}


def _result(dom, when, sort):
    return {"page": {"domain": dom, "title": ""}, "task": {"time": when}, "sort": sort,
            "labels": [], "result": ""}


def test_urlscan_paginates_and_stops_on_age(monkeypatch):
    now = dt.datetime.now(dt.timezone.utc)
    recent = (now - dt.timedelta(days=10)).isoformat()
    old = (now - dt.timedelta(days=400)).isoformat()
    calls = {"n": 0, "after": []}

    class Client:
        async def get(self, url, params=None, timeout=None, headers=None):
            calls["n"] += 1
            calls["after"].append((params or {}).get("search_after"))
            if calls["n"] == 1:
                # A full page of recent results (size 100) -> should page again.
                return _Resp([_result(f"bdo-{i}.com", recent, [1000 - i, i])
                              for i in range(config.HUNT_URLSCAN_SIZE)])
            # Second page is old -> ingest then stop on the age window.
            return _Resp([_result("bdo-old.com", old, [1, 1])])

    monkeypatch.setattr(config, "HUNT_URLSCAN_DAILY", 1000)
    meta, status, pages = asyncio.run(
        sources._urlscan(Client(), "bdo", "bdo.com.ph", pages=5))
    assert status == "answered"
    assert pages == 2  # paged once more, then stopped on age (did not use all 5)
    # search_after is the sort value of the last result of page 1 (i=99 -> [901, 99]).
    assert calls["after"][0] is None and calls["after"][1] == "901,99"
    assert "bdo-old.com" in meta  # the old page was still ingested before stopping
