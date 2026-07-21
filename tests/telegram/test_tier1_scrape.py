"""
Parser tests against real t.me HTML fixtures (fetched 2026-07-21, see
tier1_scrape.py's docstring for the empirical detection rules these encode).
"""
import os

from app.telegram import tier1_scrape as t1

_FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _load(name):
    with open(os.path.join(_FIXTURES, name)) as f:
        return f.read()


def test_user_with_broadcast_page_parses_as_channel_like():
    # @durov is a personal account with public broadcast enabled -- t.me itself
    # cannot distinguish this from a true channel; tier 3 resolves the real type.
    data = t1._parse_profile_page(_load("user_durov.html"), "durov")
    assert data["entity_type"] == "channel"
    assert data["display_name"] == "Pavel Durov"
    assert data["verified"] is True
    assert data["member_count"] == 11555170
    assert data["has_preview"] is True


def test_bot_detected_via_start_bot_action():
    data = t1._parse_profile_page(_load("bot_botfather.html"), "BotFather")
    assert data["entity_type"] == "bot"
    assert data["display_name"] == "BotFather"
    assert data["verified"] is True
    assert data["has_preview"] is False


def test_channel_detected_via_subscribers_and_preview_link():
    data = t1._parse_profile_page(_load("channel_telegram.html"), "telegram")
    assert data["entity_type"] == "channel"
    assert data["member_count"] == 10014389
    assert data["has_preview"] is True


def test_group_detected_via_members_and_no_preview_link():
    data = t1._parse_profile_page(_load("group_ru_python.html"), "ru_python")
    assert data["entity_type"] == "group"
    assert data["has_preview"] is False  # groups never expose a /s/ preview


def test_nonexistent_identifier_is_unresolved_not_a_hard_404():
    # t.me renders the identical generic fallback for "doesn't exist" and
    # "exists but has no public page" -- parse_profile_page must return None
    # for both, so routes.py can give tier 3 a chance before saying not-found.
    data = t1._parse_profile_page(_load("notfound.html"), "thisdoesnotexist99999999zz")
    assert data is None


def test_parse_count_handles_spaced_thousands_and_no_subscribers():
    assert t1._parse_count("11 555 170 subscribers") == 11555170
    assert t1._parse_count("15 055 members, 556 online") == 15055
    assert t1._parse_count("no subscribers") == 0
    assert t1._parse_count("") is None
