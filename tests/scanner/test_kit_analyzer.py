"""
Unit tests for app/scanner/kit_analyzer.py

The positive fixture is genuinely string-obfuscated, so these tests fail if the
analyzer regresses to searching raw source: every identifier it looks for is
absent from the plaintext until the string table has been decoded and the
decoder call sites resolved.
"""

import pytest

from app.scanner import kit_analyzer, rabbithunt_sig
from tests.scanner.kit_fixtures import build_clean_bundle, build_obfuscated_bundle


@pytest.fixture(scope="module")
def signature():
    return rabbithunt_sig.get_signature()


@pytest.fixture(scope="module")
def analysis(signature):
    return kit_analyzer.analyze(build_obfuscated_bundle(), signature=signature)


# ---------- the premise the whole method rests on ----------

def test_fixture_is_actually_obfuscated():
    """If these leak into the plaintext the fixture is not testing anything."""
    src = build_obfuscated_bundle()
    for token in ("AES", "t_config", "localStorage", "/console",
                  "NLFRWBHXVQJTCPYK", "phoneCode"):
        assert token not in src, f"{token} is readable in the raw fixture"


def test_raw_grep_finds_nothing_but_analysis_does(analysis):
    src = build_obfuscated_bundle()
    assert "setItem" not in src
    assert analysis["storage"]["keys_appear_hashed"] is True


# ---------- decode header ----------

def test_decode_recovers_the_string_table(analysis):
    assert analysis["error"] is None
    assert analysis["decode_score"] == 1.0
    assert analysis["table_entries"] == 68
    assert analysis["decoder"]["functions"] == ["b"]
    assert analysis["decoder"]["string_arrays_found"] >= 1
    assert analysis["sha256"]
    assert analysis["size_bytes"] > 0


# ---------- crypto ----------

def test_both_aes_pairs_recovered_with_roles(analysis):
    pairs = analysis["crypto"]["pairs"]
    assert len(pairs) == 2

    by_role = {p["role"]: p for p in pairs}
    assert by_role["storage"]["key"] == "NLFRWBHXVQJTCPYK"
    assert by_role["storage"]["iv"] == "DMAGSZEIOPQUNTVC"
    assert by_role["transport"]["key"] == "ZQMWLSPXJRDHKTNV"
    assert by_role["transport"]["iv"] == "YFBCUENAGPQLXJWR"

    for pair in pairs:
        assert pair["mode"] == "AES-128-CBC"
        assert pair["padding"] == "Pkcs7"


def test_md5_storage_wrapper_detected(analysis):
    assert analysis["crypto"]["md5_storage"] is True


# ---------- storage ----------

def test_storage_key_name_and_hash(analysis):
    keys = analysis["storage_keys"]
    assert len(keys) == 1
    assert keys[0]["name"] == "t_config"
    # The hash observed on the live site in the published teardown.
    assert keys[0]["md5"] == "2e14a1ac17c37597f4579a51c5f26330"


def test_storage_call_sites_recorded(analysis):
    ops = {c["op"] for c in analysis["storage"]["call_sites"]}
    assert {"setItem", "getItem"} <= ops


# ---------- socket ----------

def test_socket_config(analysis):
    sock = analysis["socket"]
    assert sock["present"] is True
    assert sock["path"] == "/console"
    assert sock["channels"] == ["config", "operation"]
    assert sock["transports"] == ["websocket", "polling"]


# ---------- routes ----------

def test_hash_routes_recovered(analysis):
    assert analysis["hash_routes"] == [
        "/index", "/phoneCode", "/emailCode", "/pinCode",
        "/appCode", "/tempCustomCode", "/expressCvv",
    ]


def test_socket_path_is_not_listed_as_a_victim_view(analysis):
    """/console is server-side. Listing it as a hash route would be wrong."""
    assert "/console" not in analysis["hash_routes"]


# ---------- locales and identity ----------

def test_two_national_id_formats_in_one_build(analysis):
    fields = {f["field"] for f in analysis["identity_fields"]}
    assert "National Insurance Number" in fields
    assert "Social Security number / SSN" in fields
    assert "Postcode" in fields
    assert "Zip Code" in fields
    assert "Date of Birth (DD/MM/YYYY)" in fields
    assert "Date of Birth (MM/DD/YYYY)" in fields
    assert {"GB", "US"} <= set(analysis["locales"])


# ---------- anti-analysis ----------

def test_anti_analysis_engine(analysis):
    anti = analysis["anti_analysis"]
    assert anti["count"] >= 10
    assert {"Selenium", "WebDriver", "PhantomJS", "Puppeteer", "Playwright"} <= set(anti["frameworks"])
    assert set(anti["verdict_tiers"]) == {"Likely Headless", "Definitely Headless"}


# ---------- CJK debug strings ----------

def test_eleven_cjk_strings_with_glosses(analysis):
    cjk = analysis["cjk_strings"]
    assert len(cjk) == 11
    glossed = {c["cjk"].rstrip("!:"): c["gloss"] for c in cjk}
    assert glossed["手机验证页"] == "phone verification page"
    assert glossed["运通CVV验证页"] == "Amex CVV verification page"
    assert glossed["解密结果为空"] == "decryption result empty"
    assert all(c["gloss"] for c in cjk), "every CJK string should be glossed"


def test_cjk_extraction_is_generic_without_a_signature():
    """Without a signature the strings are still found, just not glossed."""
    result = kit_analyzer.analyze(build_obfuscated_bundle())
    assert len(result["cjk_strings"]) == 11
    assert all(c["gloss"] == "" for c in result["cjk_strings"])


def test_roles_are_signature_data_not_engine_logic():
    """No signature means no role labels, but the key material is still found."""
    result = kit_analyzer.analyze(build_obfuscated_bundle())
    pairs = result["crypto"]["pairs"]
    assert len(pairs) == 2
    assert all(p["role"] == "" for p in pairs)
    assert {p["key"] for p in pairs} == {"NLFRWBHXVQJTCPYK", "ZQMWLSPXJRDHKTNV"}


# ---------- negative reporting ----------

def test_not_found_is_populated_and_structured(analysis):
    not_found = analysis["not_found"]
    assert not_found
    for entry in not_found:
        assert set(entry) == {"category", "labels"}
        assert entry["labels"]


# ---------- hostile input ----------

def test_oversized_input_is_rejected_not_analyzed(monkeypatch):
    """The cap is exercised against a lowered limit: the rule is what matters,
    and allocating the real 8 MB just to prove a comparison is waste."""
    monkeypatch.setattr(kit_analyzer, "MAX_INPUT_BYTES", 1024)
    result = kit_analyzer.analyze("x" * 1025)
    assert result["error"]
    assert "too large" in result["error"]
    assert result["table_entries"] == 0
    assert result["crypto"]["pairs"] == []


def test_input_at_the_cap_is_still_analyzed(monkeypatch):
    """The cap rejects above the limit, not at it."""
    monkeypatch.setattr(kit_analyzer, "MAX_INPUT_BYTES", 1024)
    assert kit_analyzer.analyze("x" * 1024)["error"] is None


def test_real_cap_is_the_documented_eight_megabytes():
    assert kit_analyzer.MAX_INPUT_BYTES == 8_000_000


def test_multibyte_input_is_measured_in_bytes_not_characters(monkeypatch):
    """A CJK-heavy bundle is three bytes per character; the cap counts bytes."""
    monkeypatch.setattr(kit_analyzer, "MAX_INPUT_BYTES", 1024)
    assert kit_analyzer.analyze("验" * 400)["error"] is not None


@pytest.mark.parametrize("malformed", [
    "",
    "   ",
    "\x00\x01\x02\xff",
    '["unterminated',
    '[' + ','.join('"%s"' % ("\\" * 40) for _ in range(30)) + ']',
    "function b(i){i-=0;return _0xdead[i];}" + "b(1);" * 500,
    '["' + "A" * 70 + '"]' + "�" * 100,
    "\n".join('var x%d = "%s";' % (i, "\\u" * 20) for i in range(200)),
])
def test_malformed_input_never_raises(malformed):
    """A partial dict with an error field, never an exception."""
    result = kit_analyzer.analyze(malformed)
    assert isinstance(result, dict)
    assert "error" in result
    # The shape must survive so callers can render a partial report.
    for key in ("crypto", "socket", "storage_keys", "hash_routes",
                "locales", "anti_analysis", "cjk_strings", "not_found"):
        assert key in result


def test_non_string_input_is_handled():
    for bad in (None, 12345, b"bytes", [], {}):
        result = kit_analyzer.analyze(bad)
        assert result["error"]


# ---------- clean bundle ----------

def test_clean_bundle_finds_no_kit_material():
    result = kit_analyzer.analyze(build_clean_bundle())
    assert result["error"] is None
    assert result["crypto"]["pairs"] == []
    assert result["storage_keys"] == []
    assert result["hash_routes"] == []
    assert result["cjk_strings"] == []
    assert result["socket"]["path"] == ""
    assert result["socket"]["channels"] == []


# ---------- alphabet discovery ----------

def test_find_alphabet_always_offers_fallbacks():
    alphabets = [a for _o, a in kit_analyzer.find_alphabet("var x = 1;")]
    assert kit_analyzer.STD_B64 in alphabets
    for seeded in kit_analyzer.SEEDED_ALPHABETS:
        assert seeded in alphabets


def test_find_alphabet_spots_a_shuffled_alphabet():
    shuffled = "qwertyuiopASDFGHJKLzxcvbnmQWERTYUIOPasdfghjklZXCVBNM0123456789+/="
    alphabets = [a for _o, a in kit_analyzer.find_alphabet('var a="%s";' % shuffled)]
    assert shuffled in alphabets


def test_repeated_character_string_is_not_mistaken_for_an_alphabet():
    noise = "a" * 64
    alphabets = [a for _o, a in kit_analyzer.find_alphabet('var a="%s";' % noise)]
    assert noise not in alphabets


# ---------- indirect / minified forms ----------
#
# One bug class, found by scoring the real bundles: every one of these
# extractors originally matched only the direct, unminified shape, and a real
# Vite build does not emit that shape. Each test below asserts the indirect form
# works, because that is the form real kits ship.

def test_channels_registered_through_a_wrapper_are_found():
    """Kits register channels through their own dispatch helper, not socket.on."""
    src = '''
    const H=new Map;
    function reg(n,m){n&&typeof m==="function"&&H.set(n,m)}
    sock.on("connect",function(){});
    reg("config",function(a){});
    reg("operation",fp);
    '''
    result = kit_analyzer.extract_socket(src, [])
    assert set(result["channels"]) == {"config", "operation"}


def test_wrapper_detection_ignores_render_calls():
    """createElementVNode("div", props, ...) is not a channel registration."""
    src = 'createElementVNode("div",props,children);createElementVNode("span",null,x);'
    assert kit_analyzer.find_registration_wrappers(src) == set()
    assert kit_analyzer.extract_socket(src, [])["channels"] == []


def test_channels_need_no_proximity():
    """The two registrations may sit far apart after minification reordering."""
    src = ('const H=new Map;function reg(n,m){n&&typeof m==="function"&&H.set(n,m)}\n'
           'reg("config",cb);\n' + ('var filler=1;\n' * 400) + 'reg("operation",cb2);\n')
    assert set(kit_analyzer.extract_socket(src, [])["channels"]) == {"config", "operation"}


def test_socket_present_does_not_contradict_a_recovered_config():
    """Library markers live in the vendor chunk; a recovered path still counts."""
    src = 'var o={path:"/console",transports:["websocket","polling"]};'
    result = kit_analyzer.extract_socket(src, [])
    assert result["path"] == "/console"
    assert result["present"] is True


def test_key_material_bound_to_a_variable_is_recovered():
    """The real kit parses one pair from literals and one from variables."""
    src = ('const a=c.enc.Utf8.parse("NLFRWBHXVQJTCPYK"),b=c.enc.Utf8.parse("DMAGSZEIOPQUNTVC");'
           'const k="ZQMWLSPXJRDHKTNV",v="YFBCUENAGPQLXJWR",x=c.enc.Utf8.parse(k),y=c.enc.Utf8.parse(v);'
           'mode:c.mode.CBC,padding:c.pad.Pkcs7')
    pairs = kit_analyzer.extract_crypto_pairs(src, [], None)["pairs"]
    assert [(p["key"], p["iv"]) for p in pairs] == [
        ("NLFRWBHXVQJTCPYK", "DMAGSZEIOPQUNTVC"),
        ("ZQMWLSPXJRDHKTNV", "YFBCUENAGPQLXJWR"),
    ]


def test_minified_hash_router_is_detected():
    """createWebHashHistory does not survive a Vite build; the regex literal does."""
    minified = 'const b3=/^[^#]+#/;function b4(n,m){return n.replace(b3,"#")+m}'
    assert kit_analyzer.is_hash_router([], minified) is True
    routes = kit_analyzer.extract_hash_routes(["/phoneCode", "/pinCode"], minified)
    assert routes == ["/phoneCode", "/pinCode"]


def test_non_router_bundle_gets_no_hash_routes():
    """The gate still has to keep ordinary path strings out."""
    assert kit_analyzer.is_hash_router([], "var x = 1;") is False
    assert kit_analyzer.extract_hash_routes(["/api", "/login"], "var x = 1;") == []


# ---------- normalize ----------

def test_normalize_turns_bracket_access_into_dot_access():
    src = 'c["enc"]["Utf8"]["parse"]("KEY")'
    assert kit_analyzer.normalize(src) == 'c.enc.Utf8.parse("KEY")'


def test_normalize_leaves_multi_element_arrays_alone():
    src = 'x = ["websocket","polling"];'
    assert kit_analyzer.normalize(src) == src
