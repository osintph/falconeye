"""
LLM-on audit harness for the Sock Puppet Legend path. Test harness only; it does
not touch the generator.

It drives POST /api/sockpuppet/generate with the Legend on and checks two things
per persona:

  1. Legend-vs-Cover agreement, exonym-aware. The comparison is normalized
     (lowercase, strip diacritics, token overlap) with a known-exonym map, so a
     Cover city written as a transliteration (Moskva) counts as a match against
     the Legend's exonym (Moscow). A genuine city or employer contradiction still
     flags.
  2. Residual non-Latin. Every _roman field must be Latin only after the Legend
     romanization pass.

Usage:
  FALCONEYE_URL=http://127.0.0.1:8000 python scripts/sockpuppet_legend_audit.py

Distinct CF-Connecting-IP headers are sent so the per-IP Legend cap does not throttle
the run against your own server.
"""
import json
import os
import re
import unicodedata
import urllib.request

BASE_URL = os.getenv("FALCONEYE_URL", "http://127.0.0.1:8000").rstrip("/")

# Single-token native or transliterated spelling -> canonical English exonym.
EXONYM = {
    "moskva": "moscow", "wien": "vienna", "muenchen": "munich", "munchen": "munich",
    "praha": "prague", "roma": "rome", "lisboa": "lisbon", "firenze": "florence",
    "napoli": "naples", "koeln": "cologne", "koln": "cologne", "sevilla": "seville",
    "warszawa": "warsaw", "beograd": "belgrade", "bucuresti": "bucharest",
    "athina": "athens", "athinai": "athens", "kobenhavn": "copenhagen",
    "goteborg": "gothenburg", "milano": "milan", "torino": "turin", "genova": "genoa",
    "venezia": "venice", "praga": "prague", "muenster": "munster", "nuernberg": "nuremberg",
    "agrigentum": "agrigento", "vaticana": "vatican", "vaticano": "vatican",
    "gen%C3%A8ve": "geneva", "geneve": "geneva", "genf": "geneva",
}
# Multi-word endonyms -> canonical exonym, applied on the normalized string before
# tokenization (Krung Thep is Bangkok, Civitas Vaticana is the Vatican).
PHRASE_EXONYM = {
    "krung thep": "bangkok", "sankt peterburg": "saint petersburg",
    "den haag": "the hague", "citta del vaticano": "vatican",
    "civitas vaticana": "vatican", "ciudad de mexico": "mexico city",
}


def _strip_accents(s):
    return "".join(c for c in unicodedata.normalize("NFKD", str(s or ""))
                   if not unicodedata.combining(c)).lower()


def _canon_tokens(s):
    norm = re.sub(r"[^a-z0-9 ]", " ", _strip_accents(s))
    norm = re.sub(r"\s+", " ", norm).strip()
    for src, dst in PHRASE_EXONYM.items():
        norm = norm.replace(src, dst)
    return {EXONYM.get(t, t) for t in norm.split() if len(t) >= 2}


def agree(field_value, legend_text):
    """True if the Cover field and the Legend prose share a token after diacritic
    and exonym normalization. Tolerant of paraphrase and exonyms, still catches a
    real contradiction (no shared token)."""
    return bool(_canon_tokens(field_value) & _canon_tokens(legend_text))


def has_nonlatin(s):
    return any(ord(c) >= 0x250 for c in str(s or ""))


def _unit_tests():
    cases = [
        ("Moskva", "based in Moscow at Gazprom", True),
        ("Wien", "lives in Vienna", True),
        ("Muenchen", "works in Munich", True),
        ("Praha", "from Prague", True),
        ("Roma", "grew up in Rome", True),
        ("Lisboa", "based in Lisbon", True),
        ("Firenze", "studied in Florence", True),
        ("Koeln", "works in Cologne", True),
        ("Vatican City Holdings", "joined the Vatican in 1998", True),
        ("Vannes", "grew up in Vannes, Bretagne", True),
        ("Paris", "she lives in Lyon and works in Marseille", False),
        ("Gazprom Neft", "works at Rosneft", False),
    ]
    ok = True
    print("== comparator unit tests ==")
    for fv, txt, want in cases:
        got = agree(fv, txt)
        if got != want:
            ok = False
        print(f"  [{'ok' if got == want else 'WRONG'}] agree({fv!r}, ...) = {got} (want {want})")
    print("  UNIT:", "PASS" if ok else "FAIL")
    return ok


def _generate(cc, ip):
    body = json.dumps({"country": cc, "include_legend": True}).encode()
    req = urllib.request.Request(
        f"{BASE_URL}/api/sockpuppet/generate", data=body,
        headers={"Content-Type": "application/json", "CF-Connecting-IP": ip})
    with urllib.request.urlopen(req, timeout=90) as r:
        return json.load(r)


def run(countries):
    print(f"== LLM-on spot check ({len(countries)} countries) against {BASE_URL} ==")
    residual_fails = 0
    agree_flags = 0
    for i, cc in enumerate(countries):
        try:
            d = _generate(cc, f"10.80.{i % 250}.{(i * 7) % 250}")
        except Exception as exc:
            print(f"  {cc}: request_error {type(exc).__name__}")
            continue
        c = d["cover"]
        a, pr, p = c["address"], c["professional"], c["personal"]
        txt = " ".join(d["legend"].get("content", {}).get(k, "") for k in
                       ("occupation_context", "education", "hobbies", "life_history"))
        romans = {"name": p["name_roman"], "street": a["street_roman"], "city": a["city_roman"],
                  "region": a["region_roman"], "employer": pr["employer_roman"],
                  "job": pr["job_title_roman"]}
        resid = [k for k, v in romans.items() if has_nonlatin(v)]
        if resid:
            residual_fails += 1
        flags = []
        if not agree(a["city_roman"], txt):
            flags.append("city_disagree")
        if not agree(pr["employer_roman"], txt):
            flags.append("employer_disagree")
        if resid:
            flags.append("RESIDUAL:" + ",".join(resid))
        if flags:
            agree_flags += 1
        print(f"  {cc} T{c['tier']}: {'OK' if not flags else ' '.join(flags)}"
              f"  city={a['city_roman']!r} emp={pr['employer_roman'][:26]!r}")
    print(f"\nSUMMARY residual_non_latin={residual_fails}/{len(countries)}"
          f"  agreement_flags={agree_flags}/{len(countries)}")


if __name__ == "__main__":
    _unit_tests()
    COUNTRIES = ["RU", "AT", "DE", "CZ", "IT", "PT", "GR", "PL", "SA", "TH", "JP",
                 "IR", "KR", "CN", "DZ", "FR", "ES", "BR", "MX", "ID", "SG"]
    run(COUNTRIES)
