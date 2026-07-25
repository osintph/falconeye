"""
Sock Puppet Generator - fictional OSINT research personas.

Coverage is EVERY ISO 3166 country (pycountry). Coherence is anchored on the
country code via an offline metadata layer (pycountry, babel, phonenumbers, pytz).

Two layers:
  Cover  - deterministic surface facts (always generated, no LLM required).
  Legend - one Haiku call on top of the Cover. For Tier C it also supplies name
           and city; for every locale it supplies natural Latin romanization and
           extra handle ideas. The Cover is PINNED into the prompt so the Legend
           cannot invent a different city, employer, name, or region.

Romanization layer: every script-variable field (name, street, city, region,
employer, job title) carries a Latin twin (*_roman). The twin is the LLM value
when available, else an offline unidecode transliteration (marked approximate).
The PDF and the handles use the roman twins, so non-Latin personas never render
blank and never fall back to a generic stem.

Personas are entirely fictional. For authorized OSINT investigative use only;
never to impersonate a real individual. House style: no em dashes anywhere.
"""
import importlib.util
import json
import logging
import random
import re

import phonenumbers
import pycountry
import pytz
from anthropic import AsyncAnthropic, APIError, APIStatusError, APITimeoutError
from babel.numbers import get_territory_currencies
from faker import Faker
from faker.config import AVAILABLE_LOCALES
from fastapi import APIRouter, HTTPException, Request
from phonenumbers import PhoneNumberFormat
from pydantic import BaseModel
from slowapi import Limiter
from unidecode import unidecode

from app.config import ANTHROPIC_API_KEY, LLM_TIMEOUT_SECONDS
from app.utils import rate_limit
from app.utils.client_ip import get_client_ip, get_client_ip_key
from app.utils.env import getenv_clean
from app.utils.llm_response import safe_str

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/sockpuppet", tags=["sockpuppet"])
limiter = Limiter(key_func=get_client_ip_key)

LLM_SOCKPUPPET_ENABLED = getenv_clean("LLM_SOCKPUPPET_ENABLED", "true").lower() == "true"
SOCKPUPPET_LLM_PER_DAY = 5
_RL_TABLE = "sockpuppet_llm_calls"
rate_limit.init_table(_RL_TABLE)


def _has_provider(kind: str, loc: str) -> bool:
    return importlib.util.find_spec(f"faker.providers.{kind}.{loc}") is not None


def _locale_cc(loc: str) -> str | None:
    parts = loc.split("_")
    if len(parts) >= 2 and len(parts[-1]) == 2 and parts[-1].isupper():
        cc = parts[-1]
        if pycountry.countries.get(alpha_2=cc):
            return cc
    return None


_CC_LOCALE: dict[str, tuple[str, bool, bool]] = {}
for _loc in AVAILABLE_LOCALES:
    _cc = _locale_cc(_loc)
    if not _cc:
        continue
    _addr, _person = _has_provider("address", _loc), _has_provider("person", _loc)
    _cur = _CC_LOCALE.get(_cc)
    if _cur is None or (int(_addr), int(_loc.startswith("en_"))) > (int(_cur[1]), int(_cur[0].startswith("en_"))):
        _CC_LOCALE[_cc] = (_loc, _addr, _person)


def _tier(cc: str) -> str:
    e = _CC_LOCALE.get(cc)
    if e and e[1]:
        return "A"
    if e and e[2]:
        return "B"
    return "C"


DEPARTMENTS = [
    "Operations", "Marketing", "Sales", "Finance", "Human Resources", "Engineering",
    "Product", "Customer Support", "Logistics", "Research and Development",
    "Legal and Compliance", "Procurement", "Administration", "Quality Assurance",
]
JOB_TITLES = [
    "Operations coordinator", "Marketing specialist", "Account manager",
    "Financial analyst", "HR generalist", "Software engineer", "Product manager",
    "Customer support lead", "Logistics planner", "Research assistant",
    "Compliance officer", "Procurement specialist", "Office administrator",
    "Quality analyst", "Sales representative", "Data analyst",
]
VEHICLES = [
    "Toyota Corolla", "Honda Civic", "Hyundai Accent", "Ford Ranger", "Nissan Almera",
    "Mitsubishi Mirage", "Volkswagen Golf", "Kia Picanto", "Suzuki Swift", "no vehicle",
]
COLORS = ["blue", "green", "grey", "black", "red", "teal", "navy", "maroon", "olive", "purple"]

US_STATE_TZ = {
    "Alabama": "America/Chicago", "Alaska": "America/Anchorage", "Arizona": "America/Phoenix",
    "Arkansas": "America/Chicago", "California": "America/Los_Angeles", "Colorado": "America/Denver",
    "Connecticut": "America/New_York", "Delaware": "America/New_York",
    "District of Columbia": "America/New_York", "Florida": "America/New_York",
    "Georgia": "America/New_York", "Hawaii": "Pacific/Honolulu", "Idaho": "America/Boise",
    "Illinois": "America/Chicago", "Indiana": "America/Indiana/Indianapolis",
    "Iowa": "America/Chicago", "Kansas": "America/Chicago", "Kentucky": "America/New_York",
    "Louisiana": "America/Chicago", "Maine": "America/New_York", "Maryland": "America/New_York",
    "Massachusetts": "America/New_York", "Michigan": "America/Detroit", "Minnesota": "America/Chicago",
    "Mississippi": "America/Chicago", "Missouri": "America/Chicago", "Montana": "America/Denver",
    "Nebraska": "America/Chicago", "Nevada": "America/Los_Angeles", "New Hampshire": "America/New_York",
    "New Jersey": "America/New_York", "New Mexico": "America/Denver", "New York": "America/New_York",
    "North Carolina": "America/New_York", "North Dakota": "America/Chicago", "Ohio": "America/New_York",
    "Oklahoma": "America/Chicago", "Oregon": "America/Los_Angeles", "Pennsylvania": "America/New_York",
    "Rhode Island": "America/New_York", "South Carolina": "America/New_York",
    "South Dakota": "America/Chicago", "Tennessee": "America/Chicago", "Texas": "America/Chicago",
    "Utah": "America/Denver", "Vermont": "America/New_York", "Virginia": "America/New_York",
    "Washington": "America/Los_Angeles", "West Virginia": "America/New_York",
    "Wisconsin": "America/Chicago", "Wyoming": "America/Denver",
}


def _strip_dashes(text: str) -> str:
    if not text:
        return text
    return (
        text.replace("—", " ").replace("–", "-")
        .replace("‘", "'").replace("’", "'")
        .replace("“", '"').replace("”", '"')
        .replace("…", "...")
    )


def _oneline(value) -> str:
    return re.sub(r"\s*\n\s*", ", ", str(value or "")).strip()


def _roman(text) -> str:
    """Offline Latin twin via unidecode. Good for Latin/Cyrillic/Greek, approximate
    for Arabic/Thai/CJK (the Legend supplies a natural romanization when it runs)."""
    if not text:
        return ""
    r = _strip_dashes(unidecode(str(text))).strip()
    r = re.sub(r"\s+", " ", r).replace("`", "").replace("'", "")
    return r


def _is_latin(text) -> bool:
    return all(ord(c) < 0x250 for c in str(text or ""))


def _clean_handle(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def _fact_words(job_title_roman: str, region_roman: str, cc: str) -> list[str]:
    words = []
    for src in (job_title_roman, region_roman):
        for w in re.findall(r"[A-Za-z]{4,}", src or ""):
            wl = w.lower()
            if wl not in words:
                words.append(wl)
    if cc:
        words.append(cc.lower())
    return words


def _build_handles(first_roman: str, last_roman: str, birth_year: int, age: int,
                   cc: str, job_title_roman: str, region_roman: str) -> tuple[list[str], str]:
    f = _clean_handle(first_roman) or "user"
    l = _clean_handle(last_roman) or f
    fi, li = f[:1], l[:1]
    yy, yyyy = str(birth_year)[-2:], str(birth_year)
    facts = _fact_words(job_title_roman, region_roman, cc)
    cands = [
        f"{f}.{l}", f"{fi}{l}", f"{l}.{f}", f"{f}_{li}", f"{fi}.{l}",
        f"{fi}{l}{yy}", f"{l}{yyyy}", f"{f}_{li}{age}",
    ]
    for w in facts[:2]:
        cands.append(f"{f}.{w}")
    if cc:
        cands.append(f"{l}.{cc.lower()}")
    seen, handles = set(), []
    for h in cands:
        h = re.sub(r"[^a-z0-9._]", "", h)
        if h and len(h) >= 3 and h not in seen:
            seen.add(h)
            handles.append(h)
    primary = f"{f}.{l}" if l != f else f
    return handles[:8], primary


def _apply_identity(cover: dict, first_roman: str, last_roman: str, birth_year: int,
                    age: int, cc: str, job_title_roman: str, region_roman: str) -> None:
    handles, primary = _build_handles(first_roman, last_roman, birth_year, age, cc, job_title_roman, region_roman)
    cover["contact"]["username_stem"] = primary
    cover["contact"]["username_suggestions"] = handles
    cover["contact"]["email_placeholder"] = f"{primary}@PROVIDER.example  (PLACEHOLDER, register with a provider that fits the persona)"
    cover["social"]["handle"] = "@" + (handles[0] if handles else primary)


def _mask_phone(cc: str) -> tuple[str | None, str]:
    try:
        code = phonenumbers.country_code_for_region(cc)
        example = phonenumbers.example_number(cc)
        if example is None:
            return code, ""
        formatted = phonenumbers.format_number(example, PhoneNumberFormat.INTERNATIONAL)
    except Exception:
        return None, ""
    prefix = f"+{code}"
    if formatted.startswith(prefix):
        head, tail = prefix, formatted[len(prefix):]
    else:
        head, tail = "", formatted
    return code, f"{head}{re.sub(r'[0-9]', 'X', tail)}".strip()


def _currency(cc: str) -> str:
    try:
        codes = get_territory_currencies(cc) or []
    except Exception:
        codes = []
    if not codes:
        return ""
    cur = pycountry.currencies.get(alpha_3=codes[0])
    return f"{codes[0]} ({cur.name})" if cur else codes[0]


def _metadata(cc: str) -> dict:
    tzs = pytz.country_timezones.get(cc) or ["UTC"]
    subs = [s.name for s in (pycountry.subdivisions.get(country_code=cc) or [])]
    code, phone = _mask_phone(cc)
    return {"timezone": tzs[0], "currency": _currency(cc),
            "calling_code": f"+{code}" if code else "", "phone_scaffold": phone, "subdivisions": subs}


def _dob_for(age):
    from datetime import date
    f = Faker("en_US")
    dob = f.date_of_birth(minimum_age=int(age), maximum_age=int(age)) if age is not None \
        else f.date_of_birth(minimum_age=22, maximum_age=58)
    today = date.today()
    return dob.isoformat(), today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))


def _pick_gender(requested: str) -> str:
    g = (requested or "random").lower()
    return g if g in ("female", "male", "non-binary") else random.choice(["female", "male", "non-binary"])


def _faker_name(fake: Faker, gender: str) -> tuple[str, str]:
    if gender == "female":
        return fake.first_name_female(), fake.last_name()
    if gender == "male":
        return fake.first_name_male(), fake.last_name()
    return fake.first_name(), fake.last_name()


def build_cover(cc: str, country_name: str, gender_req: str, age, include_financial: bool) -> tuple[dict, str, bool]:
    tier = _tier(cc)
    gender = _pick_gender(gender_req)
    meta = _metadata(cc)
    region = random.choice(meta["subdivisions"]) if meta["subdivisions"] else ""
    dob_iso, age_val = _dob_for(age)
    birth_year = int(dob_iso[:4])

    name_source, city_source, need_llm_identity = "faker", "faker", False

    if tier == "A":
        fake = Faker(_CC_LOCALE[cc][0])
        first, last = _faker_name(fake, gender)
        full_name = f"{first} {last}"
        street = _oneline(fake.street_address())
        city = fake.city()
        region = fake.administrative_unit() if hasattr(fake, "administrative_unit") else region
        postal = str(fake.postcode())
        job_title, employer, color = fake.job(), fake.company(), fake.color_name()
    elif tier == "B":
        fake = Faker(_CC_LOCALE[cc][0])
        first, last = _faker_name(fake, gender)
        full_name = f"{first} {last}"
        street, postal, city = "[street to be set by the operator]", "", ""
        city_source, need_llm_identity = "legend", True
        job_title = random.choice(JOB_TITLES)
        employer = f"{last} {random.choice(['Group', 'Holdings', 'Services', 'Trading'])}"
        color = random.choice(COLORS)
    else:  # Tier C
        first, last, full_name = "", "", ""
        name_source, city_source, need_llm_identity = "legend", "legend", True
        street, postal, city = "[street to be set by the operator]", "", ""
        job_title = random.choice(JOB_TITLES)
        employer = f"{country_name} {random.choice(['Group', 'Holdings', 'Services', 'Trading'])}"
        color = random.choice(COLORS)

    # Offline fallbacks so the Cover is complete even with no LLM.
    if not full_name:
        nf = Faker("en_US")
        first, last = _faker_name(nf, gender)
        full_name = f"{first} {last}"
    if not first:
        parts = full_name.split()
        first, last = parts[0], (parts[-1] if len(parts) > 1 else parts[0])
    if not city:
        city = region or f"{country_name} (capital region)"
    if not employer:
        employer = f"{country_name} Services"
    if not job_title:
        job_title = random.choice(JOB_TITLES)

    tz = meta["timezone"]
    if cc == "US":
        tz = US_STATE_TZ.get(region, tz)

    # Latin twins (offline baseline; the Legend overrides with natural romanization).
    name_roman = _roman(full_name)
    rparts = name_roman.split()
    first_roman = rparts[0] if rparts else (_roman(first) or "user")
    last_roman = rparts[-1] if len(rparts) > 1 else (_roman(last) or first_roman)
    city_roman, region_roman = _roman(city), _roman(region)
    street_roman = street if _is_latin(street) else _roman(street)
    employer_roman, job_title_roman = _roman(employer), _roman(job_title)
    approx = not (_is_latin(full_name) and _is_latin(city) and _is_latin(employer) and _is_latin(job_title))

    cover = {
        "country_code": cc,
        "tier": tier,
        "romanization_approximate": approx,
        "personal": {
            "full_name": full_name, "name_roman": name_roman,
            "date_of_birth": dob_iso, "age": age_val, "gender": gender, "nationality": country_name,
        },
        "address": {
            "street": street, "street_roman": street_roman, "city": city, "city_roman": city_roman,
            "region": region, "region_roman": region_roman, "postal_code": postal, "country": country_name,
        },
        "contact": {},
        "professional": {
            "employer": employer, "employer_roman": employer_roman,
            "job_title": job_title, "job_title_roman": job_title_roman,
            "department": random.choice(DEPARTMENTS), "years_experience": random.randint(1, max(1, min(age_val - 21, 32))),
        },
        "additional": {
            "timezone": tz, "currency": meta["currency"], "calling_code": meta["calling_code"],
            "favorite_color": color, "vehicle": random.choice(VEHICLES),
        },
        "social": {
            "handle": "", "bio": _strip_dashes(f"{job_title_roman} based in {city_roman}, {country_name}. Views my own."),
            "followers": random.randint(80, 4200), "following": random.randint(60, 900), "posts": random.randint(12, 1600),
            "note": "Fictional social scaffolding for legend completeness, not a real account.",
        },
        "field_sources": {"name": name_source, "city": city_source, "timezone_phone_currency": "offline metadata (country code)"},
    }
    cover["contact"]["phone_placeholder"] = (
        meta["phone_scaffold"] + "  (PLACEHOLDER, register a controlled number; expect VoIP to be blocked)"
        if meta["phone_scaffold"] else
        f"{meta['calling_code']} XXXXXXXXX  (PLACEHOLDER, register a controlled number)")

    _apply_identity(cover, first_roman, last_roman, birth_year, age_val, cc, job_title_roman, region_roman)

    if include_financial:
        ff = Faker("en_US")
        cover["financial"] = {
            "card_number": ff.credit_card_number(), "provider": ff.credit_card_provider(),
            "expiry": ff.credit_card_expire(), "iban": ff.iban(),
            "note": "Test-only Faker values (Luhn valid but not real). Fictional filler, "
                    "not a payment instrument. Real funding needs a genuine burner-card service.",
        }

    return cover, tier, need_llm_identity


PERSONA_SYSTEM_PROMPT = """You write a fictional cover-identity back-story, a legend, for an authorized OSINT research persona, and you provide Latin romanization for the persona's fields.

The persona is entirely fictional. Never base it on, resemble, or impersonate a real, identifiable person. Do not add real contact details, real handles, or real companies.

You receive a fixed Cover of surface facts, plus the country. USE THESE EXACT VALUES in the back-story. Do NOT invent a different city, employer, name, region, or age. When a field is marked PROVIDE, invent one that is fictional but culturally plausible for the stated country and gender, and a real city in that country; then use that invented value consistently.

For the name, city, region, employer, and job title, also return an accurate, natural Latin romanization (the roman twin). For an Arabic, Thai, or CJK name, romanize it the way a person would write it in Latin script (for example a natural Given Family spelling), not a letter-by-letter transliteration. If a value is already Latin, echo it unchanged.

Also propose three extra handle ideas in the style a real person of this occupation and country might pick, lowercase, ASCII, no leetspeak, derived from the roman name and the hobbies. Any number in a handle must be the birth year or the age, never random.

Write in plain English. Do NOT use em dashes or en dashes; use commas, periods, or the word "to" for ranges. No fancy quotation marks.

Return ONLY valid JSON in this exact shape, no markdown or preamble:

{
  "full_name": "the native full name (echo the given one, or invent only if it was PROVIDE)",
  "name_roman": "natural Latin romanization of the full name",
  "city": "the city (echo the given one, or invent a real city in the country only if it was PROVIDE)",
  "city_roman": "natural Latin romanization of the city",
  "region_roman": "natural Latin romanization of the region",
  "employer_roman": "natural Latin romanization of the employer",
  "job_title_roman": "natural Latin romanization of the job title",
  "extra_handles": ["three", "handle", "ideas"],
  "occupation_context": "1 to 2 sentences using the exact employer and job.",
  "education": "1 to 2 sentences consistent with the age and job.",
  "hobbies": "1 to 2 sentences that fit the location and persona.",
  "life_history": "3 to 5 sentences that use the exact city and employer, with no loose ends.",
  "writing_voice": "1 to 2 sentences on how this persona writes."
}
"""


async def _llm_persona(cover: dict) -> dict | None:
    # ===== HARDCODED MODEL: do NOT replace with a config variable =====
    HARDCODED_MODEL = "claude-haiku-4-5"
    # ==================================================================
    if not ANTHROPIC_API_KEY:
        return None

    p, a, pr = cover["personal"], cover["address"], cover["professional"]
    name_field = "PROVIDE" if cover["field_sources"]["name"] == "legend" else p["full_name"]
    city_field = "PROVIDE" if cover["field_sources"]["city"] == "legend" else a["city"]
    facts = (
        f"Country: {a['country']}\n"
        f"Full name (native): {name_field}\n"
        f"City (native): {city_field}\n"
        f"Region (native): {a['region']}\n"
        f"Employer (native): {pr['employer']}\n"
        f"Job title (native): {pr['job_title']}\n"
        f"Age: {p['age']} (DOB {p['date_of_birth']})\n"
        f"Gender: {p['gender']}\n"
        f"Timezone: {cover['additional']['timezone']}\n"
    )

    client = AsyncAnthropic(api_key=ANTHROPIC_API_KEY, timeout=LLM_TIMEOUT_SECONDS)
    try:
        response = await client.messages.create(
            model=HARDCODED_MODEL, max_tokens=1500,
            system=[{"type": "text", "text": PERSONA_SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": f"Cover facts to build on:\n\n{facts}"}],
        )
    except (APITimeoutError, APIStatusError, APIError) as exc:
        log.warning("Sockpuppet legend LLM error: %s", type(exc).__name__)
        return None
    except Exception as exc:
        log.warning("Sockpuppet legend LLM exception: %s", type(exc).__name__)
        return None

    raw = ""
    for block in response.content:
        if getattr(block, "type", None) == "text":
            raw += block.text
    raw = raw.strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)
    try:
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            return None
    except json.JSONDecodeError:
        log.warning("Sockpuppet legend LLM returned non-JSON")
        return None

    str_fields = ("full_name", "name_roman", "city", "city_roman", "region_roman",
                  "employer_roman", "job_title_roman", "occupation_context", "education",
                  "hobbies", "life_history", "writing_voice")
    out = {k: _strip_dashes(safe_str(parsed.get(k), 1500, "")) for k in str_fields}
    handles = parsed.get("extra_handles")
    out["extra_handles"] = [_strip_dashes(safe_str(h, 40, "")) for h in handles][:3] if isinstance(handles, list) else []
    return out


class GenRequest(BaseModel):
    gender: str = "random"
    country: str = "random"
    age: int | None = None
    include_financial: bool = False
    include_legend: bool = True


def _resolve_country(country: str):
    if not country or country == "random":
        c = random.choice(list(pycountry.countries))
        return c.alpha_2, c.name
    c = pycountry.countries.get(alpha_2=country.upper())
    if not c:
        raise HTTPException(status_code=400, detail="unknown country code")
    return c.alpha_2, c.name


@router.get("/countries")
async def get_countries():
    out = [{"code": c.alpha_2, "name": c.name, "tier": _tier(c.alpha_2)} for c in pycountry.countries]
    out.sort(key=lambda x: x["name"])
    tiers = {"A": 0, "B": 0, "C": 0}
    for c in out:
        tiers[c["tier"]] += 1
    return {"countries": out, "count": len(out), "tiers": tiers}


@router.post("/generate")
@limiter.limit("20/minute")
async def generate(req: GenRequest, request: Request):
    if req.age is not None and not (13 <= req.age <= 100):
        raise HTTPException(status_code=400, detail="age must be between 13 and 100, or left blank")

    cc, country_name = _resolve_country(req.country)
    cover, tier, need_identity = build_cover(cc, country_name, req.gender, req.age, req.include_financial)

    legend = {"available": False, "reason": "not_requested"}
    if req.include_legend or need_identity:
        if not LLM_SOCKPUPPET_ENABLED or not ANTHROPIC_API_KEY:
            legend = {"available": False, "reason": "disabled",
                      "message": "Legend generation is turned off on this server. The Cover above is complete "
                                 "(romanization is an approximate offline transliteration)."}
        else:
            source_ip = get_client_ip(request)
            allowed, used = rate_limit.check(_RL_TABLE, source_ip, SOCKPUPPET_LLM_PER_DAY)
            if not allowed:
                legend = {"available": False, "reason": "rate_limited",
                          "message": f"Legend daily limit reached ({used}/{SOCKPUPPET_LLM_PER_DAY} per 24 hours). "
                                     "The Cover above is complete; try again later for a back-story."}
            else:
                result = await _llm_persona(cover)
                if result is None:
                    legend = {"available": False, "reason": "error",
                              "message": "The Legend writer was unavailable. The Cover above is complete."}
                else:
                    rate_limit.record(_RL_TABLE, source_ip)
                    _fold_legend(cover, result, cc, country_name)
                    legend = {"available": True,
                              "content": {k: result.get(k, "") for k in
                                          ("occupation_context", "education", "hobbies", "life_history", "writing_voice")}}
                    legend["content"]["_source_note"] = "Legend and romanization by Claude Haiku 4.5 on the pinned Cover. Fictional; review before use."

    return {"cover": cover, "legend": legend,
            "disclaimer": "Research persona. Fictional. Not for impersonation of any real individual."}


def _fold_legend(cover: dict, result: dict, cc: str, country_name: str) -> None:
    """Fold the LLM identity + roman twins back into the Cover, then rebuild the
    handles and stem from the (now natural) roman name."""
    # Native identity for Tier B/C.
    if cover["field_sources"]["name"] == "legend" and result.get("full_name"):
        cover["personal"]["full_name"] = result["full_name"]
    if cover["field_sources"]["city"] == "legend" and result.get("city"):
        cover["address"]["city"] = result["city"]

    # Roman twins (primary; override the unidecode baseline).
    twin_map = [
        (result.get("name_roman"), cover["personal"], "name_roman", cover["personal"]["full_name"]),
        (result.get("city_roman"), cover["address"], "city_roman", cover["address"]["city"]),
        (result.get("region_roman"), cover["address"], "region_roman", cover["address"]["region"]),
        (result.get("employer_roman"), cover["professional"], "employer_roman", cover["professional"]["employer"]),
        (result.get("job_title_roman"), cover["professional"], "job_title_roman", cover["professional"]["job_title"]),
    ]
    for value, section, key, native in twin_map:
        section[key] = value if value else _roman(native)
    cover["romanization_approximate"] = False

    # Rebuild handles/stem/email/social from the natural roman name.
    nr = cover["personal"]["name_roman"]
    rp = nr.split()
    fr = rp[0] if rp else "user"
    lr = rp[-1] if len(rp) > 1 else fr
    birth_year = int(cover["personal"]["date_of_birth"][:4])
    _apply_identity(cover, fr, lr, birth_year, cover["personal"]["age"], cc,
                    cover["professional"]["job_title_roman"], cover["address"]["region_roman"])

    # Extra handles from the LLM (additive), deduped against the deterministic set.
    cur = cover["contact"]["username_suggestions"]
    for h in (result.get("extra_handles") or []):
        hh = re.sub(r"[^a-z0-9._]", "", str(h).lower())
        if hh and len(hh) >= 3 and hh not in cur:
            cur.append(hh)
    cover["contact"]["username_suggestions"] = cur[:11]

    cover["social"]["bio"] = _strip_dashes(
        f"{cover['professional']['job_title_roman']} based in {cover['address']['city_roman']}, {country_name}. Views my own.")
