"""
Sock Puppet Generator - fictional OSINT research personas.

Coverage is EVERY ISO 3166 country, not Faker's locale subset. Coherence is
anchored on the country code via an offline metadata layer (no runtime cost):
  pycountry        - country name, ISO codes, subdivisions
  babel            - currency for the country
  phonenumbers     - calling code and example phone format (masked, non dialable)
  pytz             - timezone for the country

Tiered generation so any country produces a coherent persona:
  Tier A (full Faker locale)    - Faker does name, street, city, region, postcode
  Tier B (Faker name only)      - Faker name; address structure from metadata; city
                                  from the Legend pass or a subdivision fallback
  Tier C (no Faker locale)      - name and city from the Legend pass constrained to
                                  the country; structural fields from metadata

Two layers, intelligence tradecraft:
  Cover  - deterministic surface facts (always generated, no LLM required).
  Legend - one Haiku call on top of the Cover (optional; for Tier C it also supplies
           the name and city, with an offline fallback so the Cover never fails).

Personas are entirely fictional. For authorized OSINT investigative use only; never
to impersonate a real individual. House style: no em dashes anywhere (also required
for the jsPDF Latin-1 export).
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


# ---------------------------------------------------------------------------
# Tier map: country code -> best Faker locale (computed once at import)
# ---------------------------------------------------------------------------

def _has_provider(kind: str, loc: str) -> bool:
    return importlib.util.find_spec(f"faker.providers.{kind}.{loc}") is not None


def _locale_cc(loc: str) -> str | None:
    parts = loc.split("_")
    if len(parts) >= 2 and len(parts[-1]) == 2 and parts[-1].isupper():
        cc = parts[-1]
        if pycountry.countries.get(alpha_2=cc):
            return cc
    return None


# cc -> (locale, address_native, person_native)
_CC_LOCALE: dict[str, tuple[str, bool, bool]] = {}
for _loc in AVAILABLE_LOCALES:
    _cc = _locale_cc(_loc)
    if not _cc:
        continue
    _addr, _person = _has_provider("address", _loc), _has_provider("person", _loc)
    _score = (int(_addr), int(_loc.startswith("en_")))
    _cur = _CC_LOCALE.get(_cc)
    if _cur is None or _score > (int(_cur[1]), int(_cur[0].startswith("en_"))):
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

# The US spans several zones and Faker shows a real state, so refine the
# country-level pytz zone by state (a Texas legend must not read as Eastern).
# All other countries use the country-level zone from pytz.country_timezones.
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


# ---------------------------------------------------------------------------
# Offline metadata (country code anchored)
# ---------------------------------------------------------------------------

def _mask_phone(cc: str) -> tuple[str | None, str]:
    """(calling_code, masked example) so the format is right but the number is not
    dialable. Masks every digit after the +code with X."""
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
    tail = re.sub(r"\d", "X", tail)
    return code, f"{head}{tail}".strip()


def _currency(cc: str) -> str:
    try:
        codes = get_territory_currencies(cc) or []
    except Exception:
        codes = []
    if not codes:
        return ""
    code = codes[0]
    cur = pycountry.currencies.get(alpha_3=code)
    return f"{code} ({cur.name})" if cur else code


def _metadata(cc: str) -> dict:
    tzs = pytz.country_timezones.get(cc) or ["UTC"]
    subs = [s.name for s in (pycountry.subdivisions.get(country_code=cc) or [])]
    code, phone = _mask_phone(cc)
    return {
        "timezone": tzs[0],
        "currency": _currency(cc),
        "calling_code": f"+{code}" if code else "",
        "phone_scaffold": phone,
        "subdivisions": subs,
    }


# ---------------------------------------------------------------------------
# Cover
# ---------------------------------------------------------------------------

def _oneline(value) -> str:
    return re.sub(r"\s*\n\s*", ", ", str(value or "")).strip()


def _strip_dashes(text: str) -> str:
    if not text:
        return text
    return (
        text.replace("—", " ").replace("–", "-")
        .replace("‘", "'").replace("’", "'")
        .replace("“", '"').replace("”", '"')
        .replace("…", "...")
    )


def _username_stem(first: str, last: str) -> str:
    base = re.sub(r"[^a-z0-9]", "", (first + last).lower())
    if not base:
        base = "researchpersona"
    return f"{base[:18]}{random.randint(1, 987)}"


def _dob_for(age):
    """Return (dob_iso, age) using a throwaway en_US Faker for the date math only."""
    f = Faker("en_US")
    from datetime import date
    if age is not None:
        dob = f.date_of_birth(minimum_age=int(age), maximum_age=int(age))
    else:
        dob = f.date_of_birth(minimum_age=22, maximum_age=58)
    today = date.today()
    real_age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
    return dob.isoformat(), real_age


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
    """Build the Cover for a country. Returns (cover, tier, need_llm_identity).
    need_llm_identity is True when name and/or city should come from the Legend pass
    (Tier B: city; Tier C: name and city)."""
    tier = _tier(cc)
    gender = _pick_gender(gender_req)
    meta = _metadata(cc)
    region = random.choice(meta["subdivisions"]) if meta["subdivisions"] else ""
    dob_iso, age_val = _dob_for(age)

    name_source = "faker"
    city_source = "faker"
    need_llm_identity = False

    if tier == "A":
        fake = Faker(_CC_LOCALE[cc][0])
        first, last = _faker_name(fake, gender)
        full_name = f"{first} {last}"
        street = _oneline(fake.street_address())
        city = fake.city()
        region = fake.administrative_unit() if hasattr(fake, "administrative_unit") else region
        postal = str(fake.postcode())
        job_title = fake.job()
        employer = fake.company()
        color = fake.color_name()
    elif tier == "B":
        fake = Faker(_CC_LOCALE[cc][0])
        first, last = _faker_name(fake, gender)
        full_name = f"{first} {last}"
        street = "[street to be set by the operator]"
        city = ""                      # from Legend pass or region fallback
        city_source = "legend"
        need_llm_identity = True
        postal = ""
        job_title = random.choice(JOB_TITLES)
        employer = f"{last} {random.choice(['Group', 'Holdings', 'Services', 'Trading'])}"
        color = random.choice(COLORS)
    else:  # Tier C
        first, last = "", ""
        full_name = ""                 # from Legend pass or neutral fallback
        name_source = "legend"
        city = ""
        city_source = "legend"
        need_llm_identity = True
        street = "[street to be set by the operator]"
        postal = ""
        job_title = random.choice(JOB_TITLES)
        employer = f"{country_name} {random.choice(['Group', 'Holdings', 'Services', 'Trading'])}"
        color = random.choice(COLORS)

    # Offline fallbacks for name/city so the Cover is complete even with no LLM.
    if not full_name:
        nf = Faker("en_US")
        ffirst, flast = _faker_name(nf, gender)
        full_name = f"{ffirst} {flast}"
        first, last = ffirst, flast
    if not first:
        parts = full_name.split()
        first, last = parts[0], (parts[-1] if len(parts) > 1 else parts[0])
    if not city:
        city = region or f"{country_name} (capital region)"

    tz = meta["timezone"]
    if cc == "US":
        tz = US_STATE_TZ.get(region, tz)

    stem = _username_stem(first, last)
    max_exp = max(1, min(age_val - 21, 32))

    cover = {
        "country_code": cc,
        "tier": tier,
        "personal": {
            "full_name": full_name,
            "date_of_birth": dob_iso,
            "age": age_val,
            "gender": gender,
            "nationality": country_name,
        },
        "address": {
            "street": street,
            "city": city,
            "region": region,
            "postal_code": postal,
            "country": country_name,
        },
        "contact": {
            "username_stem": stem,
            "email_placeholder": f"{stem}@PROVIDER.example  (PLACEHOLDER, register with a provider that fits the persona)",
            "phone_placeholder": (meta["phone_scaffold"] + "  (PLACEHOLDER, register a controlled number; expect VoIP to be blocked)")
                                 if meta["phone_scaffold"] else
                                 f"{meta['calling_code']} XXXXXXXXX  (PLACEHOLDER, register a controlled number)",
        },
        "professional": {
            "employer": employer,
            "job_title": job_title,
            "department": random.choice(DEPARTMENTS),
            "years_experience": random.randint(1, max_exp),
        },
        "additional": {
            "timezone": tz,
            "currency": meta["currency"],
            "calling_code": meta["calling_code"],
            "favorite_color": color,
            "vehicle": random.choice(VEHICLES),
        },
        "social": {
            "handle": f"@{stem}",
            "bio": _strip_dashes(f"{job_title} based in {city}, {country_name}. Views my own."),
            "followers": random.randint(80, 4200),
            "following": random.randint(60, 900),
            "posts": random.randint(12, 1600),
            "note": "Fictional social scaffolding for legend completeness, not a real account.",
        },
        "field_sources": {
            "name": name_source,
            "city": city_source,
            "timezone_phone_currency": "offline metadata (country code)",
        },
    }

    if include_financial:
        ff = Faker("en_US")
        cover["financial"] = {
            "card_number": ff.credit_card_number(),
            "provider": ff.credit_card_provider(),
            "expiry": ff.credit_card_expire(),
            "iban": ff.iban(),
            "note": "Test-only Faker values (Luhn valid but not real). Fictional filler, "
                    "not a payment instrument. Real funding needs a genuine burner-card service.",
        }

    return cover, tier, need_llm_identity


# ---------------------------------------------------------------------------
# Legend (LLM)
# ---------------------------------------------------------------------------

PERSONA_SYSTEM_PROMPT = """You write a fictional cover-identity back-story, a legend, for an authorized OSINT research persona.

The persona is entirely fictional. Never base it on, resemble, or impersonate a real, identifiable person. Do not add real contact details, real handles, or real companies.

You receive a fixed Cover of surface facts, plus the country. Build a back-story that is fully consistent with every Cover fact and never contradicts the age, gender, location, employer, or job. Keep it grounded and plausible, with no loose ends a reviewer could pull.

When the Cover marks the full name or the city as "PROVIDE", you must invent one that is fictional but culturally plausible for the stated country and gender, and a real city in that country. Otherwise use the given values and do not change them.

Write in plain English. Do NOT use em dashes or en dashes; use commas, periods, or the word "to" for ranges. No fancy quotation marks.

Return ONLY valid JSON in this exact shape, no markdown or preamble:

{
  "full_name": "the full name (echo the given one, or invent one only if it was PROVIDE)",
  "city": "the city (echo the given one, or invent a real city in the country only if it was PROVIDE)",
  "occupation_context": "1 to 2 sentences on what they do day to day and how they got there.",
  "education": "1 to 2 sentences on schooling consistent with the age and job.",
  "hobbies": "1 to 2 sentences on interests that fit the location and persona.",
  "life_history": "3 to 5 sentences of coherent life history with no loose ends.",
  "writing_voice": "1 to 2 sentences on how this persona writes so their posts stay consistent."
}
"""


async def _llm_persona(cover: dict, country_name: str, need_identity: bool) -> dict | None:
    # ===== HARDCODED MODEL: do NOT replace with a config variable =====
    HARDCODED_MODEL = "claude-haiku-4-5"
    # ==================================================================
    if not ANTHROPIC_API_KEY:
        return None

    p = cover["personal"]
    a = cover["address"]
    pr = cover["professional"]
    name_field = "PROVIDE" if cover["field_sources"]["name"] == "legend" else p["full_name"]
    city_field = "PROVIDE" if cover["field_sources"]["city"] == "legend" else a["city"]
    facts = (
        f"Country: {country_name}\n"
        f"Full name: {name_field}\n"
        f"City: {city_field}\n"
        f"Region: {a['region']}\n"
        f"Age: {p['age']} (DOB {p['date_of_birth']})\n"
        f"Gender: {p['gender']}\n"
        f"Timezone: {cover['additional']['timezone']}\n"
        f"Employer: {pr['employer']}\n"
        f"Job title: {pr['job_title']}\n"
        f"Department: {pr['department']}\n"
        f"Years of experience: {pr['years_experience']}\n"
    )

    client = AsyncAnthropic(api_key=ANTHROPIC_API_KEY, timeout=LLM_TIMEOUT_SECONDS)
    try:
        response = await client.messages.create(
            model=HARDCODED_MODEL,
            max_tokens=1300,
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

    fields = ("full_name", "city", "occupation_context", "education", "hobbies", "life_history", "writing_voice")
    out = {k: _strip_dashes(safe_str(parsed.get(k), 1500, "")) for k in fields}
    out["_source_note"] = "Legend written by Claude Haiku 4.5 on top of the Cover. Fictional; review before use."
    return out


class GenRequest(BaseModel):
    gender: str = "random"
    country: str = "random"          # ISO alpha-2, or "random"
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
    """Full ISO 3166 country list, each tagged with its generation tier."""
    out = [{"code": c.alpha_2, "name": c.name, "tier": _tier(c.alpha_2)}
           for c in pycountry.countries]
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
    want_llm = req.include_legend or need_identity   # Tier B/C always want identity from the LLM
    if want_llm:
        if not LLM_SOCKPUPPET_ENABLED or not ANTHROPIC_API_KEY:
            legend = {"available": False, "reason": "disabled",
                      "message": "Legend generation is turned off on this server. The Cover above is complete "
                                 "(name and city use an offline fallback for this country)."}
        else:
            source_ip = get_client_ip(request)
            allowed, used = rate_limit.check(_RL_TABLE, source_ip, SOCKPUPPET_LLM_PER_DAY)
            if not allowed:
                legend = {"available": False, "reason": "rate_limited",
                          "message": f"Legend daily limit reached ({used}/{SOCKPUPPET_LLM_PER_DAY} per 24 hours). "
                                     "The Cover above is complete; try again later for a back-story."}
            else:
                result = await _llm_persona(cover, country_name, need_identity)
                if result is None:
                    legend = {"available": False, "reason": "error",
                              "message": "The Legend writer was unavailable. The Cover above is complete."}
                else:
                    rate_limit.record(_RL_TABLE, source_ip)
                    # Fold LLM-provided identity back into the Cover (Tier B/C).
                    if cover["field_sources"]["name"] == "legend" and result.get("full_name"):
                        cover["personal"]["full_name"] = result["full_name"]
                        parts = result["full_name"].split()
                        stem = _username_stem(parts[0], parts[-1] if len(parts) > 1 else parts[0])
                        cover["contact"]["username_stem"] = stem
                        cover["contact"]["email_placeholder"] = f"{stem}@PROVIDER.example  (PLACEHOLDER, register with a provider that fits the persona)"
                        cover["social"]["handle"] = f"@{stem}"
                    if cover["field_sources"]["city"] == "legend" and result.get("city"):
                        cover["address"]["city"] = result["city"]
                        cover["social"]["bio"] = _strip_dashes(
                            f"{cover['professional']['job_title']} based in {result['city']}, {country_name}. Views my own.")
                    legend = {"available": True, "content": {k: v for k, v in result.items()
                                                             if k not in ("full_name", "city")}}

    return {
        "cover": cover,
        "legend": legend,
        "disclaimer": "Research persona. Fictional. Not for impersonation of any real individual.",
    }
