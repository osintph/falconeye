"""
Google Dork Generator.

Takes a natural-language goal and optional target, returns LLM-generated
Google search queries with explanations and defensive-use notes.
"""
import hashlib
import json
import logging
import os
import re
import sqlite3
from datetime import datetime, timezone

from anthropic import AsyncAnthropic, APIError, APIStatusError, APITimeoutError
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from app.config import (
    DB_PATH,
    LLM_RATE_LIMIT_PER_DAY,
    LLM_TIMEOUT_SECONDS,
    ANTHROPIC_API_KEY,
)
from app.utils.client_ip import get_client_ip

LLM_DORKGEN_ENABLED = os.getenv("LLM_DORKGEN_ENABLED", "true").lower() == "true"

log = logging.getLogger(__name__)
router = APIRouter()


# ---------- request / response models ----------

class DorkGenRequest(BaseModel):
    goal: str
    target: str | None = None
    preset: str | None = None  # for analytics only, not sent to LLM


# ---------- cache and rate limit tables ----------

def _init_cache():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS dork_gen_cache (
            id TEXT PRIMARY KEY,
            response_json TEXT NOT NULL,
            fetched_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS dork_gen_rate_limit (
            source_ip TEXT NOT NULL,
            called_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_dorkgen_rate_ip ON dork_gen_rate_limit(source_ip, called_at)")
    conn.commit()
    conn.close()


_init_cache()


def _check_rate_limit(source_ip: str) -> tuple[bool, int]:
    """Returns (allowed, calls_used_in_window)."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.execute(
        "SELECT COUNT(*) FROM dork_gen_rate_limit WHERE source_ip = ? AND called_at > datetime('now', '-24 hours')",
        (source_ip,),
    )
    count = cur.fetchone()[0]
    conn.close()
    return (count < LLM_RATE_LIMIT_PER_DAY, count)


def _record_call(source_ip: str):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO dork_gen_rate_limit (source_ip) VALUES (?)", (source_ip,))
    conn.execute("DELETE FROM dork_gen_rate_limit WHERE called_at < datetime('now', '-48 hours')")
    conn.commit()
    conn.close()


def _cache_key(goal: str, target: str | None) -> str:
    raw = f"{goal.strip().lower()}||{(target or '').strip().lower()}"
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()


# ---------- LLM system prompt ----------

DORK_SYSTEM_PROMPT = """You are a Google dork generator for OSINT investigators, penetration testers, and defensive security analysts.

You will receive a natural-language goal and optionally a target domain or organization name. Generate 5 to 10 high-quality Google search queries (dorks) that help accomplish the goal.

Frame every dork with both offensive (recon) and defensive (surface monitoring) use cases. The same dork that finds an exposed admin panel for an attacker also finds the same exposure for a defender who wants to fix it.

Refuse to generate dorks if the user explicitly names a specific INDIVIDUAL (a real person's name) as the target with apparent intent to surveil or harm them. Generating dorks against ORGANIZATIONS, DOMAINS, or general categories is allowed and expected; this is standard OSINT and red team work.

For each dork, return:

- query: The exact Google search string. Use real operators that Google supports today (site:, inurl:, intitle:, intext:, filetype:/ext:, before:, after:, cache:). Do NOT use deprecated operators like info: or link:. If a target was provided, substitute it directly into the query.
- explanation: What the query finds. One to two sentences, plain English.
- defensive_use: How a defender would use this query to find their own exposure before an attacker does. One sentence.
- risk_level: One of "info", "sensitive", "high_impact":
    - info = general discovery, low sensitivity (subdomain enumeration, indexed pages)
    - sensitive = potential exposure of credentials, configs, or PII
    - high_impact = critical infrastructure exposure, authentication bypass, secrets

Return ONLY valid JSON in this exact schema, no markdown, no preamble:

{
  "dorks": [
    {
      "query": "<google search string>",
      "explanation": "<what it finds>",
      "defensive_use": "<how a defender uses it>",
      "risk_level": "<info|sensitive|high_impact>"
    }
  ],
  "refused": false,
  "refusal_reason": null,
  "notes": "<optional 1-2 sentence overall guidance, e.g. operator quirks or escalation order>"
}

If you must refuse (named-individual targeting), return:

{
  "dorks": [],
  "refused": true,
  "refusal_reason": "<one sentence explaining why>",
  "notes": null
}

Generate 5 to 10 dorks. Prefer specific, high-signal queries over generic ones. If a target was provided, ALL dorks should use that target. If no target was provided, use TARGET.com as a placeholder the user will substitute.
"""


# ---------- LLM call ----------

async def _llm_generate_dorks(goal: str, target: str | None) -> dict | None:
    """
    Run Claude Haiku 4.5 to generate dorks. Returns None on failure.

    Hard preconditions:
      - LLM_DORKGEN_ENABLED must be True
      - ANTHROPIC_API_KEY must be set
      - goal must be non-empty and at least 10 characters
    """
    # ===== HARDCODED MODEL: do NOT replace with a config variable =====
    HARDCODED_MODEL = "claude-haiku-4-5"
    # ==================================================================

    if not LLM_DORKGEN_ENABLED:
        return None
    if not ANTHROPIC_API_KEY:
        log.warning("Dork generator enabled but ANTHROPIC_API_KEY not set")
        return None
    if not goal or len(goal.strip()) < 10:
        return None

    user_msg_parts = [f"Goal: {goal.strip()}"]
    if target and target.strip():
        user_msg_parts.append(f"Target: {target.strip()}")
    user_msg = "\n\n".join(user_msg_parts)

    client = AsyncAnthropic(api_key=ANTHROPIC_API_KEY, timeout=LLM_TIMEOUT_SECONDS)

    try:
        response = await client.messages.create(
            model=HARDCODED_MODEL,
            max_tokens=2000,
            system=[
                {
                    "type": "text",
                    "text": DORK_SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            messages=[{"role": "user", "content": user_msg}],
        )
    except APITimeoutError:
        log.warning("Dork LLM call timed out")
        return None
    except APIStatusError as e:
        log.warning(f"Dork LLM API status error: {e.status_code} {e.message}")
        return None
    except APIError as e:
        log.warning(f"Dork LLM API error: {e}")
        return None
    except Exception as e:
        log.warning(f"Dork LLM call exception: {type(e).__name__}: {e}")
        return None

    actual_model = getattr(response, "model", "")
    if HARDCODED_MODEL not in actual_model:
        log.warning(f"Dork LLM response model mismatch: expected {HARDCODED_MODEL}, got {actual_model}")

    raw_text = ""
    try:
        for block in response.content:
            if getattr(block, "type", None) == "text":
                raw_text += block.text
        raw_text = raw_text.strip()
        if raw_text.startswith("```"):
            raw_text = re.sub(r"^```(?:json)?\s*", "", raw_text)
            raw_text = re.sub(r"\s*```$", "", raw_text)

        parsed = json.loads(raw_text)
        parsed["_usage"] = {
            "model": actual_model,
            "input_tokens": response.usage.input_tokens,
            "output_tokens": response.usage.output_tokens,
            "cache_read_input_tokens": getattr(response.usage, "cache_read_input_tokens", 0),
            "cache_creation_input_tokens": getattr(response.usage, "cache_creation_input_tokens", 0),
        }
        return parsed
    except (json.JSONDecodeError, AttributeError) as e:
        log.warning(f"Dork LLM returned non-JSON: {raw_text[:200]}... ({e})")
        return None


# ---------- main endpoint ----------

@router.post("/api/dork-generator/generate")
async def generate(req: DorkGenRequest, request: Request):
    goal = (req.goal or "").strip()
    target = (req.target or "").strip()

    if not goal:
        raise HTTPException(status_code=400, detail="goal is required")
    if len(goal) < 10:
        raise HTTPException(status_code=400, detail="goal must be at least 10 characters")
    if len(goal) > 1000:
        raise HTTPException(status_code=400, detail="goal too long (max 1000 chars)")
    if target and len(target) > 200:
        raise HTTPException(status_code=400, detail="target too long (max 200 chars)")

    if not LLM_DORKGEN_ENABLED:
        raise HTTPException(
            status_code=503,
            detail="Dork generator is currently disabled. The operator has turned off LLM-powered features.",
        )
    if not ANTHROPIC_API_KEY:
        raise HTTPException(
            status_code=503,
            detail="Dork generator is not configured. Missing API key.",
        )

    cache_id = _cache_key(goal, target)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.execute(
        "SELECT response_json, fetched_at FROM dork_gen_cache WHERE id = ?",
        (cache_id,),
    )
    row = cur.fetchone()
    conn.close()

    if row:
        cached_json, fetched_at = row
        cached = json.loads(cached_json)
        cached["cache_hit"] = True
        cached["fetched_at"] = fetched_at
        return cached

    source_ip = get_client_ip(request) if request else "unknown"
    allowed, calls_used = _check_rate_limit(source_ip)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Daily limit reached ({calls_used}/{LLM_RATE_LIMIT_PER_DAY} dork generations per 24 hours). Try again later.",
        )

    result = await _llm_generate_dorks(goal, target)
    if not result:
        raise HTTPException(
            status_code=502,
            detail="Dork generator failed to produce a result. Try rephrasing your goal or try again in a moment.",
        )

    _record_call(source_ip)

    result["cache_hit"] = False
    result["fetched_at"] = datetime.now(timezone.utc).isoformat()
    result["goal"] = goal
    result["target"] = target or None

    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT OR REPLACE INTO dork_gen_cache (id, response_json, fetched_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
        (cache_id, json.dumps(result)),
    )
    conn.commit()
    conn.close()

    return result
