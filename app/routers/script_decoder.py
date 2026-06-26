"""
Suspicious Script Decoder.

Takes obfuscated or encoded code (PowerShell, JavaScript, VBA, Base64 blobs, etc),
calls Claude Haiku 4.5 to deobfuscate and explain it, and returns structured findings.
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

LLM_DECODER_ENABLED = os.getenv("LLM_DECODER_ENABLED", "true").lower() == "true"

log = logging.getLogger(__name__)
router = APIRouter()

MAX_INPUT_CHARS = 100000
MIN_INPUT_CHARS = 20


class DecodeRequest(BaseModel):
    code: str
    hint: str | None = None


def _init_cache():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS script_decoder_cache (
            id TEXT PRIMARY KEY,
            response_json TEXT NOT NULL,
            fetched_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS script_decoder_rate_limit (
            source_ip TEXT NOT NULL,
            called_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_decoder_rate_ip ON script_decoder_rate_limit(source_ip, called_at)")
    conn.commit()
    conn.close()


_init_cache()


def _check_rate_limit(source_ip: str) -> tuple[bool, int]:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.execute(
        "SELECT COUNT(*) FROM script_decoder_rate_limit WHERE source_ip = ? AND called_at > datetime('now', '-24 hours')",
        (source_ip,),
    )
    count = cur.fetchone()[0]
    conn.close()
    return (count < LLM_RATE_LIMIT_PER_DAY, count)


def _record_call(source_ip: str):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO script_decoder_rate_limit (source_ip) VALUES (?)", (source_ip,))
    conn.execute("DELETE FROM script_decoder_rate_limit WHERE called_at < datetime('now', '-48 hours')")
    conn.commit()
    conn.close()


def _cache_key(code: str, hint: str | None) -> str:
    raw = code.strip() + "||HINT||" + (hint or "")
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()


DECODER_SYSTEM_PROMPT = """You are a malware analyst and incident responder specializing in deobfuscating malicious scripts and explaining what they do.

You will receive a code snippet that the user suspects is malicious or obfuscated. The code may be:
- PowerShell (often Base64-encoded, char-array obfuscation, string concatenation tricks)
- Windows batch / cmd
- JavaScript (often hex/unicode encoded, eval-wrapped, packed via JS packers)
- VBA / VBScript macros from Office documents
- Linux shell scripts with chained encodings
- Python with marshal/zlib obfuscation
- Raw Base64, hex, or other encoded blobs
- Mixed encodings (Base64 inside PowerShell, etc)

Your job:

1. Identify the language and encoding scheme(s) used
2. Deobfuscate the code one layer at a time until you reach plain-readable code (or determine it cannot be fully decoded)
3. Explain in plain English what the code does
4. Extract all IOCs (URLs, IPs, domains, file paths, registry keys, command-and-control infrastructure, file hashes)
5. Identify what malware family or technique this looks like, if recognizable
6. Suggest a simple Sigma rule or detection heuristic where applicable

Return ONLY valid JSON in this exact schema, no markdown, no preamble:

{
  "language": "<powershell|javascript|vba|batch|bash|python|base64|hex|unknown|mixed>",
  "encoding_layers": [
    "<description of each decoding step, in order applied>"
  ],
  "deobfuscated_code": "<the fully decoded code, formatted for readability; if multi-stage, show the final stage>",
  "intermediate_stages": [
    {
      "stage": "<short label>",
      "code": "<intermediate code at this stage>"
    }
  ],
  "explanation": "<3-5 sentence plain-English description of what the code does end-to-end>",
  "intent": "<one of: download_and_execute, credential_theft, persistence, lateral_movement, ransomware, reconnaissance, defense_evasion, command_and_control, data_exfiltration, dropper, legitimate, unclear>",
  "severity": "<critical|high|medium|low|info>",
  "iocs": {
    "urls": ["<extracted URLs>"],
    "ips": ["<extracted IPs>"],
    "domains": ["<extracted domains>"],
    "file_paths": ["<extracted paths>"],
    "registry_keys": ["<extracted registry keys>"],
    "hashes": ["<extracted file hashes>"],
    "commands": ["<notable command lines being executed>"]
  },
  "malware_family": "<best guess at family/technique, or null if uncertain>",
  "mitre_techniques": ["<MITRE ATT&CK technique IDs like T1059.001, max 5>"],
  "detection_suggestion": "<one-paragraph Sigma rule, EDR query suggestion, or detection heuristic>",
  "summary": "<one-sentence headline verdict>"
}

If the input is clearly NOT malicious (e.g., legitimate clean code, documentation, prose), set intent="legitimate" and severity="info" and explain why in the summary.

If you cannot decode the input at all (truly opaque encrypted blob, corrupted), still return the JSON with deobfuscated_code="(unable to decode)" and explanation describing what you observed about the structure.

Maximum 5000 characters in deobfuscated_code field. If longer, truncate with "... [truncated]" at the end.
"""


async def _llm_decode_script(code: str, hint: str | None = None) -> dict | None:
    """
    Run Claude Haiku 4.5 to deobfuscate and explain. Returns None on failure.

    Hard preconditions:
      - LLM_DECODER_ENABLED must be True
      - ANTHROPIC_API_KEY must be set
      - code must be at least MIN_INPUT_CHARS and at most MAX_INPUT_CHARS
    """
    # ===== HARDCODED MODEL: do NOT replace with a config variable =====
    HARDCODED_MODEL = "claude-haiku-4-5"
    # ==================================================================

    if not LLM_DECODER_ENABLED:
        return None
    if not ANTHROPIC_API_KEY:
        log.warning("Script decoder enabled but ANTHROPIC_API_KEY not set")
        return None
    if not code:
        return None

    code = code.strip()
    if len(code) < MIN_INPUT_CHARS or len(code) > MAX_INPUT_CHARS:
        return None

    user_msg_parts = []
    if hint and hint.strip():
        user_msg_parts.append(f"User hint about this code: {hint.strip()[:500]}")
    user_msg_parts.append(f"Code to analyze:\n\n{code}")
    user_msg = "\n\n".join(user_msg_parts)

    client = AsyncAnthropic(api_key=ANTHROPIC_API_KEY, timeout=LLM_TIMEOUT_SECONDS)

    try:
        response = await client.messages.create(
            model=HARDCODED_MODEL,
            max_tokens=4000,
            system=[
                {
                    "type": "text",
                    "text": DECODER_SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            messages=[{"role": "user", "content": user_msg}],
        )
    except APITimeoutError:
        log.warning("Script decoder LLM timed out")
        return None
    except APIStatusError as e:
        log.warning(f"Script decoder LLM API status error: {e.status_code} {e.message}")
        return None
    except APIError as e:
        log.warning(f"Script decoder LLM API error: {e}")
        return None
    except Exception as e:
        log.warning(f"Script decoder LLM exception: {type(e).__name__}: {e}")
        return None

    actual_model = getattr(response, "model", "")
    if HARDCODED_MODEL not in actual_model:
        log.warning(f"Decoder LLM response model mismatch: expected {HARDCODED_MODEL}, got {actual_model}")

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
        log.warning(f"Script decoder LLM returned non-JSON: {raw_text[:200]}... ({e})")
        return None


@router.post("/api/script-decoder/decode")
async def decode(req: DecodeRequest, request: Request):
    code = (req.code or "").strip()
    hint = (req.hint or "").strip() or None

    if not code:
        raise HTTPException(status_code=400, detail="code is required")
    if len(code) < MIN_INPUT_CHARS:
        raise HTTPException(status_code=400, detail=f"code too short (min {MIN_INPUT_CHARS} characters)")
    if len(code) > MAX_INPUT_CHARS:
        raise HTTPException(status_code=400, detail=f"code too large (max {MAX_INPUT_CHARS} characters)")

    if not LLM_DECODER_ENABLED:
        raise HTTPException(status_code=503, detail="Script decoder is currently disabled.")
    if not ANTHROPIC_API_KEY:
        raise HTTPException(status_code=503, detail="Script decoder is not configured. Missing API key.")

    cache_id = _cache_key(code, hint)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.execute(
        "SELECT response_json, fetched_at FROM script_decoder_cache WHERE id = ?",
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

    source_ip = request.client.host if request and request.client else "unknown"
    allowed, calls_used = _check_rate_limit(source_ip)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Daily limit reached ({calls_used}/{LLM_RATE_LIMIT_PER_DAY} script decodes per 24 hours). Try again later.",
        )

    result = await _llm_decode_script(code, hint)
    if not result:
        raise HTTPException(status_code=502, detail="Script decoder failed to produce a result.")

    _record_call(source_ip)

    result["cache_hit"] = False
    result["fetched_at"] = datetime.now(timezone.utc).isoformat()

    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT OR REPLACE INTO script_decoder_cache (id, response_json, fetched_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
        (cache_id, json.dumps(result)),
    )
    conn.commit()
    conn.close()

    return result
