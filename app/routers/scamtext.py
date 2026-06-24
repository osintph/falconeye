import hashlib
import re
import sqlite3
from fastapi import APIRouter, Request, Depends, HTTPException
from pydantic import BaseModel
from app.utils.ratelimit import limiter
from app.database import get_db

router = APIRouter(prefix="/api/scamtext", tags=["scamtext"])

VALID_BRANDS = {"GCASH", "MAYA", "BDO", "BPI", "LANDBANK", "UNIONBANK", "RCBC", "METROBANK", "LBC", "PHLPOST", "OTHER"}

URL_PATTERN = re.compile(r'https?://[^\s<>"\']+')


def extract_url(text: str) -> str | None:
    match = URL_PATTERN.search(text)
    return match.group(0) if match else None


def compute_hash(content: str) -> str:
    return hashlib.sha256(content.strip().lower().encode()).hexdigest()


class ScamTextSubmission(BaseModel):
    brand_tag: str
    sender_id: str | None = None
    message_content: str


@router.post("/submit")
@limiter.limit("5/minute")
async def submit_scam_text(request: Request, payload: ScamTextSubmission, db: sqlite3.Connection = Depends(get_db)):
    brand = payload.brand_tag.upper().strip()
    if brand not in VALID_BRANDS:
        raise HTTPException(status_code=400, detail=f"Invalid brand_tag. Must be one of: {', '.join(sorted(VALID_BRANDS))}")

    if len(payload.message_content.strip()) < 10:
        raise HTTPException(status_code=400, detail="Message content too short.")

    content_hash = compute_hash(payload.message_content)
    extracted_url = extract_url(payload.message_content)

    try:
        db.execute(
            """
            INSERT INTO scam_texts (sha256_hash, brand_tag, sender_id, message_content, extracted_url)
            VALUES (?, ?, ?, ?, ?)
            """,
            (content_hash, brand, payload.sender_id, payload.message_content.strip(), extracted_url),
        )
        db.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="This message has already been reported.")

    return {
        "status": "accepted",
        "sha256": content_hash,
        "extracted_url": extracted_url,
        "brand_tag": brand,
    }


@router.get("/search")
@limiter.limit("30/minute")
async def search_scam_texts(
    request: Request,
    brand: str | None = None,
    q: str | None = None,
    limit: int = 50,
    db: sqlite3.Connection = Depends(get_db),
):
    limit = min(limit, 100)
    query = "SELECT id, brand_tag, sender_id, message_content, extracted_url, date_reported FROM scam_texts WHERE 1=1"
    params = []

    if brand:
        query += " AND brand_tag = ?"
        params.append(brand.upper())

    if q:
        query += " AND message_content LIKE ?"
        params.append(f"%{q}%")

    query += " ORDER BY date_reported DESC LIMIT ?"
    params.append(limit)

    rows = db.execute(query, params).fetchall()
    return [dict(row) for row in rows]


@router.get("/stats")
async def scam_stats(db: sqlite3.Connection = Depends(get_db)):
    rows = db.execute(
        "SELECT brand_tag, COUNT(*) as count FROM scam_texts GROUP BY brand_tag ORDER BY count DESC"
    ).fetchall()
    total = db.execute("SELECT COUNT(*) as total FROM scam_texts").fetchone()
    return {
        "total": total["total"],
        "by_brand": [dict(row) for row in rows],
    }
