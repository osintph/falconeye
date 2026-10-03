# FalconEye — Independent Review Bundle

Verbatim source of the four highest-risk custom security paths, for a cold second-model read. **No findings from the primary assessment are included here** — review these on their own merits.

For each path: assess against SSRF (resolve-then-connect consistency, redirect revalidation, IP-encoding/IPv6/metadata coverage, fail-open vs fail-closed), untrusted-binary decoding (decompression bombs, unbounded recursion/memory, version CVEs), and mail/auth abuse (credential-check bypass, open relay, header injection, secret leakage).

---

## Path 1 — SSRF guard: `app/utils/safe_fetch.py`
*What it does:* the single SSRF primitive for all outbound fetches of attacker-controlled URLs. `is_private_ip` classifies an address as blockable; `resolve_and_check` resolves a hostname and rejects it if any resolved address is private/reserved; `safe_fetch` fetches a URL, re-validating the host on every redirect hop.

```python
"""
SSRF-safe HTTP fetcher for user-supplied URLs.

Defends against two bypass classes identified in H-1:
  1. Redirect-chain bypass: validates every hop independently (follow_redirects=False
     on the underlying client; we parse Location and re-validate before each request).
  2. DNS rebinding (TOCTOU): re-resolves and re-validates the hostname at the start of
     every hop, so a short-TTL rebind between check-time and use-time is caught on the
     next resolution. httpx still performs its own resolution at connect time (the true
     TOCTOU window), but this matches the threatintel-platform posture and narrows the
     gap substantially.

Only call this for requests where the URL is attacker-controlled.  Fixed-host API
calls (Shodan, RDAP, Telegram, etc.) should continue using httpx directly.
"""

import ipaddress
import socket
from typing import Optional
from urllib.parse import urlparse, urljoin

import httpx

ALLOWED_SCHEMES = {"http", "https"}

# Explicit blocks for ranges that ipaddress stdlib does not classify via the
# is_private / is_loopback / is_link_local / is_reserved / is_unspecified
# flags on Python 3.9 (L-1 blocklist completeness):
#   0.0.0.0/8  — "This" network (RFC 1122 §3.2.1.3): also caught by is_private
#   100.64.0.0/10 — CGNAT (RFC 6598): NOT in is_private on Python 3.9
#   64:ff9b::/96  — NAT64 well-known prefix (RFC 6052): NOT reliably in stdlib flags
# Remaining ranges (169.254.0.0/16, fe80::/10, ::/128, ::1, ::ffff:a.b.c.d)
# are caught by is_link_local, is_unspecified, is_loopback, or the ipv4_mapped
# unwrap below.
_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_THIS_NETWORK = ipaddress.ip_network("0.0.0.0/8")


class SafeFetchError(Exception):
    """Raised when safe_fetch refuses or cannot complete a request."""


def is_private_ip(addr: str) -> bool:
    """Return True if *addr* should be blocked (private, loopback, link-local, etc.)."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return True  # fail closed on unparseable addresses

    # Unwrap ::ffff:a.b.c.d to get the real IPv4 address.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    ):
        return True

    if isinstance(ip, ipaddress.IPv4Address):
        if ip in _CGNAT or ip in _THIS_NETWORK:
            return True
    elif isinstance(ip, ipaddress.IPv6Address):
        if ip in _NAT64:
            return True

    return False


def resolve_and_check(host: str) -> list[str]:
    """Resolve *host* and raise SafeFetchError if any returned address is private.

    Returns the list of validated public IP strings on success.
    """
    try:
        results = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise SafeFetchError(f"Could not resolve hostname: {host}") from exc

    addrs: list[str] = []
    for result in results:
        addr = result[4][0]
        if is_private_ip(addr):
            raise SafeFetchError("hostname resolves to a private or reserved address")
        addrs.append(addr)

    if not addrs:
        raise SafeFetchError(f"No addresses returned for hostname: {host}")

    return addrs


async def safe_fetch(
    url: str,
    method: str = "GET",
    headers: Optional[dict] = None,
    timeout: float = 15.0,
    max_redirects: int = 3,
    allow_redirects: bool = True,
) -> dict:
    """Fetch *url* safely, re-validating every redirect hop against the SSRF blocklist.

    Returns a dict with keys: status, headers, body, url_final.
    Raises SafeFetchError on any policy violation or if max_redirects is exceeded.
    """
    current_url = url

    for hop in range(max_redirects + 1):
        parsed = urlparse(current_url)

        if parsed.scheme not in ALLOWED_SCHEMES:
            raise SafeFetchError(f"Scheme {parsed.scheme!r} is not allowed")

        host = parsed.hostname
        if not host:
            raise SafeFetchError("URL has no hostname")

        resolve_and_check(host)

        async with httpx.AsyncClient(
            follow_redirects=False,
            verify=True,
            timeout=timeout,
        ) as client:
            response = await client.request(
                method,
                current_url,
                headers=headers or {},
            )

        if allow_redirects and response.status_code in {301, 302, 303, 307, 308}:
            location = response.headers.get("location", "").strip()
            if not location:
                raise SafeFetchError("Redirect response missing Location header")

            # Resolve relative redirects against the current URL.
            next_url = urljoin(current_url, location)

            if hop == max_redirects:
                raise SafeFetchError(f"Exceeded maximum redirects ({max_redirects})")

            # 303 mandates GET for the subsequent request.
            if response.status_code == 303:
                method = "GET"

            current_url = next_url
            continue

        return {
            "status": response.status_code,
            "headers": dict(response.headers),
            "body": response.text,
            "url_final": str(response.url),
        }

    raise SafeFetchError(f"Exceeded maximum redirects ({max_redirects})")
```

> Review focus: `resolve_and_check(host)` validates the *resolved IP*, but `client.request(method, current_url, ...)` is then given the *hostname*, so httpx re-resolves at connect time. Is the connection ever pinned to the validated IP? What happens if DNS returns a different address on the second resolution?

---

## Path 2 — QR decoder (untrusted image bytes): `app/routers/qr_analyzer.py`
*What it does:* decodes QR codes from an uploaded image or a base64 data URI, fully in memory, via Pillow + pyzbar. Never fetches decoded URLs.

```python
MAX_IMAGE_BYTES = 5 * 1024 * 1024  # 5 MB

def decode_qr(image_bytes: bytes) -> dict:
    """Decode every QR code in *image_bytes*. In-memory only."""
    if len(image_bytes) > MAX_IMAGE_BYTES:
        return {"count": 0, "codes": [], "error": "Image exceeds the 5 MB limit."}
    try:
        img = Image.open(io.BytesIO(image_bytes))
        img.load()  # force a real decode so we reject non-image / corrupt input
    except Exception:
        return {"count": 0, "codes": [], "error": "Not a valid image file."}

    try:
        results = zbar_decode(img)
    except Exception as exc:
        return {"count": 0, "codes": [], "error": f"QR decode error: {type(exc).__name__}"}

    codes = []
    for idx, result in enumerate(results, start=1):
        content = result.data.decode("utf-8", errors="replace")
        kind, is_url = _categorize(content)
        codes.append({"index": idx, "data": content, "is_url": is_url, "kind": kind})

    return {
        "count": len(codes),
        "codes": codes,
        "error": None if codes else "No QR code detected. Try a higher-resolution image.",
    }


def _decode_data_uri(data_uri: str) -> bytes:
    raw = data_uri.strip()
    if raw.startswith("data:"):
        comma = raw.find(",")
        if comma == -1:
            raise ValueError("malformed data URI")
        header, raw = raw[:comma], raw[comma + 1:]
        if "base64" not in header:
            raise ValueError("only base64 data URIs are supported")
    try:
        return base64.b64decode(raw, validate=True)
    except Exception as exc:
        raise ValueError(f"invalid base64 payload: {exc}")


@router.post("/decode")
@limiter.limit("10/minute")
async def decode(request: Request, image: UploadFile | None = File(default=None)):
    source_ip = get_client_ip(request)
    allowed, used = _check_rate_limit(source_ip)
    if not allowed:
        raise HTTPException(status_code=429, detail=f"Daily limit reached ...")

    if image is not None:
        image_bytes = await image.read()
    else:
        try:
            body = await request.json()
        except Exception:
            body = {}
        data_uri = (body or {}).get("data_uri")
        if not data_uri:
            raise HTTPException(status_code=400, detail="Provide an image file or a data_uri.")
        try:
            image_bytes = _decode_data_uri(data_uri)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    if not image_bytes:
        raise HTTPException(status_code=400, detail="Empty image payload.")
    if len(image_bytes) > MAX_IMAGE_BYTES:
        raise HTTPException(status_code=413, detail="Image exceeds the 5 MB limit.")

    _record_call(source_ip)
    return decode_qr(image_bytes)
```

> Review focus: `img.load()` forces full rasterization. Is there a cap on decoded pixel dimensions (decompression bomb), or only on the 5 MB compressed input? Is Pillow pinned to a non-vulnerable version? Note the multipart body is parsed by `python-multipart`/Starlette *before* these size checks run.

---

## Path 3 — Email MIME parser (untrusted email): `app/routers/email_header.py`
*What it does:* parses pasted raw email headers/bodies and uploaded `.eml`/`.msg` files, walking MIME structure and decoding payloads. `/analyze` is unauthenticated with no rate limit.

```python
# ---- uploaded-file parser ----
def _parse_email_file(file_bytes: bytes, filename: str) -> tuple[str, str]:
    """Parse an uploaded email file and return (raw_header, raw_body).
    Supports .eml / .txt (RFC 822 MIME) and .msg (Outlook binary)."""
    lower_name = (filename or "").lower()

    if lower_name.endswith(".eml") or lower_name.endswith(".txt"):
        try:
            text = file_bytes.decode("utf-8", errors="replace")
        except Exception as e:
            raise ValueError(f"Could not decode .eml file: {e}")
        if "\r\n\r\n" in text:
            header_part, body_part = text.split("\r\n\r\n", 1)
        elif "\n\n" in text:
            header_part, body_part = text.split("\n\n", 1)
        else:
            header_part = text
            body_part = ""
        return header_part, body_part

    if lower_name.endswith(".msg"):
        try:
            import extract_msg
        except ImportError:
            raise ValueError(".msg support requires extract-msg package. Contact the operator.")
        with tempfile.NamedTemporaryFile(suffix=".msg", delete=True) as tmp:
            tmp.write(file_bytes)
            tmp.flush()
            try:
                msg = extract_msg.Message(tmp.name)
            except Exception as e:
                raise ValueError(f"Could not parse .msg file: {e}")
            try:
                header_lines = []
                if msg.header:
                    header_lines.append(str(msg.header))
                else:
                    if msg.sender:    header_lines.append(f"From: {msg.sender}")
                    if msg.to:        header_lines.append(f"To: {msg.to}")
                    if msg.cc:        header_lines.append(f"Cc: {msg.cc}")
                    if msg.subject:   header_lines.append(f"Subject: {msg.subject}")
                    if msg.date:      header_lines.append(f"Date: {msg.date}")
                    if msg.messageId: header_lines.append(f"Message-ID: {msg.messageId}")
                header_text = "\n".join(header_lines)
                body_text = ""
                if msg.htmlBody:
                    body_text = msg.htmlBody if isinstance(msg.htmlBody, str) else msg.htmlBody.decode("utf-8", errors="replace")
                elif msg.body:
                    body_text = msg.body
                return header_text, body_text
            finally:
                try: msg.close()
                except Exception: pass
    raise ValueError(f"Unsupported file type: {filename}. Supported formats: .eml, .msg, .txt")


# ---- analyze endpoint (no rate-limit decorator) ----
@router.post("/api/email-header/analyze")
async def analyze(req: HeaderAnalyzeRequest, request: Request):
    raw = req.raw_header.strip()
    body_input = (req.raw_body or "").strip()
    if not raw:
        raise HTTPException(status_code=400, detail="empty header input")
    if len(raw) > 200000:
        raise HTTPException(status_code=400, detail="header too large (max 200KB)")
    if len(body_input) > 500000:
        raise HTTPException(status_code=400, detail="body too large (max 500KB)")
    # ... cache lookup by sha256(raw + body) ...

    msg = message_from_string(raw)          # <-- not wrapped in try/except
    headers_pairs = list(msg.items())

    body_to_analyze = body_input
    if not body_to_analyze:
        try:
            if msg.is_multipart():
                for part in msg.walk():     # <-- walks arbitrarily nested MIME
                    ctype = part.get_content_type()
                    if ctype in ("text/html", "text/plain"):
                        payload = part.get_payload(decode=True)
                        if payload:
                            charset = part.get_content_charset() or "utf-8"
                            body_to_analyze = payload.decode(charset, errors="replace")
                            if ctype == "text/html":
                                break
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    body_to_analyze = payload.decode(errors="replace")
        except Exception:
            body_to_analyze = ""
    # ... (regex + optional LLM body analysis, BEC scoring, cache write) ...
```

> Review focus: `message_from_string(raw)` and `msg.walk()` on a deeply nested `multipart/*` within the 200 KB cap. Is there a recursion/part-count bound? What HTTP status results from an unhandled parser error, and is the endpoint rate-limited? Are decoded payloads ever fetched or executed (they should be data-only)?

---

## Path 4 — Abuse-send auth + mail path: `app/abuse/routes.py` and `app/abuse/send.py`
*What it does:* `_verify_admin` checks admin credentials from the JSON body against a bcrypt hash; `send` gates on that then calls `send_via_mailgun`, which enforces a recipient allowlist (RDAP-resolved contacts or the operator's own address), strips header-breaking chars, and posts to Mailgun. `/send` has no rate-limit decorator.

```python
# routes.py
def _verify_admin(admin_user: str, admin_password: str) -> str | None:
    """Validate admin credentials (from the JSON body) against the bcrypt hash.
    Returns None on success, or a short error string on failure. Never raises 401."""
    user = getenv_clean("FALCONEYE_ABUSE_ADMIN_USER")
    pass_hash = getenv_clean("FALCONEYE_ABUSE_ADMIN_PASS_HASH")
    if not user or not pass_hash:
        return "send not configured on this server"

    user_ok = secrets.compare_digest(admin_user or "", user)
    try:
        pass_ok = bcrypt.checkpw((admin_password or "").encode("utf-8"), pass_hash.encode("utf-8"))
    except Exception:
        pass_ok = False

    # Evaluate both regardless of the username result to avoid short-circuit timing leaks.
    if not (user_ok and pass_ok):
        return "invalid credentials"
    return None


@router.post("/send")                        # <-- no @limiter decorator
async def send(req: SendRequest, request: Request):
    auth_error = _verify_admin(req.admin_user, req.admin_password)
    if auth_error is not None:
        return {"sent": False, "mailgun_message_id": None, "error": auth_error, "rate_limited": False}
    client_ip = get_client_ip(request)
    return await send_mod.send_via_mailgun(req.composed or {}, req.recipient_email or "", client_ip)


# send.py
EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")

async def send_via_mailgun(composed: dict, recipient_email: str, client_ip: str) -> dict:
    """Send a composed report via Mailgun. Never raises."""
    result = {"sent": False, "mailgun_message_id": None, "error": None, "rate_limited": False}

    recipient = (recipient_email or "").strip()
    if not EMAIL_RE.match(recipient) or len(recipient) > 254:
        result["error"] = "Invalid recipient email address."
        return result

    # Recipient allowlist: RDAP-resolved contact OR the operator's own reporter address.
    reporter_self = getenv_clean("FALCONEYE_REPORTER_EMAIL").lower()
    allowed = store.recipient_seen_in_cache(recipient) or (
        bool(reporter_self) and recipient.lower() == reporter_self
    )
    if not allowed:
        result["error"] = ("Recipient was not returned by a recent RDAP lookup; refusing to send. "
                           "Run the abuse contact lookup first.")
        return result

    cfg = _config()
    if not (cfg["api_key"] and cfg["domain"] and cfg["from"]):
        result["error"] = "Mailgun is not configured on this server."
        return result

    composed = composed or {}
    subject = str(composed.get("subject", "") or "")
    body_text = str(composed.get("body_text", "") or "")
    reporter_email = str(composed.get("reporter_email", "") or "")
    category = str(composed.get("category", "other") or "other")
    target = str(composed.get("target", "") or "")
    target_type = str(composed.get("target_type", "") or "")

    # Defense in depth: strip header-breaking characters from single-line fields.
    subject = subject.replace("\r", " ").replace("\n", " ").strip()[:255] or "Abuse Report"
    reporter_email = reporter_email.replace("\r", "").replace("\n", "").strip()

    form = {
        "from": cfg["from"],
        "to": recipient,
        "subject": subject,
        "text": body_text,
        "o:tag": ["abuse-report", f"category:{category}"[:64]],
        "h:X-Report-Abuse": target[:255],           # <-- target not CRLF-stripped here
    }
    if EMAIL_RE.match(reporter_email or ""):
        form["h:Reply-To"] = reporter_email

    endpoint = f"{_mailgun_base(cfg['region'])}/v3/{cfg['domain']}/messages"
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(endpoint, auth=("api", cfg["api_key"]), data=form)
    except Exception as exc:
        result["error"] = f"Mailgun request failed ({type(exc).__name__})."   # never interpolates api_key
        store.record_audit(client_ip, recipient, target, target_type, category, subject, None, False)
        return result
    # ... 200 -> record success + message id; non-200 -> trimmed error body ...
```

Recipient allowlist backing check (`app/abuse/store.py`):

```python
def recipient_seen_in_cache(email: str) -> bool:
    """True if *email* was returned as an abuse contact by some prior RDAP lookup."""
    if not email:
        return False
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT 1 FROM abuse_contact_cache WHERE abuse_email = ? COLLATE NOCASE "
            "AND abuse_email IS NOT NULL AND abuse_email != '' LIMIT 1",
            (email.strip(),),
        ).fetchone()
    finally:
        conn.close()
    return row is not None
```

> Review focus: can the credential check be bypassed (empty hash, type confusion, missing env, timing)? Can `/send` become an open relay (recipient spoofed via the body)? Is the `composed` dict — fully client-controlled — a header-injection vector (`target` → `h:X-Report-Abuse`, `category` → `o:tag` are not CRLF-stripped)? Is the API key or admin password ever logged, cached, or audited? Given `/send` has no rate limit and runs bcrypt per request, what does an unauthenticated flood cost the server?
