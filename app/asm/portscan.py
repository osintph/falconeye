"""A conservative, pure-Python asyncio TCP connect scan.

Why pure Python and not nmap/naabu/masscan: nmap's NPSL treats a wrapper that
parses its output as a derivative work and requires an Nmap notice on any site
that scans for users, which conflicts with this project's licence; naabu and
masscan add a root-only binary. A connect scan of about two dozen ports over a
capped host set is well under any rate concern, needs no privilege and no extra
dependency, and has no licence entanglement.

Safety: the caller passes an already validated public IP (resolved through
app.utils.safe_fetch.resolve_and_check). This module re-checks is_private_ip as a
backstop so a private or reserved address is never connected to, even if a caller
forgets. No bytes are sent: a short read after connect captures only a
banner-first service's greeting (SSH, SMTP, FTP), and HTTP/TLS are left to the
probe. No em dashes in this module.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

from app.utils.safe_fetch import is_private_ip

log = logging.getLogger("falconeye.asm.portscan")

# A deliberately small, common-service port list. Conservative on purpose.
PORTS = (21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995, 1433, 3306,
         3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 9999, 27017)

# Services that greet first, so a short read with no write can label the port.
_BANNER_PORTS = {21, 22, 25, 110, 143, 587}


async def _probe_port(ip: str, port: int, timeout: float, sem: asyncio.Semaphore) -> Optional[dict]:
    async with sem:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout)
        except Exception:
            return None
        banner = ""
        try:
            if port in _BANNER_PORTS:
                try:
                    data = await asyncio.wait_for(reader.read(128), timeout=1.0)
                    banner = data.decode("latin-1", "replace").strip()[:120]
                except Exception:
                    banner = ""
        finally:
            try:
                writer.close()
            except Exception:
                pass
        result = {"port": port}
        if banner:
            result["banner"] = banner
        return result


async def scan(ip: str, ports=PORTS, *, timeout: float = 2.5,
               sem: Optional[asyncio.Semaphore] = None) -> list:
    """Return the list of open ports on *ip* (each {port, banner?}), sorted.

    Refuses a private or reserved address outright (returns []). *sem* bounds how
    many connects run at once; the caller shares one across the whole run so the
    whole scan stays within ASM_PORT_CONCURRENCY.
    """
    if not ip or is_private_ip(ip):
        return []
    if sem is None:
        sem = asyncio.Semaphore(50)
    results = await asyncio.gather(*[_probe_port(ip, p, timeout, sem) for p in ports])
    return sorted((r for r in results if r), key=lambda r: r["port"])
