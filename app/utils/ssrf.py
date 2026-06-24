import ipaddress
import socket
from urllib.parse import urlparse

BLOCKED_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

ALLOWED_SCHEMES = {"http", "https"}


def validate_url(url: str) -> tuple[bool, str]:
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Malformed URL"

    if parsed.scheme not in ALLOWED_SCHEMES:
        return False, f"Scheme '{parsed.scheme}' not allowed"

    hostname = parsed.hostname
    if not hostname:
        return False, "No hostname found"

    try:
        raw_ip = ipaddress.ip_address(hostname)
        for blocked in BLOCKED_RANGES:
            if raw_ip in blocked:
                return False, f"IP {hostname} is in a blocked range"
    except ValueError:
        pass

    try:
        resolved = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False, f"Could not resolve hostname: {hostname}"

    for result in resolved:
        addr = result[4][0]
        try:
            ip = ipaddress.ip_address(addr)
            for blocked in BLOCKED_RANGES:
                if ip in blocked:
                    return False, f"Hostname resolves to blocked IP: {addr}"
        except ValueError:
            return False, f"Could not parse resolved address: {addr}"

    return True, ""
