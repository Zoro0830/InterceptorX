"""
SSRF protection — blocks replays to internal/private addresses.

Defends against:
  - Literal private IPs (127.x, 10.x, 192.168.x, etc.)
  - DNS rebinding: resolves hostnames and checks all returned IPs
  - Localhost aliases and link-local ranges
"""
import ipaddress
import socket
import urllib.parse
import logging

logger = logging.getLogger(__name__)

_BLOCKED_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / AWS metadata
    ipaddress.ip_network("100.64.0.0/10"),    # CGNAT
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
]

_BLOCKED_HOSTNAMES = {
    "localhost", "ip6-localhost", "ip6-loopback",
    "broadcasthost", "0.0.0.0", "::1",
}


def _ip_is_internal(ip_str: str) -> bool:
    """Return True if the IP address falls in any blocked range."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in r for r in _BLOCKED_RANGES)
    except ValueError:
        return True  # unparseable — block it


def is_safe(url: str) -> bool:
    """
    Return True only if the URL is safe to replay.

    Performs DNS resolution to defend against DNS rebinding attacks —
    a hostname that resolves to an internal IP is blocked even if the
    hostname itself looks public.
    """
    try:
        parsed = urllib.parse.urlparse(url)

        if parsed.scheme not in ("http", "https"):
            return False

        hostname = parsed.hostname
        if not hostname:
            return False

        # Block known localhost aliases before DNS lookup
        if hostname.lower() in _BLOCKED_HOSTNAMES:
            return False

        # If it's already a literal IP, check directly
        try:
            addr = ipaddress.ip_address(hostname)
            if _ip_is_internal(str(addr)):
                logger.warning("SSRF blocked literal IP: %s", hostname)
                return False
            return True
        except ValueError:
            pass  # hostname is a domain — proceed to DNS resolution

        # ── DNS resolution check (anti-rebinding) ────────────────────────────
        try:
            results = socket.getaddrinfo(hostname, None)
        except socket.gaierror:
            # Cannot resolve — block to be safe
            logger.warning("SSRF blocked unresolvable hostname: %s", hostname)
            return False

        for result in results:
            resolved_ip = result[4][0]
            if _ip_is_internal(resolved_ip):
                logger.warning(
                    "SSRF blocked %s — resolved to internal IP %s",
                    hostname, resolved_ip
                )
                return False

        return True

    except Exception:
        return False  # block anything that causes unexpected errors