"""
Session-aware HTTP request repeater with SSRF protection.

Key upgrades over basic repeater:
  - Uses requests.Session() — cookies persist across requests automatically
  - Named sessions — isolate state per target (e.g. "login", "admin", "user2")
  - CSRF token auto-extraction — scans response for common CSRF patterns
    and stores them so the next request can use them
  - Redirect following is optional (default off — bug bounty needs to see 302s)
  - Raw HTTP request parsing — accepts raw HTTP text as well as JSON params

Lab mode:
  TLS verification is disabled intentionally (LAB_MODE = True).
  This tool operates as a proxy in a controlled lab environment.
  Set LAB_MODE = False before using against production targets.
"""
import re
import logging
import requests
import ssrf
import session_store

logger = logging.getLogger(__name__)

LAB_MODE = False  # Set False for production targets (enables TLS verification)

_HOP_BY_HOP = {
    "host", "content-length", "transfer-encoding",
    "connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailers", "upgrade",
}

# Common CSRF token field names found in forms and JSON responses
_CSRF_PATTERNS = [
    re.compile(r'name=["\'](_csrf|csrf_token|csrfmiddlewaretoken|authenticity_token|__RequestVerificationToken)["\'][^>]*value=["\']([^"\']+)["\']', re.I),
    re.compile(r'value=["\']([^"\']{20,})["\'][^>]*name=["\'](_csrf|csrf_token|csrfmiddlewaretoken)["\']', re.I),
    re.compile(r'"(csrf_?token|_csrf|xsrf_?token)"\s*:\s*"([^"]{8,})"', re.I),
    re.compile(r'<meta[^>]+name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\']', re.I),
]


def _clean_headers(headers: dict) -> dict:
    return {k: v for k, v in headers.items()
            if k.lower() not in _HOP_BY_HOP}


def _extract_csrf(html: str) -> str | None:
    """Try to find a CSRF token in an HTML or JSON response."""
    for pattern in _CSRF_PATTERNS:
        m = pattern.search(html)
        if m:
            # Last group is always the token value
            token = m.group(m.lastindex)
            logger.info("CSRF token extracted: %s…", token[:12])
            return token
    return None


def parse_raw_http(raw: str, base_url: str = "") -> dict:
    """
    Parse a raw HTTP request string into components.

    Accepts format:
        POST /login HTTP/1.1
        Host: example.com
        Content-Type: application/x-www-form-urlencoded

        username=admin&password=test

    Returns dict with: method, url, headers, body
    """
    lines = raw.replace("\r\n", "\n").split("\n")
    if not lines:
        raise ValueError("Empty request")

    # First line: METHOD /path HTTP/1.x
    parts = lines[0].strip().split()
    if len(parts) < 2:
        raise ValueError(f"Invalid request line: {lines[0]!r}")

    method = parts[0].upper()
    path   = parts[1]

    headers = {}
    host    = ""
    i = 1
    while i < len(lines) and lines[i].strip():
        if ":" in lines[i]:
            k, _, v = lines[i].partition(":")
            headers[k.strip()] = v.strip()
            if k.strip().lower() == "host":
                host = v.strip()
        i += 1

    # Body is everything after the blank line
    body = "\n".join(lines[i+1:]).strip()

    # Build full URL
    if path.startswith("http"):
        url = path
    elif host:
        scheme = "https" if "443" in host or base_url.startswith("https") else "http"
        url = f"{scheme}://{host}{path}"
    elif base_url:
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(base_url)
        url = urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))
    else:
        url = path

    return {"method": method, "url": url, "headers": headers, "body": body}


def send(method: str, url: str, headers: dict, body: str,
         session_name: str = "default",
         follow_redirects: bool = False,
         update_csrf: bool = True) -> dict:
    """
    Replay a request using a persistent session.

    Args:
        session_name:     Which named session to use (cookies persist per session)
        follow_redirects: Follow 301/302 (default False — bug bounty needs to see them)
        update_csrf:      Auto-extract and store CSRF token from response

    Returns dict with:
        status_code, response_headers, response_body,
        session_cookies, csrf_token (if found)

    Raises ValueError on SSRF-blocked URLs or invalid inputs.
    """
    if not isinstance(headers, dict):
        raise ValueError("headers must be a JSON object, not a string or array.")
    if not ssrf.is_safe(url):
        raise ValueError(f"Blocked: {url} targets a private/internal address (SSRF protection).")

    sess    = session_store.get(session_name)
    cleaned = _clean_headers(headers)

    # Merge session cookies with any explicit Cookie header
    # (explicit header wins for the same key)
    try:
        resp = sess.request(
            method=method,
            url=url,
            headers=cleaned,
            data=body if body else None,
            timeout=20,
            verify=not LAB_MODE,
            allow_redirects=follow_redirects,
        )
    except requests.exceptions.SSLError as e:
        raise ValueError(f"TLS error (LAB_MODE={LAB_MODE}): {e}")
    except requests.exceptions.ConnectionError as e:
        raise ValueError(f"Connection error: {e}")
    except requests.exceptions.Timeout:
        raise ValueError("Request timed out (20s). Target may be rate-limiting.")

    # Auto-extract CSRF token for next request
    csrf_token = None
    if update_csrf:
        csrf_token = _extract_csrf(resp.text)

    # Current session cookie state
    session_cookies = dict(sess.cookies)

    result = {
        "status_code":      resp.status_code,
        "response_headers": dict(resp.headers),
        "response_body":    resp.text[:50000],
        "session_name":     session_name,
        "session_cookies":  session_cookies,
        "redirect_history": [
            {"url": r.url, "status": r.status_code}
            for r in resp.history
        ],
    }
    if csrf_token:
        result["csrf_token"] = csrf_token
        result["csrf_note"]  = "CSRF token extracted — available for next request"

    return result


def send_raw(raw_http: str, base_url: str = "",
             session_name: str = "default",
             follow_redirects: bool = False) -> dict:
    """
    Parse and send a raw HTTP request string.
    Useful for the raw HTTP editor in the UI.
    """
    parsed = parse_raw_http(raw_http, base_url)
    return send(
        method           = parsed["method"],
        url              = parsed["url"],
        headers          = parsed["headers"],
        body             = parsed["body"],
        session_name     = session_name,
        follow_redirects = follow_redirects,
    )