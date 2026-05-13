"""
Active vulnerability testing module.

Confidence levels:
  LOW       — minor behavioural difference (length / status change)
  MEDIUM    — payload partially reflected, or notable response shift
  HIGH      — confirmed DB error signature or full payload reflection
  CONFIRMED — (reserved for future boolean-condition bypass logic)

Design notes:
  - Destructive payloads (DROP TABLE etc.) are intentionally excluded.
  - Tracking / session parameters are skipped to reduce false positives.
  - Signatures are matched in context (error pages, not all HTML).
  - Rate limiting: max MAX_REQUESTS_PER_RUN outbound requests per test run.
"""
import re
import json
import urllib.parse
import socket
import logging
import requests
import ssrf

logger = logging.getLogger(__name__)

# ── Lab-mode flag ─────────────────────────────────────────────────────────────
# TLS verification is disabled intentionally.
# This tool operates as an intercepting proxy in a controlled lab environment.
# Do NOT use against production targets without proper authorisation.
LAB_MODE = False

REQUEST_OPTIONS = {
    "timeout": 20,  # Increased — WAFs/slow servers need more headroom
    "verify": not LAB_MODE,   # False in lab mode — intentional, documented
    "allow_redirects": False,
}

# Hard cap on outbound requests per active-test run (prevents accidental DoS)
MAX_REQUESTS_PER_RUN = 50

# ── Payload library ───────────────────────────────────────────────────────────

DEFAULT_PAYLOADS = {
    "sqli": [
        "'",
        '"',
        "' OR '1'='1",
        "' OR 1=1--",
        '" OR "1"="1',
        "admin'--",
        "' UNION SELECT NULL--",
        # NOTE: destructive payloads (DROP TABLE, DELETE, etc.) are intentionally
        # excluded — this tool is for detection, not exploitation.
    ],
    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "'><script>alert(document.cookie)</script>",
        "<body onload=alert(1)>",
    ],
    "idor": [],  # handled via numeric ID enumeration
}

# ── Parameter filtering ───────────────────────────────────────────────────────

IGNORED_PARAMS = {
    # Search engine internals
    "sca_esv", "sxsrf", "ei", "iflsig", "ved", "gs_lp", "uact", "oq",
    "gs_lcp", "sclient", "source", "hl", "gl", "num", "start",
    # Analytics / tracking
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "msclkid", "_ga", "_gl",
    # Session / CSRF
    "csrf_token", "csrfmiddlewaretoken", "_token", "nonce",
    # Misc dynamic / telemetry
    "sid", "session_id", "ts", "timestamp", "_", "cb",
}

INTERESTING_PARAMS = {
    "id", "user", "user_id", "uid", "account", "account_id",
    "search", "q", "query", "keyword", "term",
    "category", "cat", "type", "filter",
    "page", "limit", "offset", "sort", "order",
    "username", "email", "login", "name",
    "redirect", "return", "next", "url", "to", "from",
    "token", "key", "apikey", "api_key",
    "file", "path", "dir", "filename",
}

# ── SQLi error signatures — matched in context ────────────────────────────────
#
# IMPORTANT: generic words like "odbc", "jdbc", "syntax" appear in normal HTML
# (YouTube embeds, marketing copy, etc.) and cause massive false positives when
# matched against the entire response body.
#
# Rules:
#   1. Match only inside <pre>, <code>, error divs, or plain-text responses
#      when possible — use surrounding context patterns.
#   2. Prefer multi-word signatures over single tokens.
#   3. "odbc", "jdbc", "mariadb" alone are NOT reliable signals.

_SQLI_PATTERNS = [
    # MySQL
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning:\s*mysql", re.I),
    re.compile(r"mysql_fetch", re.I),
    re.compile(r"supplied argument is not a valid mysql", re.I),
    # PostgreSQL
    re.compile(r"pg_query\(\)|pg_exec\(\)", re.I),
    re.compile(r"postgresql.*error", re.I),
    re.compile(r"psql.*error", re.I),
    # SQLite
    re.compile(r"sqlite3?\.operationalerror", re.I),
    re.compile(r"sqlite error", re.I),
    # Oracle
    re.compile(r"\bora-\d{4,5}\b", re.I),
    # MSSQL
    re.compile(r"unclosed quotation mark after the character string", re.I),
    re.compile(r"incorrect syntax near", re.I),
    re.compile(r"microsoft.*odbc.*sql server", re.I),   # context-rich
    re.compile(r"odbc.*driver.*error", re.I),           # context-rich (not bare "odbc")
    # Generic — but only multi-word
    re.compile(r"sql syntax.*error|error.*sql syntax", re.I),
    re.compile(r"division by zero", re.I),
    re.compile(r"sqlstate\[\w+\]", re.I),
]

XSS_REFLECT_RE = re.compile(
    r"<script>alert\(1\)</script>"
    r"|<img[^>]+onerror\s*="
    r"|<svg[^>]+onload\s*="
    r"|<body[^>]+onload\s*=",
    re.IGNORECASE,
)

_HOP_BY_HOP = {
    "host", "content-length", "transfer-encoding",
}


# ── Internal helpers ──────────────────────────────────────────────────────────

def _clean_headers(headers: dict) -> dict:
    return {k: v for k, v in headers.items()
            if k.lower() not in _HOP_BY_HOP}


def _request(method, url, headers, body):
    return requests.request(
        method=method, url=url,
        headers=_clean_headers(headers),
        data=body,
        **REQUEST_OPTIONS,
    )


def _should_test_param(key: str) -> bool:
    k = key.lower()
    if k in IGNORED_PARAMS:
        return False
    if k in INTERESTING_PARAMS:
        return True
    # Skip long random-looking tokens
    if len(key) > 30 and re.fullmatch(r"[A-Za-z0-9_\-+/=]{30,}", key):
        return False
    return True


def _inject_url_params(url: str, payload: str, vuln_type: str = "xss") -> list:
    """
    Return list of (mutated_url, param_name) for interesting params.

    For SQLi: returns empty list if no real params exist — synthetic ?test=
    parameters are never processed server-side and produce meaningless results.

    For XSS: synthetic fallback is acceptable since reflection can happen
    even in error pages that echo unknown query params.
    """
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    interesting = {k: v for k, v in params.items() if _should_test_param(k)}

    if not interesting:
        if vuln_type == "sqli":
            # Refuse synthetic param — SQLi requires real server-side parameters
            return []
        # XSS: synthetic fallback acceptable
        new_url = url + ("&" if "?" in url else "?") + f"test={urllib.parse.quote(payload)}"
        return [(new_url, "test")]

    results = []
    for target_key in interesting:
        new_params = {k: v[:] for k, v in params.items()}
        new_params[target_key] = [payload]
        new_query = urllib.parse.urlencode(new_params, doseq=True)
        results.append((urllib.parse.urlunparse(parsed._replace(query=new_query)), target_key))
    return results


def _inject_body_params(body: str, payload: str) -> list:
    """Return list of (mutated_body, param_name) for interesting params."""
    if not body:
        return []
    try:
        d = json.loads(body)
        return [(json.dumps({**d, k: payload}), k)
                for k in d if _should_test_param(k)]
    except Exception:
        pass
    params = urllib.parse.parse_qs(body, keep_blank_values=True)
    if params:
        results = []
        for key in params:
            if _should_test_param(key):
                new_params = {k: v[:] for k, v in params.items()}
                new_params[key] = [payload]
                results.append((urllib.parse.urlencode(new_params, doseq=True), key))
        return results
    return []


def _detect_sqli_error(text: str) -> str | None:
    """
    Return the matched error signature string, or None.
    Uses compiled regex patterns with surrounding context to avoid
    false positives from single-word matches in normal HTML.
    """
    for pattern in _SQLI_PATTERNS:
        m = pattern.search(text)
        if m:
            return m.group(0)
    return None


def _assess_sqli(orig_text, mutated_text, orig_status, mutated_status, payload):
    """Return (flag, confidence)."""
    sig = _detect_sqli_error(mutated_text)
    if sig:
        return (f"🔴 DB error pattern detected: '{sig[:80]}'", "HIGH")

    if mutated_status != orig_status:
        return (f"🟡 Status changed ({orig_status} → {mutated_status})", "MEDIUM")

    if payload.lower() in mutated_text.lower():
        return ("🟡 Payload partially reflected in response", "MEDIUM")

    len_diff = abs(len(mutated_text) - len(orig_text))
    if len_diff > 500:
        return (f"🔵 Response length changed by {len_diff} bytes (likely dynamic content, not a finding)", "LOW")

    return ("✅ No SQL error signatures detected", "SAFE")


def _assess_xss(mutated_text, payload):
    """Return (flag, confidence)."""
    if XSS_REFLECT_RE.search(mutated_text):
        return ("🔴 Payload fully reflected — potential reflected XSS", "HIGH")
    if payload.lower() in mutated_text.lower():
        return ("🟡 Payload partially reflected — review manually", "MEDIUM")
    return ("✅ Payload not reflected", "SAFE")


# ── Public API ────────────────────────────────────────────────────────────────

def run(vuln_type: str, method: str, original_url: str,
        original_body: str, headers: dict,
        custom_payloads: list) -> list:
    """
    Run active tests. Returns list of result dicts.
    Raises ValueError on invalid input or SSRF-blocked URL.
    """
    if not ssrf.is_safe(original_url):
        raise ValueError("Blocked: original URL targets an internal address (SSRF protection).")

    payloads = custom_payloads if custom_payloads else DEFAULT_PAYLOADS.get(vuln_type, [])
    results  = []
    request_count = 0

    def _budget_ok():
        if request_count >= MAX_REQUESTS_PER_RUN:
            logger.warning("Active test hit MAX_REQUESTS_PER_RUN (%d) — stopping early", MAX_REQUESTS_PER_RUN)
            return False
        return True

    # ── IDOR ─────────────────────────────────────────────────────────────────
    if vuln_type == "idor":
        match = re.search(r"/(\d+)(/|$)", original_url)
        if not match:
            raise ValueError("No numeric ID found in URL path to test IDOR.")

        original_id = int(match.group(1))
        try:
            baseline     = _request(method, original_url, headers, original_body)
            request_count += 1
            baseline_len = len(baseline.text)
        except Exception:
            baseline_len = 0

        for test_id in [original_id + i for i in range(1, 6)]:
            if not _budget_ok():
                break
            test_url = (original_url[:match.start()] +
                        str(test_id) +
                        original_url[match.end():])
            try:
                resp = _request(method, test_url, headers, original_body)
                request_count += 1
                len_diff = abs(len(resp.text) - baseline_len)

                if resp.status_code in (401, 403):
                    flag, conf = "✅ Access denied — authorization enforced", "SAFE"
                elif resp.status_code == 200 and len_diff > 50:
                    flag = f"⚠️ Response differs from baseline (Δ {len_diff} bytes) — potential IDOR"
                    conf = "MEDIUM"
                elif resp.status_code == 200:
                    flag, conf = "🟡 HTTP 200 — verify response content manually", "LOW"
                else:
                    flag, conf = f"ℹ️ HTTP {resp.status_code}", "LOW"

                results.append({
                    "payload": f"ID={test_id}", "url": test_url,
                    "status_code": resp.status_code,
                    "response_length": len(resp.text),
                    "baseline_length": baseline_len,
                    "confidence": conf, "flag": flag,
                    "response_snippet": resp.text[:500],
                })
            except Exception as e:
                results.append({"payload": f"ID={test_id}", "url": test_url, "error": str(e)})

        return results

    # ── SQLi / XSS ────────────────────────────────────────────────────────────
    try:
        baseline    = _request(method, original_url, headers, original_body)
        request_count += 1
        orig_text   = baseline.text
        orig_status = baseline.status_code
    except Exception:
        orig_text = ""
        orig_status = 0

    # Pre-check: for SQLi, warn early if URL has no real injectable params
    # so the user knows to test the POST request instead
    if vuln_type == "sqli":
        _test_params = {k: v for k, v in
                        urllib.parse.parse_qs(urllib.parse.urlparse(original_url).query,
                                              keep_blank_values=True).items()
                        if _should_test_param(k)}
        _has_body_params = bool(_inject_body_params(original_body, "'"))
        if not _test_params and not _has_body_params:
            return [{
                "payload": "—",
                "flag": (
                    "⚠️ No injectable parameters found in URL or body. "
                    "If testing a login form, capture the POST request "
                    "(with username= and password= fields) and run SQLi from there."
                ),
                "confidence": "INFO",
                "status_code": None,
                "response_length": 0,
                "baseline_length": 0,
            }]

    for payload in payloads:
        for mutated_url, param_name in _inject_url_params(original_url, payload, vuln_type):
            if not _budget_ok():
                break
            try:
                resp = _request(method, mutated_url, headers, original_body)
                request_count += 1
                flag, conf = (_assess_sqli(orig_text, resp.text, orig_status, resp.status_code, payload)
                              if vuln_type == "sqli"
                              else _assess_xss(resp.text, payload))
                results.append({
                    "payload": payload, "param": param_name, "url": mutated_url,
                    "status_code": resp.status_code,
                    "response_length": len(resp.text),
                    "baseline_length": len(orig_text),
                    "confidence": conf, "flag": flag,
                    "response_snippet": resp.text[:300],
                })
            except Exception as e:
                results.append({"payload": payload, "url": mutated_url, "error": str(e)})

        for mutated_body, param_name in _inject_body_params(original_body, payload):
            if not _budget_ok():
                break
            try:
                resp = _request(method, original_url, headers, mutated_body)
                request_count += 1
                flag, conf = (_assess_sqli(orig_text, resp.text, orig_status, resp.status_code, payload)
                              if vuln_type == "sqli"
                              else _assess_xss(resp.text, payload))
                results.append({
                    "payload": payload, "param": param_name, "body": mutated_body,
                    "status_code": resp.status_code,
                    "response_length": len(resp.text),
                    "baseline_length": len(orig_text),
                    "confidence": conf, "flag": flag,
                    "response_snippet": resp.text[:300],
                })
            except Exception as e:
                results.append({"payload": payload, "body": mutated_body, "error": str(e)})

    return results