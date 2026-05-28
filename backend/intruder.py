"""
InterceptorX — Intruder / Fuzzer (Sniper mode)

How Sniper works:
  - Take a request with §marked§ injection points
  - For each marked position, substitute each payload one at a time
  - All other positions stay as original
  - Record status code, response length, response time for each

Markers: §value§  — wrap any value you want to fuzz
Example:
  POST /login
  username=§admin§&password=§password§
"""
import re
import time
import json
import requests
import logging
import ssrf
from config import LAB_MODE

logger = logging.getLogger(__name__)

MAX_REQUESTS = 1000
TIMEOUT      = 15

REQUEST_OPTIONS = {
    "timeout":         TIMEOUT,
    "verify":          not LAB_MODE,
    "allow_redirects": False,
}

WORDLISTS = {
    "sqli": [
        "'", '"', "' OR '1'='1", "' OR 1=1--", '" OR "1"="1',
        "admin'--", "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--", "1' AND SLEEP(5)--",
        "' AND 1=1--", "' AND 1=2--",
        "' ORDER BY 1--", "' ORDER BY 2--", "' ORDER BY 3--",
        "1 OR 1=1", "1' OR '1'='1",
    ],
    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "'><script>alert(document.cookie)</script>",
        "<body onload=alert(1)>",
        '"><img src=x onerror=alert(1)>',
        "<iframe src=javascript:alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        "{{7*7}}", "${7*7}", "<%= 7*7 %>",
    ],
    "passwords": [
        "password", "123456", "admin", "password123", "letmein",
        "qwerty", "abc123", "monkey", "dragon", "master",
        "sunshine", "princess", "welcome", "shadow", "superman",
        "michael", "football", "iloveyou", "admin123",
        "root", "toor", "pass", "test", "guest", "login",
    ],
    "dirs": [
        "admin", "administrator", "login", "dashboard", "panel",
        "api", "api/v1", "api/v2", "backup", "config", "db",
        "debug", "dev", "test", "staging", "uploads", "files",
        "images", "static", "assets", "inc", "includes",
        "wp-admin", "wp-login.php", "phpmyadmin",
        ".env", ".git", "robots.txt", "sitemap.xml",
        "swagger", "swagger-ui", "docs", "graphql",
        "health", "status", "metrics", "actuator",
    ],
    "params": [
        "1", "0", "-1", "true", "false", "null", "undefined",
        "' OR 1=1--", "<script>alert(1)</script>",
        "../etc/passwd", "../../etc/passwd",
        "%00", "%0a", "%0d", "{{7*7}}", "${7*7}",
        "999999999", "-999999999",
    ],
}

MARKER_RE = re.compile(r"§([^§]*)§")

_HOP_BY_HOP = {
    "host", "content-length", "transfer-encoding",
    "connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailers", "upgrade",
}


def find_positions(template: str) -> list:
    positions = []
    for m in MARKER_RE.finditer(template):
        positions.append({
            "start":    m.start(),
            "end":      m.end(),
            "original": m.group(1),
        })
    return positions


def apply_payload(template: str, positions: list, target_idx: int, payload: str) -> str:
    result = template
    offset = 0
    for i, pos in enumerate(positions):
        start = pos["start"] + offset
        end   = pos["end"]   + offset
        replacement = payload if i == target_idx else pos["original"]
        result = result[:start] + replacement + result[end:]
        offset += len(replacement) - (end - start)
    return result


def _clean_headers(headers: dict) -> dict:
    return {k: v for k, v in headers.items()
            if k.lower() not in _HOP_BY_HOP}


def _send(method: str, url: str, headers: dict, body: str) -> dict:
    start = time.time()
    try:
        resp = requests.request(
            method=method, url=url,
            headers=_clean_headers(headers),
            data=body or None,
            **REQUEST_OPTIONS,
        )
        elapsed = round((time.time() - start) * 1000)
        return {
            "status":   resp.status_code,
            "length":   len(resp.content),
            "time_ms":  elapsed,
            "body":     resp.text[:1000],
            "headers":  dict(resp.headers),
            "error":    None,
        }
    except Exception as e:
        elapsed = round((time.time() - start) * 1000)
        return {"status": None, "length": 0, "time_ms": elapsed, "body": "", "headers": {}, "error": str(e)}


def run_sniper(method: str, url_template: str, headers_dict: dict,
               body_template: str, payloads: list) -> dict:
    clean_url = MARKER_RE.sub(lambda m: m.group(1), url_template)
    if not ssrf.is_safe(clean_url):
        raise ValueError(f"SSRF blocked: {clean_url}")
    if not payloads:
        raise ValueError("No payloads provided.")

    url_positions  = find_positions(url_template)
    body_positions = find_positions(body_template)

    all_positions = (
        [("url",  i, p) for i, p in enumerate(url_positions)] +
        [("body", i, p) for i, p in enumerate(body_positions)]
    )

    if not all_positions:
        raise ValueError(
            "No injection points found. Wrap values with §markers§ — e.g. username=§admin§"
        )

    baseline_url  = MARKER_RE.sub(lambda m: m.group(1), url_template)
    baseline_body = MARKER_RE.sub(lambda m: m.group(1), body_template)
    baseline      = _send(method, baseline_url, headers_dict, baseline_body)
    baseline["payload"]  = "(baseline)"
    baseline["position"] = "—"

    results = []
    request_count = 0

    for part, local_idx, pos_meta in all_positions:
        pos_label = pos_meta["original"] or f"pos{local_idx}"

        for payload in payloads:
            if request_count >= MAX_REQUESTS:
                return {"baseline": baseline, "results": results,
                        "truncated": True, "total": request_count,
                        "positions": [p["original"] for _, _, p in all_positions]}

            if part == "url":
                mut_url  = apply_payload(url_template,  url_positions,  local_idx, payload)
                mut_body = baseline_body
            else:
                mut_url  = baseline_url
                mut_body = apply_payload(body_template, body_positions, local_idx, payload)

            result = _send(method, mut_url, headers_dict, mut_body)
            result["payload"]  = payload
            result["position"] = pos_label

            # Smart detection
            analysis = analyze_response(
                payload         = payload,
                resp_body       = result["body"] or "",
                resp_headers    = result.get("headers", {}),
                status          = result["status"] or 0,
                baseline_status = baseline["status"] or 0,
                baseline_body   = baseline["body"] or "",
                baseline_length = baseline["length"] or 0,
                resp_length     = result["length"] or 0,
                resp_time       = result["time_ms"] or 0,
                baseline_time   = baseline["time_ms"] or 0,
            )
            result.update(analysis)

            results.append(result)
            request_count += 1

    return {
        "baseline":  baseline,
        "results":   results,
        "truncated": False,
        "total":     request_count,
        "positions": [p["original"] for _, _, p in all_positions],
    }


# ── Smart detection engine ────────────────────────────────────────────────────

# SQL error signatures from major databases
SQL_ERRORS = [
    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql_",
    "mysql_fetch_array()",
    "mysql_num_rows()",
    "supplied argument is not a valid mysql",
    "unclosed quotation mark after the character string",
    # PostgreSQL
    "pg_query()", "pg_exec()", "psql error",
    "postgresql query failed",
    "syntax error at or near",
    # MSSQL
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "unclosed quotation mark",
    "incorrect syntax near",
    "syntax error converting",
    # Oracle
    "ora-00933", "ora-00907", "ora-00911", "ora-00942",
    "ora-01756", "oracle error",
    # SQLite
    "sqlite3::", "sqlite_", "sqliteexception",
    # Generic
    "sql syntax", "sql error", "database error",
    "division by zero", "invalid query",
    "syntax error", "unterminated string",
]

# XSS reflection — these exact strings should NOT appear in a safe response
XSS_REFLECTION_MARKERS = [
    "<script>", "onerror=", "onload=", "onclick=",
    "javascript:", "alert(", "document.cookie",
]

# SSTI evaluation markers — if 49 appears where we sent {{7*7}}, it evaluated
SSTI_EVAL = {
    "{{7*7}}": "49",
    "${7*7}":  "49",
    "{{7*'7'}}": "7777777",
    "<%= 7*7 %>": "49",
    "#{7*7}": "49",
}

# LFI success markers
LFI_MARKERS = [
    "root:x:0:0", "root:*:", "/bin/bash", "/bin/sh",
    "[boot loader]", "[operating systems]",
    "for 16-bit app support", "windows registry editor",
]

# Open redirect — response has Location header with our payload
# (checked separately in _send_smart)

# Command injection markers
CMD_INJECTION_MARKERS = [
    "uid=", "gid=", "groups=",  # id command output
    "root:", "daemon:", "nobody:",  # /etc/passwd
    "volume serial number",  # Windows dir
    "directory of c:\\",
]


def analyze_response(payload: str, resp_body: str, resp_headers: dict,
                     status: int, baseline_status: int,
                     baseline_body: str, baseline_length: int,
                     resp_length: int, resp_time: int,
                     baseline_time: int) -> dict:
    """
    Smart analysis of a response to detect true positives.
    Returns dict with findings list and severity.
    """
    findings  = []
    body_low  = resp_body.lower()
    pay_low   = payload.lower()

    # ── 1. SQL Error Detection ────────────────────────────────────────────
    for sig in SQL_ERRORS:
        if sig in body_low and sig not in baseline_body.lower():
            findings.append({
                "type":     "SQL Error",
                "detail":   f"DB error signature found: '{sig}'",
                "severity": "HIGH",
                "certain":  True,
            })
            break

    # ── 2. XSS Reflection ────────────────────────────────────────────────
    if any(m.lower() in pay_low for m in XSS_REFLECTION_MARKERS):
        # Check if payload is reflected unsanitized
        if payload.lower() in body_low and payload.lower() not in baseline_body.lower():
            findings.append({
                "type":     "XSS Reflection",
                "detail":   "Payload reflected unsanitized in response",
                "severity": "HIGH",
                "certain":  True,
            })
        elif any(m.lower() in body_low and m.lower() not in baseline_body.lower()
                 for m in XSS_REFLECTION_MARKERS):
            findings.append({
                "type":     "Partial XSS Reflection",
                "detail":   "XSS marker reflected — verify manually",
                "severity": "MEDIUM",
                "certain":  False,
            })

    # ── 3. SSTI Evaluation ───────────────────────────────────────────────
    expected = SSTI_EVAL.get(payload)
    if expected and expected in resp_body and expected not in baseline_body:
        findings.append({
            "type":     "SSTI Confirmed",
            "detail":   f"Expression evaluated: {payload} → {expected}",
            "severity": "CRITICAL",
            "certain":  True,
        })

    # ── 4. LFI Detection ─────────────────────────────────────────────────
    for marker in LFI_MARKERS:
        if marker.lower() in body_low and marker.lower() not in baseline_body.lower():
            findings.append({
                "type":     "LFI Confirmed",
                "detail":   f"File content marker found: '{marker}'",
                "severity": "CRITICAL",
                "certain":  True,
            })
            break

    # ── 5. Command Injection ─────────────────────────────────────────────
    for marker in CMD_INJECTION_MARKERS:
        if marker.lower() in body_low and marker.lower() not in baseline_body.lower():
            findings.append({
                "type":     "Command Injection",
                "detail":   f"Command output marker found: '{marker}'",
                "severity": "CRITICAL",
                "certain":  True,
            })
            break

    # ── 6. Open Redirect ─────────────────────────────────────────────────
    location = resp_headers.get("location", "") or resp_headers.get("Location", "")
    if location and payload in location and status in (301, 302, 303, 307, 308):
        findings.append({
            "type":     "Open Redirect",
            "detail":   f"Redirects to payload URL: {location}",
            "severity": "MEDIUM",
            "certain":  True,
        })

    # ── 7. Time-based SQLi (generous threshold) ───────────────────────────
    if resp_time > baseline_time + 4000 and ("sleep" in pay_low or "waitfor" in pay_low or "benchmark" in pay_low):
        findings.append({
            "type":     "Time-based SQLi",
            "detail":   f"Response delayed {resp_time - baseline_time}ms with sleep payload",
            "severity": "HIGH",
            "certain":  False,
        })

    # ── 8. Status diff (meaningful only) ─────────────────────────────────
    diff_status = status != baseline_status
    # Only flag length diff if meaningful (>200 bytes, not just search noise)
    diff_length = abs(resp_length - baseline_length) > 200

    # Severity summary
    severities = [f["severity"] for f in findings]
    if "CRITICAL" in severities: severity = "CRITICAL"
    elif "HIGH"   in severities: severity = "HIGH"
    elif "MEDIUM" in severities: severity = "MEDIUM"
    elif findings:               severity = "INFO"
    else:                        severity = "SAFE"

    return {
        "findings":     findings,
        "severity":     severity,
        "diff_status":  diff_status,
        "diff_length":  diff_length,
        "diff_time":    resp_time > baseline_time + 4000,
        "interesting":  len(findings) > 0,
    }