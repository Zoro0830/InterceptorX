from mitmproxy import http
import sqlite3
import json
import re
import os
import base64
 
# ─── Filters ────────────────────────────────────────────────────────────────
 
IGNORED_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".css", ".js", ".woff", ".woff2",
    ".ico", ".map", ".ttf", ".eot"
)
 
IGNORED_DOMAINS = (
    "google-analytics.com",
    "googletagmanager.com",
    "gstatic.com",
    "doubleclick.net",
    "facebook.com",
    "twitter.com"
)
 
IGNORED_KEYWORDS = [
    "gen_204", "telemetry", "analytics",
    "suggest", "complete/s", "RotateCookies",
    "waa", "ogads", "heartbeat", "ping"
]
 
ALLOWED_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
 
# ─── Security Header Check ──────────────────────────────────────────────────
 
REQUIRED_SECURITY_HEADERS = [
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security",
]
 
# ─── Helper: Response type ────────────────────────────────────────────────────
 
def is_api_response(response_headers):
    content_type = response_headers.get("content-type", "").lower()
    return "application/json" in content_type
 
def is_html_response(response_headers):
    content_type = response_headers.get("content-type", "").lower()
    return "text/html" in content_type
 
# ─── Luhn Algorithm ──────────────────────────────────────────────────────────
 
def luhn_check(number):
    digits = [int(d) for d in str(number)]
    digits.reverse()
    total = 0
    for i, d in enumerate(digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0
 
# ─── XSS Patterns (request only, strict) ────────────────────────────────────
 
XSS_PATTERNS = [
    r"<script[\s>][^<]*?(alert|document\.cookie|eval|fetch|xhr)",
    r"javascript\s*:\s*(alert|void|eval|fetch)",
    r"on(load|error|click|mouseover)\s*=\s*['\"]?\s*(alert|eval|fetch|document)",
    r"<img[^>]+onerror\s*=",
    r"<svg[^>]+onload\s*=",
    r"%3Cscript%3E",
    r"&#x3C;script",
]
 
# ─── SQLi Patterns (request only, strict) ────────────────────────────────────
 
SQLI_PATTERNS = [
    r"['\"](\s)*(or|and)(\s)+['\"]?\d",
    r"union(\s)+all(\s)+select|union(\s)+select",
    r";\s*(drop|insert|update|delete|create|alter)\s+",
    r"(sleep\s*\(\s*\d+|benchmark\s*\(\s*\d+|waitfor\s+delay\s+['\"])",
    r"(\bor\b|\band\b)\s+\d+\s*=\s*\d+",
    r"['\"](\s)*(--|#|/\*)",
]
 
# ─── IDOR Patterns (API endpoints only) ──────────────────────────────────────
 
IDOR_API_PATTERNS = [
    r"/api/(users?|accounts?|orders?|documents?|files?|profiles?|customers?)/\d+",
    r"/(user|account|order|document|profile|customer)/\d{2,}",
    r"(user_id|account_id|order_id|customer_id|profile_id)=\d+",
]
 
def check_idor(url, request_body):
    combined = f"{url} {request_body or ''}"
    for pattern in IDOR_API_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            return True
    return False
 
# ─── Path Traversal ──────────────────────────────────────────────────────────
 
PATH_TRAVERSAL_PATTERNS = [
    r"\.\.(/|\\|%2f|%5c)",
    r"%252e%252e(%252f|%255c)",
    r"(\.\.%c0%af|\.\.%c1%9c)",
]
 
# ─── Sensitive Data (JSON responses only) ────────────────────────────────────
 
def check_sensitive_data(response_body, response_headers):
    findings = []
    if not is_api_response(response_headers):
        return findings
 
    cc_matches = re.findall(r"\b(\d{16})\b", response_body)
    for match in cc_matches:
        if luhn_check(match):
            findings.append({
                "type": "Sensitive Data Exposure",
                "detail": "Possible real credit card number in API response (passes Luhn check)",
                "severity": "HIGH"
            })
            break
 
    if re.search(r'"(password|passwd|pwd)"\s*:\s*"[^"]{3,}"', response_body, re.IGNORECASE):
        findings.append({
            "type": "Sensitive Data Exposure",
            "detail": "Plaintext password field in API response",
            "severity": "HIGH"
        })
 
    if re.search(r'"(api_key|apikey|secret_key|access_token|private_key)"\s*:\s*"[A-Za-z0-9_\-]{16,}"', response_body, re.IGNORECASE):
        findings.append({
            "type": "Sensitive Data Exposure",
            "detail": "API key or secret exposed in response",
            "severity": "HIGH"
        })
 
    return findings
 
# ─── JWT Detection ──────────────────────────────────────────────────────────
 
def detect_jwt(text):
    jwt_pattern = r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    return re.findall(jwt_pattern, text)
 
def decode_jwt_payload(token):
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload = parts[1]
        payload += "=" * (4 - len(payload) % 4)
        decoded = base64.urlsafe_b64decode(payload).decode("utf-8")
        return json.loads(decoded)
    except Exception:
        return None
 
# ─── Security Headers (HTML pages only) ──────────────────────────────────────
 
def analyze_security_headers(response_headers, url):
    normalized = {h.lower() for h in response_headers}
    content_type = response_headers.get("content-type", "").lower()
    if "text/html" not in content_type:
        return []
    return [h for h in REQUIRED_SECURITY_HEADERS if h not in normalized]
 
# ─── Main Scan ───────────────────────────────────────────────────────────────
 
def scan_for_vulns(url, request_headers, request_body, response_body, response_headers):
    findings = []
    user_input = f"{url} {request_body or ''}"
 
    for pattern in SQLI_PATTERNS:
        if re.search(pattern, user_input, re.IGNORECASE):
            findings.append({"type": "SQL Injection Attempt", "detail": "SQLi pattern in request input", "severity": "HIGH"})
            break
 
    for pattern in XSS_PATTERNS:
        if re.search(pattern, user_input, re.IGNORECASE):
            findings.append({"type": "XSS Attempt", "detail": "XSS payload in request", "severity": "HIGH"})
            break
 
    if check_idor(url, request_body):
        findings.append({"type": "Possible IDOR", "detail": "User-controlled resource ID on API endpoint", "severity": "MEDIUM"})
 
    for pattern in PATH_TRAVERSAL_PATTERNS:
        if re.search(pattern, user_input, re.IGNORECASE):
            findings.append({"type": "Path Traversal Attempt", "detail": "Directory traversal sequence in request", "severity": "HIGH"})
            break
 
    findings.extend(check_sensitive_data(response_body, response_headers))
 
    jwt_locations = detect_jwt(str(request_headers) + (request_body or ""))
    for token in jwt_locations[:1]:
        payload = decode_jwt_payload(token)
        findings.append({"type": "JWT Token Detected", "detail": f"JWT in request. Payload: {json.dumps(payload) if payload else 'undecoded'}", "severity": "INFO"})
 
    if is_api_response(response_headers):
        for token in detect_jwt(response_body)[:1]:
            payload = decode_jwt_payload(token)
            findings.append({"type": "JWT in API Response", "detail": f"JWT exposed in API response", "severity": "MEDIUM"})
 
    return findings
 
 
def get_severity(missing_headers, vuln_findings):
    severities = [f["severity"] for f in vuln_findings]
    if "HIGH" in severities:
        return "HIGH"
    if "MEDIUM" in severities or missing_headers:
        return "MEDIUM"
    if "INFO" in severities:
        return "INFO"
    return "SAFE"
 
# ─── Filters ─────────────────────────────────────────────────────────────────
 
def should_ignore(url):
    lower_url = url.lower()
    for ext in IGNORED_EXTENSIONS:
        if lower_url.endswith(ext):
            return True
    for domain in IGNORED_DOMAINS:
        if domain in lower_url:
            return True
    for keyword in IGNORED_KEYWORDS:
        if keyword.lower() in lower_url:
            return True
    return False
 
def is_interesting_response(flow):
    content_type = flow.response.headers.get("content-type", "").lower()
    if flow.response.status_code == 204:
        return False
    return "text/html" in content_type or "application/json" in content_type
 
# ─── DB Path ─────────────────────────────────────────────────────────────────
 
DB_PATH = r"Z:\burpclone\backend\database\traffic.db"
 
# ─── Main Hook ───────────────────────────────────────────────────────────────
 
def response(flow: http.HTTPFlow):
    method = flow.request.method
    if method not in ALLOWED_METHODS:
        return
 
    url = flow.request.pretty_url
    if should_ignore(url):
        return
 
    if not is_interesting_response(flow):
        return
 
    status_code = flow.response.status_code
    request_headers = dict(flow.request.headers)
    response_headers = dict(flow.response.headers)
    request_body = flow.request.get_text(strict=False) or ""
    response_body = flow.response.get_text(strict=False) or ""
 
    missing_headers = analyze_security_headers(response_headers, url)
    vuln_findings = scan_for_vulns(url, request_headers, request_body, response_body, response_headers)
    severity = get_severity(missing_headers, vuln_findings)
 
    all_findings = [
        {"type": f"Missing Header: {h}", "detail": f"Security header '{h}' not set", "severity": "MEDIUM"}
        for h in missing_headers
    ]
    all_findings.extend(vuln_findings)
 
    severity_icon = {"HIGH": "🔴", "MEDIUM": "🟡", "INFO": "🔵", "SAFE": "🟢"}.get(severity, "⚪")
    print(f"{severity_icon} [{status_code}] {method} {url}")
    for f in all_findings:
        print(f"   ↳ [{f['severity']}] {f['type']}: {f['detail']}")
 
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO traffic_logs
        (method, url, status_code, request_headers, request_body,
         response_headers, response_body, findings, severity)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            method, url, status_code,
            json.dumps(request_headers),
            request_body,
            json.dumps(response_headers),
            response_body,
            json.dumps(all_findings),
            severity
        )
    )
    conn.commit()
    conn.close()