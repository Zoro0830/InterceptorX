"""
InterceptorX — Passive JS Endpoint Extractor

Runs inside mitmproxy response hook.
Scans every JS response for:
  - API endpoints (/api/, /v1/, /v2/, etc.)
  - fetch() and axios() calls
  - GraphQL endpoints
  - WebSocket URLs (ws://, wss://)
  - Internal admin paths
  - Next.js / React route manifests
  - XMLHttpRequest URLs
  - Source map references

Stores discovered endpoints in SQLite for the Flask UI to display.
Pure passive — no outbound requests made.
"""
import re
import json
import os
import sqlite3
import logging
import urllib.parse
from datetime import datetime

logger = logging.getLogger(__name__)

DB_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "backend", "database", "traffic.db"
)

# ── Extraction patterns ───────────────────────────────────────────────────────

# API path patterns — quoted strings that look like API routes
_API_PATH_RE = re.compile(
    r'["\']'                          # opening quote
    r'(/(?:api|v\d+|graphql|rest|'
    r'internal|admin|auth|oauth|'
    r'user|account|profile|search|'
    r'upload|download|export|import|'
    r'webhook|callback|redirect|'
    r'public|private|secure|debug|'
    r'config|settings|health|status|'
    r'metrics|actuator|manage|'
    r'ws|socket)[^"\'\\s]{0,200})'   # path content
    r'["\']',
    re.IGNORECASE
)

# fetch() calls
_FETCH_RE = re.compile(
    r'fetch\s*\(\s*["\`]([^"\'`\s]{4,200})["\`]',
    re.IGNORECASE
)

# axios calls
_AXIOS_RE = re.compile(
    r'axios\s*\.\s*(?:get|post|put|delete|patch|request)\s*\(\s*["\`]([^"\'`\s]{4,200})["\`]',
    re.IGNORECASE
)

# XMLHttpRequest
_XHR_RE = re.compile(
    r'\.open\s*\(\s*["\'](?:GET|POST|PUT|DELETE|PATCH)["\']'
    r'\s*,\s*["\`]([^"\'`\s]{4,200})["\`]',
    re.IGNORECASE
)

# WebSocket
_WS_RE = re.compile(
    r'new\s+WebSocket\s*\(\s*["\`](wss?://[^"\'`\s]{4,200})["\`]',
    re.IGNORECASE
)

# GraphQL
_GQL_RE = re.compile(
    r'["\'](/graphql[^"\'\\s]*)["\']|'
    r'uri\s*:\s*["\']([^"\']{4,100})["\'].*?graphql|'
    r'graphql.*?uri\s*:\s*["\']([^"\']{4,100})["\']',
    re.IGNORECASE
)

# Next.js route manifest
_NEXTJS_RE = re.compile(
    r'"page"\s*:\s*"(/[^"]{1,200})"',
    re.IGNORECASE
)

# Relative paths in JS that look like endpoints
_RELATIVE_RE = re.compile(
    r'["\']'
    r'(/[a-zA-Z0-9_\-/]{3,100}'
    r'(?:\.[a-zA-Z0-9]+)?'
    r'(?:\?[^"\']{0,100})?)'
    r'["\']'
)

# URL-like strings with full domain
_FULL_URL_RE = re.compile(
    r'["\`](https?://[^\s"\'`<>{}\[\]\\]{10,300})["\`]'
)


# ── Endpoint classifier ───────────────────────────────────────────────────────

def _classify(url: str) -> str:
    u = url.lower()
    if u.startswith("ws://") or u.startswith("wss://"):
        return "websocket"
    if "graphql" in u:
        return "graphql"
    if any(x in u for x in ["/admin", "/manage", "/internal", "/debug", "/actuator", "/console"]):
        return "admin"
    if any(x in u for x in ["/api/", "/v1/", "/v2/", "/v3/", "/rest/"]):
        return "api"
    if any(x in u for x in ["/auth/", "/oauth/", "/login", "/logout", "/token", "/session"]):
        return "auth"
    if any(x in u for x in ["/upload", "/download", "/export", "/import", "/file"]):
        return "file"
    if any(x in u for x in ["/webhook", "/callback", "/redirect", "/notify"]):
        return "webhook"
    return "path"


def _normalize(url: str, base_url: str = "") -> str | None:
    """Normalize a discovered URL. Returns None if junk."""
    url = url.strip()
    if not url or len(url) < 2:
        return None

    # Skip obvious non-endpoints
    skip_patterns = [
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
        ".woff2", ".ttf", ".eot", ".css", ".map",
        "localhost", "127.0.0.1", "example.com", "schema.org",
        "w3.org", "mozilla.org", "//", "data:", "blob:",
        "${", "#{", "{{", "%{", "__",
    ]
    url_low = url.lower()
    if any(p in url_low for p in skip_patterns):
        return None

    # Resolve relative URLs against base
    if url.startswith("/") and base_url:
        try:
            parsed = urllib.parse.urlparse(base_url)
            url = f"{parsed.scheme}://{parsed.netloc}{url}"
        except Exception:
            pass

    # Must start with / or http
    if not (url.startswith("/") or url.startswith("http") or
            url.startswith("ws://") or url.startswith("wss://")):
        return None

    # Remove query string noise for dedup (keep path)
    try:
        parsed = urllib.parse.urlparse(url)
        clean = parsed.path
        if parsed.query:
            clean += "?" + parsed.query
        if parsed.netloc:
            clean = f"{parsed.scheme}://{parsed.netloc}{clean}"
        return clean.rstrip("/") or "/"
    except Exception:
        return url


def extract_endpoints(js_content: str, source_url: str = "") -> list[dict]:
    """
    Extract all endpoints from JS content.
    Returns list of {url, type, source_url, raw_match} dicts.
    """
    found = {}  # url → dict, for dedup

    def _add(url, etype, raw=""):
        norm = _normalize(url, source_url)
        if norm and norm not in found:
            found[norm] = {
                "url":        norm,
                "type":       etype or _classify(norm),
                "source_url": source_url,
                "raw_match":  raw[:200],
            }

    # fetch()
    for m in _FETCH_RE.finditer(js_content):
        _add(m.group(1), "fetch", m.group(0))

    # axios()
    for m in _AXIOS_RE.finditer(js_content):
        _add(m.group(1), "api", m.group(0))

    # XHR
    for m in _XHR_RE.finditer(js_content):
        _add(m.group(1), "xhr", m.group(0))

    # WebSocket
    for m in _WS_RE.finditer(js_content):
        _add(m.group(1), "websocket", m.group(0))

    # GraphQL
    for m in _GQL_RE.finditer(js_content):
        for g in m.groups():
            if g:
                _add(g, "graphql", m.group(0))

    # Next.js routes
    for m in _NEXTJS_RE.finditer(js_content):
        _add(m.group(1), "nextjs_route", m.group(0))

    # API path patterns
    for m in _API_PATH_RE.finditer(js_content):
        _add(m.group(1), _classify(m.group(1)), m.group(0))

    # Full URLs
    for m in _FULL_URL_RE.finditer(js_content):
        url = m.group(1)
        if any(x in url.lower() for x in ["/api", "/v1", "/v2", "graphql",
                                            "/auth", "/admin", "/webhook"]):
            _add(url, _classify(url), m.group(0))

    return list(found.values())


# ── Database helpers ──────────────────────────────────────────────────────────

def _get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def ensure_table():
    """Create endpoints table if it doesn't exist."""
    try:
        conn = _get_db()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS js_endpoints (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                url         TEXT NOT NULL,
                type        TEXT DEFAULT 'path',
                source_url  TEXT,
                raw_match   TEXT,
                first_seen  DATETIME DEFAULT CURRENT_TIMESTAMP,
                times_seen  INTEGER DEFAULT 1,
                UNIQUE(url)
            )
        """)
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning("Could not create js_endpoints table: %s", e)


def save_endpoints(endpoints: list[dict]) -> int:
    """Save endpoints to DB. Returns count of new endpoints added."""
    if not endpoints:
        return 0
    added = 0
    try:
        conn = _get_db()
        for ep in endpoints:
            try:
                conn.execute("""
                    INSERT INTO js_endpoints (url, type, source_url, raw_match)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(url) DO UPDATE SET
                        times_seen = times_seen + 1,
                        source_url = excluded.source_url
                """, (ep["url"], ep["type"], ep["source_url"], ep["raw_match"]))
                if conn.execute("SELECT changes()").fetchone()[0] > 0:
                    added += 1
            except Exception:
                pass
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning("Could not save endpoints: %s", e)
    return added


def get_all_endpoints(type_filter: str = None, search: str = None) -> list[dict]:
    try:
        conn = _get_db()
        query = "SELECT * FROM js_endpoints"
        params = []
        conditions = []
        if type_filter and type_filter != "all":
            conditions.append("type = ?")
            params.append(type_filter)
        if search:
            conditions.append("url LIKE ?")
            params.append(f"%{search}%")
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY first_seen DESC"
        rows = conn.execute(query, params).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.warning("Could not get endpoints: %s", e)
        return []


def clear_endpoints():
    try:
        conn = _get_db()
        conn.execute("DELETE FROM js_endpoints")
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning("Could not clear endpoints: %s", e)


# Initialize table on import
ensure_table()