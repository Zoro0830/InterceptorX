"""
Session store — persists named requests.Session objects across replays.

Why this matters for bug bounty:
  - Cookies set by login responses are preserved automatically
  - CSRF tokens extracted from responses are available for next request
  - Auth headers persist without manual copy-paste
  - Multiple targets can have isolated sessions

Usage:
  session_store.get("my-target")   → returns or creates a Session
  session_store.reset("my-target") → clears cookies/state for that session
  session_store.list_sessions()    → all active session names
"""
import threading
import requests
import logging
from urllib.parse import urlparse
from config import LAB_MODE

logger = logging.getLogger(__name__)

_lock     = threading.Lock()
_sessions: dict[str, requests.Session] = {}


def get(name: str = "default") -> requests.Session:
    """Return existing session or create a new one."""
    with _lock:
        if name not in _sessions:
            s = requests.Session()
            s.verify = not LAB_MODE   # Lab mode — disabled intentionally
            _sessions[name] = s
            logger.info("Created new session: %s", name)
        return _sessions[name]


def reset(name: str = "default") -> None:
    """Clear all cookies and state for a named session."""
    with _lock:
        if name in _sessions:
            _sessions[name].cookies.clear()
            _sessions[name].headers.clear()
            logger.info("Reset session: %s", name)


def delete(name: str) -> bool:
    """Remove a session entirely."""
    with _lock:
        if name in _sessions:
            del _sessions[name]
            logger.info("Deleted session: %s", name)
            return True
        return False


def list_sessions() -> list[dict]:
    """Return info about all active sessions."""
    with _lock:
        result = []
        for name, sess in _sessions.items():
            cookies = [
                {"name": c.name, "domain": c.domain, "path": c.path}
                for c in sess.cookies
            ]
            result.append({
                "name":         name,
                "cookie_count": len(cookies),
                "cookies":      cookies,
            })
        return result


def get_cookies(name: str = "default") -> dict:
    """Return cookies for a session as a plain dict."""
    with _lock:
        if name not in _sessions:
            return {}
        return dict(_sessions[name].cookies)


def inject_cookies(name: str, cookies: dict) -> None:
    """Manually inject cookies into a named session."""
    sess = get(name)
    for k, v in cookies.items():
        sess.cookies.set(k, v)
    logger.info("Injected %d cookie(s) into session '%s'", len(cookies), name)