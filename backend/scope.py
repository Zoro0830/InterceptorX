"""
Scope management — defines which targets are in-scope for active testing.

Why this is critical for bug bounty:
  - Bug bounty programs define strict scope. Testing out-of-scope assets
    can get you banned or cause legal problems.
  - CDN/analytics domains must be excluded automatically.
  - Wildcard support: *.example.com covers all subdomains.

Scope is persisted to scope.json next to this file so it survives restarts.
"""
import json
import os
import fnmatch
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_SCOPE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scope.json")

# In-memory scope state
_state: dict = {
    "enabled": False,      # When False, everything passes (passive mode)
    "allowed": [],         # List of patterns e.g. "*.example.com", "api.target.com"
    "blocked": [],         # Explicit block list (always blocked regardless of allowed)
}

# Always-blocked regardless of user scope — CDN, analytics, third-party
_ALWAYS_BLOCKED = {
    "google-analytics.com", "googletagmanager.com", "doubleclick.net",
    "gstatic.com", "googleadservices.com", "googlesyndication.com",
    "facebook.com", "facebook.net", "twitter.com", "instagram.com",
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com",
    "ajax.googleapis.com", "fonts.googleapis.com", "fonts.gstatic.com",
    "youtube.com", "ytimg.com",
}


def _load() -> None:
    global _state
    if os.path.exists(_SCOPE_FILE):
        try:
            with open(_SCOPE_FILE) as f:
                _state = json.load(f)
            logger.info("Scope loaded: %d allowed, %d blocked patterns",
                        len(_state.get("allowed", [])),
                        len(_state.get("blocked", [])))
        except Exception as e:
            logger.warning("Could not load scope file: %s", e)


def _save() -> None:
    try:
        with open(_SCOPE_FILE, "w") as f:
            json.dump(_state, f, indent=2)
    except Exception as e:
        logger.warning("Could not save scope file: %s", e)


def _hostname(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def _matches_any(host: str, patterns: list) -> bool:
    """Return True if host matches any pattern (supports * wildcards)."""
    for pattern in patterns:
        if fnmatch.fnmatch(host, pattern):
            return True
        # Also match subdomains: pattern "example.com" matches "sub.example.com"
        if host.endswith("." + pattern):
            return True
    return False


def _is_always_blocked(host: str) -> bool:
    if host in _ALWAYS_BLOCKED:
        return True
    for blocked in _ALWAYS_BLOCKED:
        if host.endswith("." + blocked):
            return True
    return False


# Load on import
_load()


# ── Public API ────────────────────────────────────────────────────────────────

def is_in_scope(url: str) -> tuple[bool, str]:
    """
    Check if a URL is in scope for active testing.
    Returns (allowed: bool, reason: str).
    """
    host = _hostname(url)
    if not host:
        return False, "Cannot parse hostname"

    # Always-blocked CDN/analytics — regardless of user scope
    if _is_always_blocked(host):
        return False, f"{host} is a CDN/analytics domain — always excluded"

    # Explicit user block list
    if _matches_any(host, _state.get("blocked", [])):
        return False, f"{host} is explicitly blocked in scope"

    # If scope enforcement is off — allow everything not always-blocked
    if not _state.get("enabled", False):
        return True, "Scope enforcement disabled — all targets allowed"

    # Check allowed list
    if _matches_any(host, _state.get("allowed", [])):
        return True, f"{host} matches allowed scope"

    return False, f"{host} is not in scope — add it via Scope Manager"


def get_state() -> dict:
    return {
        "enabled": _state.get("enabled", False),
        "allowed": _state.get("allowed", []),
        "blocked": _state.get("blocked", []),
    }


def set_enabled(enabled: bool) -> None:
    _state["enabled"] = enabled
    _save()
    logger.info("Scope enforcement: %s", "ON" if enabled else "OFF")


def add_allowed(pattern: str) -> None:
    pattern = pattern.strip().lower()
    if pattern and pattern not in _state.setdefault("allowed", []):
        _state["allowed"].append(pattern)
        _save()
        logger.info("Scope: added allowed pattern '%s'", pattern)


def remove_allowed(pattern: str) -> None:
    pattern = pattern.strip().lower()
    _state.setdefault("allowed", [])
    if pattern in _state["allowed"]:
        _state["allowed"].remove(pattern)
        _save()


def add_blocked(pattern: str) -> None:
    pattern = pattern.strip().lower()
    if pattern and pattern not in _state.setdefault("blocked", []):
        _state["blocked"].append(pattern)
        _save()
        logger.info("Scope: added blocked pattern '%s'", pattern)


def remove_blocked(pattern: str) -> None:
    _state.setdefault("blocked", [])
    if pattern in _state["blocked"]:
        _state["blocked"].remove(pattern)
        _save()


def clear_all() -> None:
    _state["allowed"] = []
    _state["blocked"] = []
    _state["enabled"] = False
    _save()