"""
InterceptorX — Wordlist store
Manages built-in and user-uploaded wordlists.
Wordlists stored in backend/wordlists/ directory.
"""
import os
import json
import logging

logger = logging.getLogger(__name__)

_WORDLIST_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wordlists")
_USER_DIR     = os.path.join(_WORDLIST_DIR, "user")

# Built-in wordlist metadata
BUILTIN_META = {
    "sqli":          {"label": "SQL Injection",       "file": "sqli.txt"},
    "xss":           {"label": "XSS",                 "file": "xss.txt"},
    "lfi":           {"label": "LFI / Path Traversal","file": "lfi.txt"},
    "ssti":          {"label": "SSTI",                "file": "ssti.txt"},
    "open_redirect": {"label": "Open Redirect",       "file": "open_redirect.txt"},
    "passwords":     {"label": "Common Passwords",    "file": "passwords.txt"},
    "dirs":          {"label": "Directory Fuzzing",   "file": "dirs.txt"},
    "params":        {"label": "Parameter Names",     "file": "params.txt"},
}


def _ensure_dirs():
    os.makedirs(_WORDLIST_DIR, exist_ok=True)
    os.makedirs(_USER_DIR, exist_ok=True)


def _read_file(path: str) -> list:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [l.rstrip("\n") for l in f if l.strip()]
    except Exception as e:
        logger.warning("Could not read wordlist %s: %s", path, e)
        return []


def get_builtin(name: str) -> list:
    meta = BUILTIN_META.get(name)
    if not meta:
        return []
    path = os.path.join(_WORDLIST_DIR, meta["file"])
    return _read_file(path)


def list_all() -> list:
    """Return metadata for all wordlists (built-in + user)."""
    _ensure_dirs()
    result = []

    # Built-in
    for key, meta in BUILTIN_META.items():
        path  = os.path.join(_WORDLIST_DIR, meta["file"])
        lines = _read_file(path)
        result.append({
            "id":      key,
            "label":   meta["label"],
            "type":    "builtin",
            "count":   len(lines),
        })

    # User uploaded
    for fname in sorted(os.listdir(_USER_DIR)):
        if not fname.endswith(".txt"):
            continue
        path  = os.path.join(_USER_DIR, fname)
        lines = _read_file(path)
        name  = fname[:-4]
        result.append({
            "id":    "user_" + name,
            "label": name + " (custom)",
            "type":  "user",
            "count": len(lines),
            "file":  fname,
        })

    return result


def get_payloads(wordlist_id: str) -> list:
    """Get payloads for any wordlist by ID."""
    _ensure_dirs()
    if wordlist_id.startswith("user_"):
        fname = wordlist_id[5:] + ".txt"
        path  = os.path.join(_USER_DIR, fname)
        return _read_file(path)
    return get_builtin(wordlist_id)


def save_user_wordlist(name: str, content: str) -> dict:
    """Save a user-uploaded wordlist. Returns metadata."""
    _ensure_dirs()
    # Sanitize name
    safe_name = "".join(c for c in name if c.isalnum() or c in "-_").strip()
    if not safe_name:
        safe_name = "custom"
    fname = safe_name + ".txt"
    path  = os.path.join(_USER_DIR, fname)
    lines = [l.strip() for l in content.splitlines() if l.strip()]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    logger.info("Saved user wordlist: %s (%d payloads)", fname, len(lines))
    return {"id": "user_" + safe_name, "label": safe_name + " (custom)",
            "type": "user", "count": len(lines), "file": fname}


def delete_user_wordlist(name: str) -> bool:
    """Delete a user wordlist by name (without .txt)."""
    fname = name + ".txt"
    path  = os.path.join(_USER_DIR, fname)
    if os.path.exists(path):
        os.remove(path)
        return True
    return False