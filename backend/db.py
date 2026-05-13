"""SQLite database helpers."""
import sqlite3
import json
import os
import logging

logger = logging.getLogger(__name__)

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database", "traffic.db")


def get_db():
    """
    Open a SQLite connection.
    timeout=10  — wait up to 10s if DB is locked by concurrent writer
                  (mitmproxy + Flask can write simultaneously)
    check_same_thread=False — Flask may hand connection across threads
    """
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # WAL mode: readers don't block writers and vice versa
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def row_to_dict(row) -> dict:
    def _parse(raw, default):
        try:
            return json.loads(raw) if raw else default
        except Exception:
            return default

    return {
        "id":               row["id"],
        "method":           row["method"],
        "url":              row["url"],
        "status_code":      row["status_code"],
        "request_headers":  _parse(row["request_headers"],  {}),
        "request_body":     row["request_body"]  or "",
        "response_headers": _parse(row["response_headers"], {}),
        "response_body":    row["response_body"] or "",
        "findings":         _parse(row["findings"],         []),
        "severity":         row["severity"] if "severity" in row.keys() else "SAFE",
        "timestamp":        row["timestamp"],
    }