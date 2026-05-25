"""
InterceptorX — Shared intercept state between mitmproxy and Flask.

How it works:
  - mitmproxy addon checks _intercept_enabled before pausing
  - Paused flows are stored in _queue dict keyed by flow_id
  - Flask reads _queue to show pending requests in the UI
  - Flask writes decisions (forward/drop/edit) back to _queue
  - mitmproxy addon polls its flow's decision and acts on it

This module is imported by BOTH interceptor.py and app.py.
They share the same process memory when run together.

NOTE: This only works when Flask and mitmproxy run in the same process
OR when using a file/socket based IPC. For now we use a shared file
approach so both processes can communicate reliably.
"""
import json
import os
import threading
import time

_STORE_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "intercept_state.json"
)

_lock = threading.Lock()


def _read() -> dict:
    try:
        with open(_STORE_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {"enabled": False, "queue": {}}


def _write(state: dict) -> None:
    try:
        with open(_STORE_FILE, "w") as f:
            json.dump(state, f, indent=2)
    except Exception:
        pass


# ── Public API ────────────────────────────────────────────────────────────────

def is_enabled() -> bool:
    return _read().get("enabled", False)


def set_enabled(val: bool) -> None:
    with _lock:
        state = _read()
        state["enabled"] = val
        _write(state)


def add_to_queue(flow_id: str, data: dict) -> None:
    """Add a paused request to the queue."""
    with _lock:
        state = _read()
        state.setdefault("queue", {})[flow_id] = {
            "id":         flow_id,
            "method":     data.get("method", ""),
            "url":        data.get("url", ""),
            "headers":    data.get("headers", {}),
            "body":       data.get("body", ""),
            "timestamp":  data.get("timestamp", ""),
            "decision":   None,   # None = waiting, "forward", "drop", "edited"
            "edited_request": None,
        }
        _write(state)


def get_queue() -> dict:
    return _read().get("queue", {})


def get_flow(flow_id: str) -> dict | None:
    return _read().get("queue", {}).get(flow_id)


def set_decision(flow_id: str, decision: str,
                 edited_method: str = None,
                 edited_url: str = None,
                 edited_headers: dict = None,
                 edited_body: str = None) -> bool:
    """Set forward/drop/edited decision for a flow. Returns False if not found."""
    with _lock:
        state = _read()
        queue = state.get("queue", {})
        if flow_id not in queue:
            return False
        queue[flow_id]["decision"] = decision
        if decision == "edited":
            queue[flow_id]["edited_request"] = {
                "method":  edited_method,
                "url":     edited_url,
                "headers": edited_headers or {},
                "body":    edited_body or "",
            }
        _write(state)
        return True


def remove_from_queue(flow_id: str) -> None:
    with _lock:
        state = _read()
        state.get("queue", {}).pop(flow_id, None)
        _write(state)


def clear_queue() -> None:
    with _lock:
        state = _read()
        state["queue"] = {}
        _write(state)