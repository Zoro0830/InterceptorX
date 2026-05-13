"""JWT decoding utilities (no signature verification)."""
import base64
import json


def _b64_decode(part: str) -> dict:
    """
    Decode a base64url JWT segment with correct padding.
    (4 - len % 4) % 4 avoids adding 4 spurious '=' when already aligned —
    the classic off-by-one padding bug.
    """
    part += "=" * ((4 - len(part) % 4) % 4)
    return json.loads(base64.urlsafe_b64decode(part).decode("utf-8"))


def decode(token: str) -> dict:
    """
    Decode a JWT token string.
    Returns dict with keys: header, payload, signature, raw.
    Raises ValueError on bad input.
    """
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format — expected 3 dot-separated parts")

    return {
        "header":    _b64_decode(parts[0]),
        "payload":   _b64_decode(parts[1]),
        "signature": parts[2],
        "raw":       token,
    }