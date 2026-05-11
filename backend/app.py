from flask import Flask, jsonify, render_template, request as flask_request
import sqlite3
import json
import base64
import requests as http_requests

app = Flask(__name__)

DB_PATH = "database/traffic.db"


# ─── DB Helper ───────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def row_to_dict(row):
    findings_raw = row["findings"]
    try:
        findings = json.loads(findings_raw) if findings_raw else []
    except Exception:
        findings = []

    response_headers_raw = row["response_headers"]
    try:
        response_headers = json.loads(response_headers_raw) if response_headers_raw else {}
    except Exception:
        response_headers = {}

    request_headers_raw = row["request_headers"]
    try:
        request_headers = json.loads(request_headers_raw) if request_headers_raw else {}
    except Exception:
        request_headers = {}

    return {
        "id": row["id"],
        "method": row["method"],
        "url": row["url"],
        "status_code": row["status_code"],
        "request_headers": request_headers,
        "request_body": row["request_body"] or "",
        "response_headers": response_headers,
        "response_body": row["response_body"] or "",
        "findings": findings,
        "severity": row["severity"] if "severity" in row.keys() else "SAFE",
        "timestamp": row["timestamp"]
    }


# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return "<meta http-equiv='refresh' content='0; url=/dashboard'>"


@app.route("/traffic", methods=["GET"])
def get_traffic():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM traffic_logs ORDER BY id DESC LIMIT 100")
    rows = cursor.fetchall()
    conn.close()
    return jsonify([row_to_dict(r) for r in rows])


@app.route("/dashboard")
def dashboard():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM traffic_logs ORDER BY id DESC LIMIT 100")
    rows = cursor.fetchall()
    conn.close()

    traffic_data = [row_to_dict(r) for r in rows]

    # Stats
    stats = {
        "total": len(traffic_data),
        "high": sum(1 for t in traffic_data if t["severity"] == "HIGH"),
        "medium": sum(1 for t in traffic_data if t["severity"] == "MEDIUM"),
        "safe": sum(1 for t in traffic_data if t["severity"] == "SAFE"),
    }

    return render_template("dashboard.html", traffic=traffic_data, stats=stats)


@app.route("/request/<int:request_id>")
def request_detail(request_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM traffic_logs WHERE id = ?", (request_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return "Request not found", 404

    return render_template("request_detail.html", req=row_to_dict(row))


# ─── Repeater ────────────────────────────────────────────────────────────────

@app.route("/repeat/<int:request_id>", methods=["POST"])
def repeat_request(request_id):
    """Resend a captured request, optionally with modified headers/body."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM traffic_logs WHERE id = ?", (request_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "Request not found"}), 404

    data = flask_request.get_json(silent=True) or {}
    method = row["method"]
    url = data.get("url", row["url"])

    # Use modified headers/body from request body if provided, else use original
    try:
        original_headers = json.loads(row["request_headers"] or "{}")
    except Exception:
        original_headers = {}

    headers = data.get("headers", original_headers)
    body = data.get("body", row["request_body"] or "")

    # Remove proxy-related headers that would cause issues
    for h in ["host", "content-length", "transfer-encoding"]:
        headers.pop(h, None)
        headers.pop(h.capitalize(), None)

    try:
        resp = http_requests.request(
            method=method,
            url=url,
            headers=headers,
            data=body,
            timeout=15,
            verify=False,
            allow_redirects=False
        )

        return jsonify({
            "status_code": resp.status_code,
            "response_headers": dict(resp.headers),
            "response_body": resp.text[:50000]  # Cap at 50KB
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── JWT Decoder ─────────────────────────────────────────────────────────────

@app.route("/jwt-decode", methods=["POST"])
def jwt_decode():
    """Decode a JWT token without verification."""
    data = flask_request.get_json(silent=True) or {}
    token = data.get("token", "").strip()

    if not token:
        return jsonify({"error": "No token provided"}), 400

    try:
        parts = token.split(".")
        if len(parts) != 3:
            return jsonify({"error": "Invalid JWT format"}), 400

        def decode_part(part):
            part += "=" * (4 - len(part) % 4)
            return json.loads(base64.urlsafe_b64decode(part).decode("utf-8"))

        header = decode_part(parts[0])
        payload = decode_part(parts[1])

        return jsonify({
            "header": header,
            "payload": payload,
            "signature": parts[2],
            "raw": token
        })

    except Exception as e:
        return jsonify({"error": f"Failed to decode: {str(e)}"}), 400


# ─── Clear DB ────────────────────────────────────────────────────────────────

@app.route("/clear", methods=["POST"])
def clear_traffic():
    conn = get_db()
    conn.execute("DELETE FROM traffic_logs")
    conn.commit()
    conn.close()
    return jsonify({"message": "Traffic log cleared."})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
