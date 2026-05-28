"""
InterceptorX — Flask backend
Modules:
  db.py             — SQLite helpers
  ssrf.py           — SSRF protection
  repeater.py       — Session-aware HTTP request replayer
  session_store.py  — Named persistent sessions (cookie jars)
  scope.py          — Scope management (allowed/blocked domains)
  jwt_utils.py      — JWT decoder
  active_testing.py — Payload mutation + response analysis
  report_export.py  — JSON / HTML report generation
"""
import sys, os
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from flask import Flask, jsonify, render_template, request as flask_request, Response
import logging, secrets

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)

import db
import ssrf
import repeater
import session_store
import scope
import jwt_utils
import active_testing
import report_export
import intruder
import wordlist_store

app = Flask(__name__)

# CSRF-style token for destructive endpoints
_CLEAR_TOKEN = secrets.token_hex(16)


# ─── Core Routes ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return "<meta http-equiv='refresh' content='0; url=/dashboard'>"


@app.route("/traffic")
def get_traffic():
    conn  = db.get_db()
    rows  = conn.execute("SELECT * FROM traffic_logs ORDER BY id DESC LIMIT 100").fetchall()
    conn.close()
    return jsonify([db.row_to_dict(r) for r in rows])


@app.route("/dashboard")
def dashboard():
    conn    = db.get_db()
    rows    = conn.execute("SELECT * FROM traffic_logs ORDER BY id DESC LIMIT 100").fetchall()
    conn.close()
    traffic = [db.row_to_dict(r) for r in rows]
    stats   = {
        "total":  len(traffic),
        "high":   sum(1 for t in traffic if t["severity"] == "HIGH"),
        "medium": sum(1 for t in traffic if t["severity"] == "MEDIUM"),
        "safe":   sum(1 for t in traffic if t["severity"] == "SAFE"),
    }
    scope_state = scope.get_state()
    return render_template("dashboard.html", traffic=traffic, stats=stats,
                           scope=scope_state)


@app.route("/request/<int:request_id>")
def request_detail(request_id):
    conn = db.get_db()
    row  = conn.execute("SELECT * FROM traffic_logs WHERE id = ?", (request_id,)).fetchone()
    conn.close()
    if not row:
        return "Request not found", 404
    req       = db.row_to_dict(row)
    in_scope, scope_reason = scope.is_in_scope(req["url"])
    return render_template("request_detail.html", req=req,
                           in_scope=in_scope, scope_reason=scope_reason,
                           sessions=session_store.list_sessions())


# ─── Scope Management ────────────────────────────────────────────────────────

@app.route("/scope", methods=["GET"])
def get_scope():
    return jsonify(scope.get_state())


@app.route("/scope/enable", methods=["POST"])
def set_scope_enabled():
    data = flask_request.get_json(silent=True) or {}
    scope.set_enabled(bool(data.get("enabled", False)))
    return jsonify(scope.get_state())


@app.route("/scope/allowed", methods=["POST"])
def add_scope_allowed():
    data    = flask_request.get_json(silent=True) or {}
    pattern = data.get("pattern", "").strip()
    if not pattern:
        return jsonify({"error": "pattern required"}), 400
    scope.add_allowed(pattern)
    return jsonify(scope.get_state())


@app.route("/scope/allowed", methods=["DELETE"])
def remove_scope_allowed():
    data    = flask_request.get_json(silent=True) or {}
    pattern = data.get("pattern", "").strip()
    scope.remove_allowed(pattern)
    return jsonify(scope.get_state())


@app.route("/scope/blocked", methods=["POST"])
def add_scope_blocked():
    data    = flask_request.get_json(silent=True) or {}
    pattern = data.get("pattern", "").strip()
    if not pattern:
        return jsonify({"error": "pattern required"}), 400
    scope.add_blocked(pattern)
    return jsonify(scope.get_state())


@app.route("/scope/blocked", methods=["DELETE"])
def remove_scope_blocked():
    data    = flask_request.get_json(silent=True) or {}
    pattern = data.get("pattern", "").strip()
    scope.remove_blocked(pattern)
    return jsonify(scope.get_state())


@app.route("/scope/check", methods=["POST"])
def check_scope():
    data = flask_request.get_json(silent=True) or {}
    url  = data.get("url", "")
    allowed, reason = scope.is_in_scope(url)
    return jsonify({"url": url, "in_scope": allowed, "reason": reason})


# ─── Session Management ───────────────────────────────────────────────────────

@app.route("/sessions", methods=["GET"])
def list_sessions():
    return jsonify(session_store.list_sessions())


@app.route("/sessions/<name>", methods=["DELETE"])
def delete_session(name):
    deleted = session_store.delete(name)
    return jsonify({"deleted": deleted, "name": name})


@app.route("/sessions/<name>/reset", methods=["POST"])
def reset_session(name):
    session_store.reset(name)
    return jsonify({"reset": True, "name": name})


@app.route("/sessions/<name>/cookies", methods=["GET"])
def get_session_cookies(name):
    return jsonify(session_store.get_cookies(name))


@app.route("/sessions/<name>/cookies", methods=["POST"])
def inject_session_cookies(name):
    data    = flask_request.get_json(silent=True) or {}
    cookies = data.get("cookies", {})
    if not isinstance(cookies, dict):
        return jsonify({"error": "cookies must be a JSON object"}), 400
    session_store.inject_cookies(name, cookies)
    return jsonify({"injected": len(cookies), "name": name})


# ─── Repeater ────────────────────────────────────────────────────────────────

@app.route("/repeat/<int:request_id>", methods=["POST"])
def repeat_request(request_id):
    conn = db.get_db()
    row  = conn.execute("SELECT * FROM traffic_logs WHERE id = ?", (request_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "Request not found"}), 404

    data     = flask_request.get_json(silent=True) or {}
    row_d    = db.row_to_dict(row)

    # Raw HTTP mode — parse the raw editor content
    raw_http = data.get("raw_http", "").strip()
    if raw_http:
        try:
            result = repeater.send_raw(
                raw_http         = raw_http,
                base_url         = row_d["url"],
                session_name     = data.get("session", "default"),
                follow_redirects = data.get("follow_redirects", False),
            )
            return jsonify(result)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        except Exception as e:
            logger.exception("Error in raw repeat")
            return jsonify({"error": "Internal server error"}), 500

    # Standard JSON mode
    method   = row_d["method"]
    url      = data.get("url",     row_d["url"])
    headers  = data.get("headers", row_d["request_headers"])
    body     = data.get("body",    row_d["request_body"])
    session  = data.get("session", "default")
    follow   = data.get("follow_redirects", False)

    try:
        result = repeater.send(method, url, headers, body,
                               session_name=session,
                               follow_redirects=follow)
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.exception("Unhandled error in repeat_request")
        return jsonify({"error": "Internal server error"}), 500


# ─── JWT Decoder ─────────────────────────────────────────────────────────────

@app.route("/jwt-decode", methods=["POST"])
def jwt_decode():
    data  = flask_request.get_json(silent=True) or {}
    token = data.get("token", "").strip()
    if not token:
        return jsonify({"error": "No token provided"}), 400
    try:
        return jsonify(jwt_utils.decode(token))
    except Exception as e:
        return jsonify({"error": f"Failed to decode: {e}"}), 400


# ─── Clear DB ─────────────────────────────────────────────────────────────────

@app.route("/clear-token")
def get_clear_token():
    return jsonify({"token": _CLEAR_TOKEN})


@app.route("/clear", methods=["POST"])
def clear_traffic():
    data  = flask_request.get_json(silent=True) or {}
    token = data.get("token", "")
    if not secrets.compare_digest(token, _CLEAR_TOKEN):
        logger.warning("Clear attempt with invalid token")
        return jsonify({"error": "Invalid confirmation token."}), 403
    conn = db.get_db()
    conn.execute("DELETE FROM traffic_logs")
    conn.commit()
    conn.close()
    logger.info("Traffic log cleared")
    return jsonify({"message": "Traffic log cleared."})


# ─── Export Reports ───────────────────────────────────────────────────────────

@app.route("/export/json")
def export_json():
    conn    = db.get_db()
    rows    = conn.execute("SELECT * FROM traffic_logs ORDER BY id DESC").fetchall()
    conn.close()
    traffic = [db.row_to_dict(r) for r in rows]
    return Response(report_export.to_json(traffic), mimetype="application/json",
                    headers={"Content-Disposition": "attachment; filename=interceptorx_report.json"})


@app.route("/export/html")
def export_html():
    conn    = db.get_db()
    rows    = conn.execute("SELECT * FROM traffic_logs ORDER BY id DESC").fetchall()
    conn.close()
    traffic = [db.row_to_dict(r) for r in rows]
    return Response(report_export.to_html(traffic), mimetype="text/html",
                    headers={"Content-Disposition": "attachment; filename=interceptorx_report.html"})


# ─── Active Tester ────────────────────────────────────────────────────────────

@app.route("/active-test/<int:request_id>", methods=["POST"])
def active_test(request_id):
    conn = db.get_db()
    row  = conn.execute("SELECT * FROM traffic_logs WHERE id = ?", (request_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "Request not found"}), 404

    row_d           = db.row_to_dict(row)
    data            = flask_request.get_json(silent=True) or {}
    vuln_type       = data.get("type", "sqli").lower()
    custom_payloads = data.get("payloads", [])

    # Scope check before active testing
    in_scope, reason = scope.is_in_scope(row_d["url"])
    if not in_scope:
        return jsonify({"error": f"Out of scope: {reason}"}), 403

    try:
        results = active_testing.run(
            vuln_type       = vuln_type,
            method          = row_d["method"],
            original_url    = row_d["url"],
            original_body   = row_d["request_body"],
            headers         = row_d["request_headers"],
            custom_payloads = custom_payloads,
        )
        return jsonify({"type": vuln_type, "results": results})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.exception("Unhandled error in active_test")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/analytics")
def analytics():
    return render_template("interceptorx_charts.html")



# ─── Intruder ─────────────────────────────────────────────────────────────────

@app.route("/intruder")
def intruder_page():
    req_id = flask_request.args.get("id")
    req    = None
    if req_id:
        conn = db.get_db()
        row  = conn.execute("SELECT * FROM traffic_logs WHERE id = ?", (req_id,)).fetchone()
        conn.close()
        if row:
            req = db.row_to_dict(row)
    return render_template("intruder.html", req=req)


@app.route("/intruder/wordlists", methods=["GET"])
def get_wordlists():
    return jsonify(wordlist_store.list_all())


@app.route("/intruder/wordlists/<wordlist_id>", methods=["GET"])
def get_wordlist_payloads(wordlist_id):
    payloads = wordlist_store.get_payloads(wordlist_id)
    return jsonify({"id": wordlist_id, "payloads": payloads, "count": len(payloads)})


@app.route("/intruder/wordlists/upload", methods=["POST"])
def upload_wordlist():
    data    = flask_request.get_json(silent=True) or {}
    name    = data.get("name", "custom").strip()
    content = data.get("content", "")
    if not content.strip():
        return jsonify({"error": "No content provided"}), 400
    meta = wordlist_store.save_user_wordlist(name, content)
    return jsonify(meta)


@app.route("/intruder/wordlists/user/<name>", methods=["DELETE"])
def delete_wordlist(name):
    deleted = wordlist_store.delete_user_wordlist(name)
    return jsonify({"deleted": deleted})


@app.route("/intruder/run", methods=["POST"])
def run_intruder():
    data = flask_request.get_json(silent=True) or {}

    method         = data.get("method", "GET").upper()
    url_template   = data.get("url", "").strip()
    headers_raw    = data.get("headers", {})
    body_template  = data.get("body", "")
    wordlist_name  = data.get("wordlist", "params")
    custom_payloads = data.get("custom_payloads", [])

    if not url_template:
        return jsonify({"error": "URL is required"}), 400

    # Build payload list
    if custom_payloads:
        payloads = [p.strip() for p in custom_payloads if p.strip()]
    else:
        payloads = wordlist_store.get_payloads(wordlist_name)
        if not payloads:
            payloads = wordlist_store.get_payloads("params")

    if not payloads:
        return jsonify({"error": "No payloads selected"}), 400

    # Parse headers
    if isinstance(headers_raw, str):
        try:
            headers_dict = __import__("json").loads(headers_raw)
        except Exception:
            headers_dict = {}
    else:
        headers_dict = headers_raw or {}

    # Scope check
    import re as _re
    clean_url = _re.sub(r"§([^§]*)§", lambda m: m.group(1), url_template)
    in_scope, reason = scope.is_in_scope(clean_url)
    if not in_scope:
        return jsonify({"error": f"Out of scope: {reason}"}), 403

    try:
        results = intruder.run_sniper(
            method        = method,
            url_template  = url_template,
            headers_dict  = headers_dict,
            body_template = body_template,
            payloads      = payloads,
        )
        return jsonify(results)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.exception("Intruder error")
        return jsonify({"error": "Internal server error"}), 500

# ─── Intercept Mode ───────────────────────────────────────────────────────────

import intercept_store

@app.route("/intercept")
def intercept_page():
    return render_template("intercept.html")


@app.route("/intercept/status", methods=["GET"])
def intercept_status():
    return jsonify({
        "enabled": intercept_store.is_enabled(),
        "queue":   list(intercept_store.get_queue().values()),
    })


@app.route("/intercept/toggle", methods=["POST"])
def intercept_toggle():
    data    = flask_request.get_json(silent=True) or {}
    enabled = bool(data.get("enabled", False))
    intercept_store.set_enabled(enabled)
    if not enabled:
        intercept_store.clear_queue()
    logger.info("Intercept mode: %s", "ON" if enabled else "OFF")
    return jsonify({"enabled": enabled})


@app.route("/intercept/forward/<flow_id>", methods=["POST"])
def intercept_forward(flow_id):
    ok = intercept_store.set_decision(flow_id, "forward")
    if not ok:
        return jsonify({"error": "Flow not found"}), 404
    return jsonify({"status": "forwarded", "id": flow_id})


@app.route("/intercept/drop/<flow_id>", methods=["POST"])
def intercept_drop(flow_id):
    ok = intercept_store.set_decision(flow_id, "drop")
    if not ok:
        return jsonify({"error": "Flow not found"}), 404
    return jsonify({"status": "dropped", "id": flow_id})


@app.route("/intercept/edit/<flow_id>", methods=["POST"])
def intercept_edit(flow_id):
    data = flask_request.get_json(silent=True) or {}
    ok   = intercept_store.set_decision(
        flow_id,
        "edited",
        edited_method  = data.get("method"),
        edited_url     = data.get("url"),
        edited_headers = data.get("headers"),
        edited_body    = data.get("body"),
    )
    if not ok:
        return jsonify({"error": "Flow not found"}), 404
    return jsonify({"status": "edited_and_forwarded", "id": flow_id})


@app.route("/intercept/clear", methods=["POST"])
def intercept_clear():
    intercept_store.clear_queue()
    return jsonify({"status": "cleared"})

if __name__ == "__main__":
    app.run(debug=False, port=5000)