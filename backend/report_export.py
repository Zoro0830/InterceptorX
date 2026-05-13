"""Report generation — JSON and HTML exports."""
import json
import datetime
import html


def to_json(traffic: list) -> str:
    flagged = [t for t in traffic if t["severity"] in ("HIGH", "MEDIUM")]
    report = {
        "tool":        "InterceptorX",
        "exported_at": datetime.datetime.utcnow().isoformat() + "Z",
        "summary": {
            "total_requests": len(traffic),
            "high":           sum(1 for t in traffic if t["severity"] == "HIGH"),
            "medium":         sum(1 for t in traffic if t["severity"] == "MEDIUM"),
            "safe":           sum(1 for t in traffic if t["severity"] == "SAFE"),
            "flagged_count":  len(flagged),
        },
        "findings": flagged,
    }
    return json.dumps(report, indent=2)


def to_html(traffic: list) -> str:
    flagged    = [t for t in traffic if t["severity"] in ("HIGH", "MEDIUM")]
    timestamp  = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    rows_html = ""
    for t in flagged:
        color = "#ef4444" if t["severity"] == "HIGH" else "#f59e0b"
        f_txt = html.escape("; ".join(f["type"] for f in t["findings"])) if t["findings"] else "—"
        rows_html += (
            f"<tr>"
            f"<td>{html.escape(str(t['id']))}</td>"
            f"<td><b>{html.escape(str(t['method']))}</b></td>"
            f"<td style='word-break:break-all;font-size:12px;'>{html.escape(str(t['url']))}</td>"
            f"<td>{html.escape(str(t['status_code']))}</td>"
            f"<td style='color:{color};font-weight:bold;'>{html.escape(str(t['severity']))}</td>"
            f"<td style='font-size:12px;'>{f_txt}</td>"
            f"<td style='font-size:11px;'>{html.escape(str(t['timestamp']))}</td>"
            f"</tr>"
)
    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>InterceptorX Report — {timestamp}</title>
<style>
  body{{font-family:monospace;background:#0f172a;color:#e2e8f0;padding:32px;}}
  h1{{color:#38bdf8;}}h2{{color:#94a3b8;font-size:14px;margin-top:8px;}}
  table{{width:100%;border-collapse:collapse;margin-top:24px;}}
  th{{background:#1e293b;padding:10px 12px;text-align:left;font-size:12px;color:#94a3b8;text-transform:uppercase;}}
  td{{padding:10px 12px;border-bottom:1px solid #1e293b;vertical-align:top;}}
  tr:hover{{background:#1e293b;}}
</style></head><body>
<h1>InterceptorX — Security Report</h1>
<h2>Generated: {timestamp} &nbsp;|&nbsp; Flagged: {len(flagged)} of {len(traffic)} requests</h2>
<p style="font-size:12px;color:#f59e0b;margin-top:12px;">
  ⚠️ Findings indicate suspicious patterns — manual verification required before claiming confirmed vulnerabilities.
</p>
<table>
  <thead><tr><th>#</th><th>Method</th><th>URL</th><th>Status</th><th>Severity</th><th>Findings</th><th>Time</th></tr></thead>
  <tbody>{rows_html}</tbody>
</table>
</body></html>"""