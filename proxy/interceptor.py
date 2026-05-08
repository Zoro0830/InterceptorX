from mitmproxy import http
import sqlite3

def request(flow: http.HTTPFlow):

    method = flow.request.method
    url = flow.request.pretty_url

    print(f"[REQUEST] {method} {url}")

    conn = sqlite3.connect("database/traffic.db")
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO traffic_logs (method, url) VALUES (?, ?)",
        (method, url)
    )

    conn.commit()
    conn.close()