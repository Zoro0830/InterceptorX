# InterceptorX

Passive and active web application security testing platform featuring HTTP/HTTPS interception, request replay, vulnerability pattern analysis, JWT inspection, and interactive traffic analysis dashboards.

## Features

- ✅ HTTP/HTTPS interception via mitmproxy
- ✅ Automatic vulnerability detection:
  - SQL Injection patterns
  - XSS (reflected detection)
  - IDOR (user-controlled ID parameters)
  - Path Traversal
  - Sensitive Data Exposure (credit cards, emails, API keys)
  - Missing Security Headers (CSP, HSTS, X-Frame-Options, etc.)
- ✅ JWT detection & decoder
- ✅ Request Repeater (modify & resend any captured request)
- ✅ Live traffic dashboard with severity filters
- ✅ Auto-refresh dashboard
- ✅ Full request/response inspection

## Tech Stack

- Python, mitmproxy, Flask, SQLite

## Setup

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Initialize the database
python database_setup.py

# 3. Start the Flask dashboard
python app.py

# 4. In a new terminal, start the proxy
mitmdump -s interceptor.py --listen-port 8080

# 5. Configure your browser to use proxy: 127.0.0.1:8080
#    Then install the mitmproxy CA cert by visiting: http://mitm.it
```

## Usage

- Browse to `http://localhost:5000/dashboard` to see captured traffic
- Click any row to inspect the full request/response
- Use the **Repeater** tab to modify and resend requests
- Use the **JWT Decoder** tab to decode any JWT token

## Legal Disclaimer

For educational and authorized security testing only. Do not use against targets you do not own or have explicit permission to test.
