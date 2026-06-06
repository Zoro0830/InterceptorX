# InterceptorX

A lightweight web application security testing platform inspired by Burp Suite workflows. Built with Python, mitmproxy, and Flask for educational and authorized security testing purposes.

> ⚠️ For authorized security testing only. Always obtain explicit written permission before testing any target.

---

## What is InterceptorX?

InterceptorX is a personal security testing tool that sits between your browser and the internet, capturing and analyzing HTTP/HTTPS traffic. It provides tools for manual testing, fuzzing, and passive reconnaissance — similar to Burp Suite Community Edition but built from scratch in Python.

---

## Features

### 🔴 Proxy & Interception
- HTTP/HTTPS traffic capture via mitmproxy
- **Live intercept mode** — pause requests before forwarding, edit and release
- Toggle intercept on/off — queue multiple requests simultaneously
- Forward, Drop, or Edit+Forward each intercepted request
- Auto-refresh traffic dashboard

### 🔁 Request Repeater
- Resend any captured request with modifications
- Raw HTTP editor mode
- Named persistent sessions with automatic cookie management
- CSRF token auto-extraction
- Redirect control — follow or inspect 302 responses

### 🎯 Intruder / Fuzzer (Sniper Mode)
- Mark injection points with `§markers§`
- Auto-mark common parameters with one click
- 8 built-in wordlists — SQLi, XSS, LFI, SSTI, Open Redirect, Passwords, Dirs, Params
- Upload custom `.txt` wordlist files
- **Smart detection engine** — finds real vulnerabilities, not just length diffs:
  - SQL error signatures (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
  - XSS reflection detection
  - SSTI evaluation confirmation (`{{7*7}}` → `49`)
  - LFI success markers (`root:x:0:0`)
  - Command injection output detection
  - Open redirect via Location header
  - Time-based SQLi (4000ms threshold)
- Response diff viewer — click any result to compare baseline vs payload
- Severity badges — CRITICAL, HIGH, MEDIUM, SAFE
- Filter by findings only — hide false positives instantly

### 🔍 JS Endpoint Extractor
- Passively scans every JS file captured by the proxy
- Extracts API routes, fetch() calls, axios() calls, GraphQL endpoints, WebSocket URLs, admin paths, auth endpoints
- Categorized endpoint inventory — API, fetch, GraphQL, WebSocket, Admin, Auth, Path
- Send any discovered endpoint directly to Intruder or Repeater
- Export full endpoint list as .txt
- Manual JS scan for specific files

### 🔐 JWT Decoder
- Decode any JWT token without signature verification
- View header, payload, and signature separately
- Detect JWT tokens in captured requests and responses automatically

### 🎯 Scope Manager
- Define allowed and blocked domains with wildcard support (`*.example.com`)
- CDN and analytics domains auto-excluded
- Active testing enforces scope automatically
- Scope persists across restarts

### 🛡️ SSRF Protection
- Blocks replays to private/internal IP ranges
- DNS rebinding protection — resolves hostnames and checks IPs
- Covers localhost, 10.x, 172.16.x, 192.168.x, link-local, CGNAT ranges

### 📊 Analytics Dashboard
- Severity breakdown chart (doughnut)
- Finding types chart (horizontal bar)
- Requests over time chart (stacked line)
- Auto-refreshes every 10 seconds

### 📄 Report Export
- Export findings as JSON
- Export findings as styled HTML report
- Reports include severity, findings, timestamps

### ⚙️ Session Management
- Multiple named sessions with isolated cookie jars
- Manual cookie injection
- Session reset and delete
- Cookie persistence across requests

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Proxy engine | Python, mitmproxy 12.2.2 |
| Backend | Flask 3.1.3 |
| Database | SQLite (WAL mode) |
| HTTP client | requests 2.34.0 |
| Charts | Chart.js (local) |
| Frontend | HTML, CSS, Vanilla JS |

---

## Project Structure

```
burpzip/
├── start_interceptorx.bat          ← One-click launcher (Windows)
├── README.md
├── requirements.txt
├── backend/
│   ├── app.py                      ← Flask routes and API
│   ├── config.py                   ← Central LAB_MODE configuration
│   ├── db.py                       ← SQLite helpers (WAL mode)
│   ├── active_testing.py           ← Active vulnerability tester
│   ├── intruder.py                 ← Sniper fuzzer engine
│   ├── repeater.py                 ← Session-aware request replayer
│   ├── session_store.py            ← Named session management
│   ├── scope.py                    ← Scope enforcement
│   ├── ssrf.py                     ← SSRF protection
│   ├── jwt_utils.py                ← JWT decoder
│   ├── js_extractor.py             ← Passive JS endpoint extractor
│   ├── wordlist_store.py           ← Built-in and custom wordlists
│   ├── intercept_store.py          ← Shared intercept queue (IPC)
│   ├── report_export.py            ← JSON/HTML report generation
│   ├── database_setup.py           ← DB initialization
│   ├── wordlists/                  ← Built-in wordlist files
│   │   ├── sqli.txt                (104 payloads)
│   │   ├── xss.txt                 (82 payloads)
│   │   ├── lfi.txt                 (69 payloads)
│   │   ├── ssti.txt                (35 payloads)
│   │   ├── open_redirect.txt       (30 payloads)
│   │   ├── passwords.txt           (109 payloads)
│   │   ├── dirs.txt                (140 payloads)
│   │   ├── params.txt              (106 payloads)
│   │   └── user/                   ← User-uploaded wordlists
│   └── templates/
│       ├── dashboard.html
│       ├── request_detail.html
│       ├── intercept.html
│       ├── intruder.html
│       ├── endpoints.html
│       └── interceptorx_charts.html
└── proxy/
    └── interceptor.py              ← mitmproxy addon (passive scanner + JS extractor)
```

---

## Setup

```bash
# 1. Create virtual environment
python -m venv .venv

# 2. Activate it (Windows)
.venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Initialize database
python backend/database_setup.py
```

---

## Running

### Option A — One click (Windows)
Double-click `start_interceptorx.bat`

Automatically:
- Activates virtual environment
- Initializes database if needed
- Starts Flask dashboard on port 5000
- Starts mitmproxy proxy on port 8080
- Opens dashboard in browser

### Option B — Manual
```bash
# Terminal 1 — Flask dashboard
cd backend
python app.py

# Terminal 2 — mitmproxy
cd proxy
mitmdump -s interceptor.py --listen-port 8080
```

---

## Browser Setup

1. Set browser proxy to `127.0.0.1:8080`
2. Visit `http://mitm.it` through the proxy
3. Install the mitmproxy CA certificate
4. Browse any HTTPS site — traffic appears in dashboard

---

## Pages

| URL | Description |
|-----|-------------|
| `localhost:5000/dashboard` | Main traffic dashboard |
| `localhost:5000/intercept` | Live intercept mode |
| `localhost:5000/intruder` | Fuzzer / Sniper attack |
| `localhost:5000/endpoints` | JS endpoint discovery |
| `localhost:5000/analytics` | Charts and statistics |
| `localhost:5000/request/<id>` | Request detail + tools |
| `localhost:5000/export/json` | Download JSON report |
| `localhost:5000/export/html` | Download HTML report |

---

## Configuration

Edit `backend/config.py`:

```python
LAB_MODE = True   # Disable TLS verification (local lab only)
LAB_MODE = False  # Enable TLS verification (real targets)
```

---

## Testing Workflow

1. Start InterceptorX and configure browser proxy
2. Browse target application normally — traffic captured automatically
3. Check `/endpoints` for hidden API routes discovered from JS files
4. Click interesting requests → **Send to Intruder**
5. Mark injection points with `§markers§`, select wordlist, run Sniper
6. Filter results by **🎯 Findings only** — review HIGH/CRITICAL results
7. Use Repeater to manually verify findings
8. Export HTML report for documentation

---

## Security Notice

InterceptorX is designed for:
- Authorized bug bounty testing
- Security research on systems you own
- Educational learning about web security

**Never test against systems without explicit written permission.**

---

## Requirements

```
mitmproxy==12.2.2
Flask==3.1.3
requests==2.34.0
```

---

## Legal Disclaimer

InterceptorX is intended for educational purposes and authorized security testing only. The authors are not responsible for any misuse of this tool. Always obtain explicit written permission before testing any target system.