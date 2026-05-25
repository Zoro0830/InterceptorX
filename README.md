# InterceptorX

A lightweight passive and active web application security testing platform built with Python for educational and authorized security assessment. InterceptorX combines HTTP/HTTPS traffic interception, request replay, heuristic vulnerability analysis, JWT inspection, scope management, and interactive analytics dashboards in a unified interface.

> ⚠️ **Legal Warning:** InterceptorX is intended strictly for educational purposes and authorized security testing only. Do not use this tool against systems you do not own or do not have explicit written permission to test.

---

# Features

## Core Platform
- ✅ HTTP/HTTPS traffic interception powered by **mitmproxy**
- ✅ Live traffic monitoring dashboard with auto-refresh
- ✅ Full request and response inspection
- ✅ One-click Windows startup script (`start_interceptorx.bat`)
- ✅ SQLite-based traffic logging with WAL mode for improved concurrency

---

## Passive Security Analysis

InterceptorX automatically analyzes captured traffic for suspicious patterns.

### Detection Capabilities
- ✅ SQL Injection pattern detection
- ✅ Cross-Site Scripting (XSS) pattern detection
- ✅ Heuristic IDOR detection (user-controlled identifiers)
- ✅ Path Traversal detection
- ✅ Sensitive Data Exposure detection:
  - Credit card numbers (Luhn validated)
  - Plaintext password leakage
  - API key / secret exposure
- ✅ Missing security headers detection:
  - Content-Security-Policy (CSP)
  - Strict-Transport-Security (HSTS)
  - X-Frame-Options
  - X-Content-Type-Options
- ✅ JWT token detection in requests and API responses

---

## Active Security Testing

InterceptorX supports controlled active testing against authorized targets.

### Active Testing Features
- ✅ SQL Injection payload injection
- ✅ Database error signature analysis
- ✅ Reflected XSS payload testing
- ✅ IDOR enumeration with baseline comparison
- ✅ Request budget cap to reduce accidental denial-of-service
- ✅ Scope enforcement to prevent testing out-of-scope targets

---

## Request Repeater

Captured requests can be modified and replayed.

### Repeater Capabilities
- ✅ Modify and resend captured requests
- ✅ Raw HTTP request editor
- ✅ Named persistent sessions
- ✅ Cookie persistence across requests
- ✅ Cookie injection support
- ✅ Redirect handling (follow or inspect redirects)
- ✅ Automatic CSRF token extraction

---

## Additional Security Tools

### JWT Inspector
- ✅ Decode JWT token structure
- ✅ Inspect header
- ✅ Inspect payload
- ✅ View raw signature segment

> **Note:** JWT signatures are **not cryptographically verified**. This module is for inspection only.

---

### Scope Manager
- ✅ Wildcard domain allow lists
- ✅ Explicit block lists
- ✅ CDN / analytics domain auto-exclusion
- ✅ Scope enforcement for active testing

Example:
```text
*.example.com
api.target.com
```

---

### SSRF Protection

Request replay is protected against unsafe destinations.

Protections include:
- ✅ Localhost blocking
- ✅ Private IP blocking
- ✅ Internal subnet blocking
- ✅ DNS rebinding protection
- ✅ Unsafe protocol rejection

---

### Analytics Dashboard

Interactive visual dashboards for captured traffic.

Includes:
- ✅ Severity breakdown charts
- ✅ Finding distribution charts
- ✅ Request timeline trends

---

### Report Export

Generate structured reports for documentation.

Supported formats:
- ✅ JSON export
- ✅ HTML export

---

# Technology Stack

- **Python 3.x**
- **Flask**
- **mitmproxy**
- **SQLite**
- **requests**
- **Chart.js**

---

# Project Structure

```text
BURPZIP/
├── start_interceptorx.bat
├── requirements.txt
├── README.md
│
├── backend/
│   ├── app.py
│   ├── config.py
│   ├── db.py
│   ├── database_setup.py
│   ├── active_testing.py
│   ├── repeater.py
│   ├── session_store.py
│   ├── scope.py
│   ├── ssrf.py
│   ├── jwt_utils.py
│   ├── report_export.py
│   │
│   ├── database/
│   │   └── traffic.db
│   │
│   └── templates/
│       ├── dashboard.html
│       ├── request_detail.html
│       └── interceptorx_charts.html
│
├── proxy/
│   └── interceptor.py
│
├── docs/
├── frontend/
└── screenshots/
```

---

# Installation

## 1. Create Virtual Environment

### Windows
```bash
python -m venv .venv
.venv\Scripts\activate
```

### Linux / macOS
```bash
python3 -m venv .venv
source .venv/bin/activate
```

---

## 2. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 3. Initialize Database

```bash
python backend/database_setup.py
```

---

# Running InterceptorX

## Option A — One Click (Windows)

Double-click:

```text
start_interceptorx.bat
```

This will:
- Activate virtual environment
- Initialize database
- Start Flask dashboard
- Start mitmproxy interception engine
- Open dashboard automatically

---

## Option B — Manual Startup

### Terminal 1 — Flask Dashboard

```bash
cd backend
python app.py
```

### Terminal 2 — Proxy Engine

```bash
cd proxy
mitmdump -s interceptor.py --listen-port 8080
```

---

# Browser Proxy Configuration

Configure your browser proxy:

```text
127.0.0.1:8080
```

Then:

1. Open browser through proxy
2. Visit:

```text
http://mitm.it
```

3. Download the mitmproxy CA certificate
4. Install the certificate into browser / operating system trust store
5. Start browsing

Captured traffic will appear automatically in the dashboard.

---

# Dashboard Endpoints

| Endpoint | Purpose |
|---------|---------|
| `/dashboard` | Main traffic dashboard |
| `/traffic` | Raw traffic JSON feed |
| `/analytics` | Analytics dashboard |
| `/request/<id>` | Request detail inspector |
| `/export/json` | JSON report export |
| `/export/html` | HTML report export |
| `/scope` | Scope configuration API |
| `/sessions` | Session management API |

---

# Configuration

Edit:

```text
backend/config.py
```

Example:

```python
LAB_MODE = False
```

Modes:

```python
LAB_MODE = True
```
Disables TLS verification for controlled local lab environments.

```python
LAB_MODE = False
```
Enables TLS verification for authorized external testing.

---

# Limitations

InterceptorX is an academic security testing platform and has intentional limitations.

Current limitations:
- No native interactive intercept-edit-forward UI
- No crawler / spider module
- No websocket traffic analysis
- No extension/plugin ecosystem
- JWT signature verification not implemented
- Heuristic vulnerability detection (not exploit confirmation)

---

# Intended Use Cases

Suitable for:
- Cybersecurity academic projects
- Web application security learning
- Authorized lab testing
- Vulnerability demonstration
- HTTP traffic inspection
- Request replay experimentation

Not intended as a replacement for enterprise commercial tools.

---

# Legal Disclaimer

InterceptorX must only be used for:
- Educational purposes
- Controlled lab environments
- Authorized penetration testing

Unauthorized use may violate laws, policies, or contractual agreements.

The authors assume no responsibility for misuse.