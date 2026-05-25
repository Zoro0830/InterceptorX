@echo off
title InterceptorX Launcher
color 0A

echo.
echo  ██╗███╗   ██╗████████╗███████╗██████╗  ██████╗███████╗██████╗ ████████╗ ██████╗ ██████╗ ██╗  ██╗
echo  ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗╚██╗██╔╝
echo  ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝██║     █████╗  ██████╔╝   ██║   ██║   ██║██████╔╝ ╚███╔╝ 
echo  ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗██║     ██╔══╝  ██╔═══╝    ██║   ██║   ██║██╔══██╗ ██╔██╗ 
echo  ██║██║ ╚████║   ██║   ███████╗██║  ██║╚██████╗███████╗██║        ██║   ╚██████╔╝██║  ██║██╔╝ ██╗
echo  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
echo.
echo  Lightweight Web Security Testing Platform
echo  ------------------------------------------
echo.

REM ── Step 1: Check Python ────────────────────────────────────────────────────
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Please install Python 3.10+ and add it to PATH.
    pause
    exit /b 1
)

REM ── Step 2: Check virtual environment ───────────────────────────────────────
if exist ".venv\Scripts\activate.bat" (
    echo [*] Activating virtual environment...
    call .venv\Scripts\activate.bat
) else (
    echo [!] No .venv found. Using system Python.
    echo     Tip: Run  python -m venv .venv  then  pip install -r requirements.txt
)

REM ── Step 3: Initialize database if not already set up ───────────────────────
if not exist "backend\database\traffic.db" (
    echo [*] Initializing database...
    python backend\database_setup.py
    if errorlevel 1 (
        echo [ERROR] Database setup failed. Check database_setup.py.
        pause
        exit /b 1
    )
    echo [OK] Database initialized.
) else (
    echo [OK] Database already exists. Skipping init.
)

echo.
echo [*] Starting Flask dashboard on http://localhost:5000 ...
start "InterceptorX Dashboard" cmd /k "cd backend && python app.py"

REM ── Give Flask a moment to start ────────────────────────────────────────────
timeout /t 3 /nobreak >nul

echo [*] Starting mitmproxy on port 8080 ...
start "InterceptorX Proxy" cmd /k "cd proxy && mitmdump -s interceptor.py --listen-port 8080 --set block_global=false"

timeout /t 2 /nobreak >nul

echo.
echo ════════════════════════════════════════════════════════
echo   InterceptorX is running!
echo.
echo   Dashboard  →  http://localhost:5000/dashboard
echo   Proxy      →  127.0.0.1:8080
echo   CA Cert    →  http://mitm.it  (visit via proxied browser)
echo ════════════════════════════════════════════════════════
echo.
echo   Configure your browser proxy: 127.0.0.1:8080
echo   Then visit http://mitm.it to install the CA certificate.
echo.
echo   Press any key to open the dashboard in your browser...
pause >nul
start http://localhost:5000/dashboard