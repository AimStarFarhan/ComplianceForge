@echo off
title ComplianceForge Launcher
echo ====================================================
echo   ComplianceForge - One Control Plane
echo ====================================================
echo.

REM ---- 1. Backend dependencies (skip if already installed) ----
echo [1/4] Checking backend dependencies...
cd /d "%~dp0backend"
python -c "import fastapi, uvicorn, sqlalchemy, yaml, reportlab, jwt" >nul 2>&1
if errorlevel 1 (
    echo       Installing backend packages...
    python -m pip install -r requirements.txt
)

REM ---- 2. Frontend dependencies (skip if node_modules exists) ----
echo [2/4] Checking frontend dependencies...
if not exist "%~dp0frontend\node_modules" (
    echo       Installing frontend packages...
    cd /d "%~dp0frontend"
    call npm install
)

REM ---- 3. Start backend (FastAPI on :8000) ----
REM Auth: local demo uses dev-default credentials. For any shared/demo
REM deployment set CF_ADMIN_PASSWORD + CF_JWT_SECRET instead (the backend
REM refuses to start with defaults otherwise).
set CF_DEV_ALLOW_DEFAULTS=1
REM AI modes: local LM Studio models (air-gapped, no API key needed).
REM   Classifier -> fast 1.2B model (per-pattern calls must stay snappy).
REM   Report analyst (chat) -> larger reasoning model (quality matters).
REM   If LM Studio is down, the backend degrades gracefully to the
REM   deterministic classifier — so these are safe to leave on.
set CF_USE_LOCAL_LM=1
set CF_LOCAL_LM_CLASSIFY_MODEL=liquid/lfm2.5-1.2b
set CF_LOCAL_LM_ANALYST_MODEL=google/gemma-4-e4b
REM   Neural mode (cloud) alternative: set ANTHROPIC_API_KEY=... (or OPENAI_API_KEY=...)
echo [3/4] Starting backend  -^> http://127.0.0.1:8000
start "ComplianceForge API" cmd /k "cd /d ""%~dp0backend"" && python -m uvicorn app.main:app --port 8000"

REM ---- 4. Start frontend (Vite on :5173) ----
echo [4/4] Starting frontend -^> http://localhost:5173
start "ComplianceForge UI" cmd /k "cd /d ""%~dp0frontend"" && npm run dev"

REM ---- Open the control plane in the browser ----
echo.
echo      Waiting for servers to come up...
timeout /t 8 /nobreak >nul
start http://localhost:5173

echo.
echo ====================================================
echo   App        : http://localhost:5173
echo   API docs   : http://127.0.0.1:8000/docs
echo   Login      : admin / admin
echo.
echo   To STOP: close the two server windows
echo            (or run stop.bat)
echo ====================================================
echo.
pause
