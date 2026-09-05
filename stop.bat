@echo off
title ComplianceForge - Stop Servers
echo Stopping ComplianceForge servers...

REM Kill uvicorn (backend) and vite (frontend)
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :8000 ^| findstr LISTENING') do taskkill /PID %%a /F >nul 2>&1
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :5173 ^| findstr LISTENING') do taskkill /PID %%a /F >nul 2>&1

echo Done. Backend (:8000) and frontend (:5173) stopped.
pause
