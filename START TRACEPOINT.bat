@echo off
REM Double-click launcher for TRACEPOINT.
REM Runs first-time install automatically, then starts the app. No typing needed.
cd /d "%~dp0"
title TRACEPOINT
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0TRACEPOINT.ps1"
echo.
echo TRACEPOINT has closed.
pause
