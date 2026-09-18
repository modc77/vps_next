@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title M WOIF Worker Service

set "PY=.venv\Scripts\python.exe"

if not exist "%PY%" (
    echo.
    echo [ERROR] Python venv not found: %PY%
    echo Run setup_worker.bat first.
    goto :failed
)

if not exist ".env" (
    echo.
    echo [ERROR] Missing .env
    goto :failed
)

:preflight
echo.
echo ============================================================
echo   M WOIF WORKER - PREFLIGHT
echo ============================================================
"%PY%" main.py preflight
if errorlevel 1 (
    echo.
    echo [ERROR] PREFLIGHT FAILED
    goto :failed
)

:run
echo.
echo ============================================================
echo   M WOIF WORKER - RUNNING
echo ============================================================
"%PY%" main.py worker-service
set "RC=%ERRORLEVEL%"

echo.
echo ============================================================
echo   WORKER STOPPED - EXIT CODE %RC%
echo ============================================================
echo.
echo [R] Restart worker
echo [Q] Quit
choice /C RQ /N /M "Select: "
if errorlevel 2 exit /b %RC%
goto :preflight

:failed
echo.
echo Worker was not started. This window will stay open so the error can be read.
pause
exit /b 1
