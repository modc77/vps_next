@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title M WOIF Auth Keeper Worker LAB V1

set "PY=.venv\Scripts\python.exe"

if not exist "%PY%" (
    echo.
    echo [ERROR] Python venv not found: %PY%
    echo Run setup_worker.bat first.
    goto :failed
)

if not exist ".env" (
    echo.
    echo [ERROR] Missing production .env in this VPS root.
    goto :failed
)

if not exist "test\auth_keeper_worker_lab\main_lab.py" (
    echo.
    echo [ERROR] LAB files are missing.
    goto :failed
)

echo.
echo ============================================================
echo  M WOIF AUTH KEEPER WORKER LAB V1 - PREFLIGHT
echo ============================================================
echo  IMPORTANT: production start_worker.bat must be STOPPED.
echo  This LAB uses the live Web/DB but an isolated LAB session cache.
echo ============================================================
"%PY%" test\auth_keeper_worker_lab\main_lab.py preflight
if errorlevel 1 goto :failed

echo.
echo ============================================================
echo  M WOIF AUTH KEEPER WORKER LAB V1 - RUNNING
echo ============================================================
"%PY%" test\auth_keeper_worker_lab\main_lab.py worker-service
set "RC=%ERRORLEVEL%"

echo.
echo ============================================================
echo  LAB WORKER STOPPED - EXIT CODE %RC%
echo ============================================================
pause
exit /b %RC%

:failed
echo.
echo LAB Worker was not started. Read the error above.
pause
exit /b 1
