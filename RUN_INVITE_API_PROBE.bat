@echo off
setlocal
cd /d "%~dp0"
title M WOIF - Invite API Probe V1

echo ============================================================
echo   M WOIF INVITE API PROBE V1 - ISOLATED
echo ============================================================
echo.
echo This tool reuses the existing VPS login/session/gRPC modules.
echo It does NOT start, stop, or modify the running worker service.
echo.

echo [1] Preview only - no SetReferrer write
echo [2] LIVE one-account proof - may consume this receiver once
echo [0] Exit
echo.
set /p MODE=Select: 

if "%MODE%"=="1" goto PREVIEW
if "%MODE%"=="2" goto LIVE
if "%MODE%"=="0" goto END

echo Invalid selection.
goto END

:PREVIEW
python tools\invite_api_probe.py
goto END

:LIVE
python tools\invite_api_probe.py --live
goto END

:END
echo.
pause
endlocal
