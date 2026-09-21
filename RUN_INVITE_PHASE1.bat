@echo off
setlocal
cd /d "%~dp0"

echo ============================================================
echo   M WOIF INVITE_PUMP - VPS PHASE 1
echo ============================================================
echo.
echo [1] Check target / calculate remaining only
echo [2] Live Phase 1 with test Lv.5 receiver accounts
echo [0] Exit
echo.
set /p MWOIF_CHOICE=Select: 

if "%MWOIF_CHOICE%"=="1" goto preview
if "%MWOIF_CHOICE%"=="2" goto live
if "%MWOIF_CHOICE%"=="0" goto end

echo Invalid selection.
goto end

:preview
python tools\invite_phase1.py
goto end

:live
python tools\invite_phase1.py --live
goto end

:end
endlocal
