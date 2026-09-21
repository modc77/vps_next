@echo off
setlocal
cd /d "%~dp0"
if not exist "mwoif\" (
  echo [ERROR] Put tools\direct_login_inspect.py and this BAT in the VPS root.
  pause
  exit /b 1
)
python tools\direct_login_inspect.py
set RC=%ERRORLEVEL%
echo.
echo ExitCode=%RC%
pause
exit /b %RC%
