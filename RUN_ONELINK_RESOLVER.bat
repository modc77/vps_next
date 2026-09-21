@echo off
setlocal
cd /d "%~dp0"
python tools\onelink_resolver.py
set "RC=%ERRORLEVEL%"
echo.
if not "%RC%"=="0" echo ExitCode=%RC%
pause
exit /b %RC%
