@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo [ERROR] .venv not found
  pause
  exit /b 1
)
.venv\Scripts\python.exe tools\friend_relationship_lab.py
set "RC=%ERRORLEVEL%"
echo.
echo [DONE] exit=%RC%
pause
exit /b %RC%
