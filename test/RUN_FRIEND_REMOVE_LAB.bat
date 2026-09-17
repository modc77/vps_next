@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
  echo [ERROR] .venv not found.
  echo Put RUN_FRIEND_REMOVE_LAB.bat, FRIEND_REMOVE_LAB.env and tools folder inside vps_next.
  pause
  exit /b 2
)

".venv\Scripts\python.exe" tools\friend_remove_lab.py
set RC=%ERRORLEVEL%

if "%RC%"=="10" (
  echo.
  echo [SETUP] Open FRIEND_REMOVE_LAB.env and fill FRIEND_REMOVE_LAB_PASSWORD.
  start "" notepad.exe "%CD%\FRIEND_REMOVE_LAB.env"
)

echo.
echo [DONE] exit=%RC%
pause
exit /b %RC%
