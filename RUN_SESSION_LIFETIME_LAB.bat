@echo off
setlocal EnableExtensions
cd /d "%~dp0"
set "ROOT=%CD%"
if not exist "%ROOT%\tools\session_lifetime_lab.py" (
  echo [ERROR] tools\session_lifetime_lab.py not found
  pause
  exit /b 2
)
if exist "%ROOT%\.venv\Scripts\python.exe" (
  set "PY=%ROOT%\.venv\Scripts\python.exe"
) else (
  set "PY=py -3"
)
set "PYTHONPATH=%ROOT%"
%PY% "%ROOT%\tools\session_lifetime_lab.py"
set "RC=%ERRORLEVEL%"
echo.
echo [DONE] exit=%RC%
pause
exit /b %RC%
