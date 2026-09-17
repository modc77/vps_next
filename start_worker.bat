@echo off
setlocal
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (echo Run setup_worker.bat first.& exit /b 1)
if not exist .env (echo Missing .env& exit /b 1)
.venv\Scripts\python.exe main.py preflight || exit /b 1
.venv\Scripts\python.exe main.py worker-service
