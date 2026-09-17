@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul || (echo Python launcher not found.& exit /b 1)
if not exist .venv py -3.12 -m venv .venv
call .venv\Scripts\activate.bat
if not exist state mkdir state
if not exist logs mkdir logs
python -m pip install --upgrade pip
pip install -r requirements.txt
if not exist .env copy /Y .env.example .env >nul
echo Setup complete. Fill .env and copy the two private state JSON files into state\ before starting.
