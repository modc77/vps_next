@echo off
setlocal
cd /d "%~dp0.."
python tools\gift_draw_api_probe.py %*
endlocal
