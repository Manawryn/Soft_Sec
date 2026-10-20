@echo off
title Multi-Tier Research Workspace Launcher

echo [*] Activating / Creating virtual environment...
if not exist venv (
    python -m venv venv
)
call venv\Scripts\activate.bat

echo [*] Installing dependencies...
pip install -r requirements.txt

echo [*] Installing external package as local dependency...
pip install -e external_pkg

echo [*] Initializing SQLite database...
python resource_service\database.py

echo [*] Starting Services in separate processes...
start "Resource Service (5002)" cmd /k "call venv\Scripts\activate.bat && python resource_service\app.py"
timeout /t 2 /nobreak >nul

start "Processing Service (5003)" cmd /k "call venv\Scripts\activate.bat && python processing_service\app.py"
timeout /t 2 /nobreak >nul

start "Application API (5001)" cmd /k "call venv\Scripts\activate.bat && python app_api\app.py"

echo.
echo ====================================================
echo All 3 microservices are running in separate processes!
echo Application API:      http://127.0.0.1:5001
echo Resource Service:     http://127.0.0.1:5002
echo Processing Service:   http://127.0.0.1:5003
echo ====================================================