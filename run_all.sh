#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "[*] Activating / creating virtual environment..."
[ -d venv ] || python3 -m venv venv
source venv/bin/activate

echo "[*] Installing dependencies..."
pip install -r requirements.txt

echo "[*] Installing external package as local dependency..."
pip install -e external_pkg

echo "[*] Initializing SQLite database..."
python resource_service/database.py

export JWT_SECRET="${JWT_SECRET:-local-dev-only-secret}"

echo "[*] Starting services in separate processes..."
python resource_service/app.py &
python processing_service/app.py &
python app_api/app.py &

trap 'echo "[*] Stopping services..."; kill $(jobs -p) 2>/dev/null' EXIT INT TERM

echo
echo "===================================================="
echo "Application API:      http://127.0.0.1:5001"
echo "Resource Service:     http://127.0.0.1:5002"
echo "Processing Service:   http://127.0.0.1:5003"
echo "Press Ctrl+C to stop all three."
echo "===================================================="
wait