#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
[ -x .venv/bin/python ] || { echo "Run setup first"; exit 1; }
[ -f .env ] || { echo "Missing .env"; exit 1; }
.venv/bin/python main.py preflight
exec .venv/bin/python main.py worker-service
