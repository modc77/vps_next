#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [[ ! -d mwoif ]]; then
  echo "[ERROR] Put tools/direct_login_inspect.py and this script in the VPS root."
  exit 1
fi
python3 tools/direct_login_inspect.py
