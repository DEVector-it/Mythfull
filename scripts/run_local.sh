#!/usr/bin/env bash
set -euo pipefail

if [ ! -d "${VIRTUAL_ENV:-}" ] && ! command -v flask >/dev/null 2>&1; then
  echo "[!] Flask is not installed in this environment." >&2
  echo "    Run 'pip install -r requirements.txt' first." >&2
  exit 1
fi

export FLASK_DEBUG=${FLASK_DEBUG:-1}
export FLASK_APP=app

exec flask run --host=0.0.0.0 --port="${PORT:-5000}"
