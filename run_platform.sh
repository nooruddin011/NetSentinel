#!/usr/bin/env bash
# Argus development launcher for macOS/Linux: backend on :8000, frontend on :5173
set -euo pipefail
cd "$(dirname "$0")"
[ -f .env ] || cp .env.example .env
if [ ! -d backend/.venv ]; then
  python3 -m venv backend/.venv
  backend/.venv/bin/pip install -r backend/requirements.txt
fi
(cd frontend && npm install --no-audit --no-fund)   # always: picks up new dependencies after an upgrade (fast when nothing changed)
trap 'kill 0' EXIT
(cd backend && .venv/bin/uvicorn app.main:app --reload) &
(cd frontend && npm run dev) &
wait
