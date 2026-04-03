#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# KavachX Backend Bootstrap Script
# Usage: ./start.sh [--dev]
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Virtual Environment Autoload ─────────────────────────────
if [ -d "venv" ]; then
    echo "[start.sh] Activating local virtual environment (venv)..."
    source venv/bin/activate
elif [ -d ".venv" ]; then
    echo "[start.sh] Activating local virtual environment (.venv)..."
    source .venv/bin/activate
fi

# ── Read PORT from .env via Python if not already set in shell env ────────────
# The shell doesn't auto-read .env, but pydantic does.  Ask Python for the
# canonical port so start.sh always matches what the app expects.
if [[ -z "${PORT:-}" ]]; then
    PORT=$(python3 -c "from app.core.config import settings; print(settings.PORT)" 2>/dev/null || echo "8000")
fi
WORKERS="${WEB_CONCURRENCY:-1}"
LOG_LEVEL="${LOG_LEVEL:-info}"
ENV="${ENVIRONMENT:-$(python3 -c "from app.core.config import settings; print(settings.ENVIRONMENT)" 2>/dev/null || echo "development")}"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  KavachX AI Governance Platform"
echo "  Environment : ${ENV}"
echo "  Port        : ${PORT}"
echo "  Workers     : ${WORKERS}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── Resolve DATABASE_URL (shell env → .env via Python) ───────────────────────
if [[ -z "${DATABASE_URL:-}" ]]; then
    DATABASE_URL=$(python3 -c "from app.core.config import settings; print(settings.DATABASE_URL)" 2>/dev/null || echo "")
fi

# ── PostgreSQL readiness check (skipped for SQLite) ──────────────────────────
if [[ "${DATABASE_URL:-}" == postgresql* ]] || [[ "${DATABASE_URL:-}" == postgres* ]]; then
    echo "[start.sh] PostgreSQL detected — waiting for connection..."
    # Extract host:port from DATABASE_URL (handles asyncpg:// and standard://)
    DB_HOST=$(echo "${DATABASE_URL}" | sed -E 's|.*@([^:/]+)[:/].*|\1|')
    DB_PORT=$(echo "${DATABASE_URL}" | sed -E 's|.*:([0-9]+)/.*|\1|' || echo "5432")
    DB_PORT="${DB_PORT:-5432}"

    MAX_WAIT=30
    WAITED=0
    until pg_isready -h "${DB_HOST}" -p "${DB_PORT}" -q 2>/dev/null; do
        if [ "${WAITED}" -ge "${MAX_WAIT}" ]; then
            echo "[start.sh] ERROR: PostgreSQL not ready after ${MAX_WAIT}s — aborting."
            exit 1
        fi
        echo "[start.sh] Waiting for PostgreSQL at ${DB_HOST}:${DB_PORT}... (${WAITED}s)"
        sleep 2
        WAITED=$((WAITED + 2))
    done
    echo "[start.sh] PostgreSQL is ready."
fi

# ── Dev-key generation (only if BASCG_SIGNING_KEY_SEED_B64 is empty) ─────────
if [[ -z "${BASCG_SIGNING_KEY_SEED_B64:-}" ]] && [[ "${ENV}" == "development" ]]; then
    echo "[start.sh] No BASCG signing key found — generating ephemeral dev key..."
    python -c "
import base64, os
seed = os.urandom(32)
print('BASCG_SIGNING_KEY_SEED_B64=' + base64.b64encode(seed).decode())
" >> .env 2>/dev/null || true
fi

# ── Start uvicorn ─────────────────────────────────────────────────────────────
echo "[start.sh] Starting uvicorn on 0.0.0.0:${PORT} ..."

if [[ "${ENV}" == "development" ]] || [[ "${1:-}" == "--dev" ]]; then
    exec uvicorn app.main:app \
        --host 0.0.0.0 \
        --port "${PORT}" \
        --reload \
        --log-level "${LOG_LEVEL}" \
        --access-log
else
    exec uvicorn app.main:app \
        --host 0.0.0.0 \
        --port "${PORT}" \
        --workers "${WORKERS}" \
        --log-level "${LOG_LEVEL}" \
        --access-log \
        --forwarded-allow-ips "*"
fi
