# ─────────────────────────────────────────────────────────────────────────────
# KavachX Backend — Production Dockerfile (multi-stage)
# ─────────────────────────────────────────────────────────────────────────────
# Stage 1: dependency builder (cached layer)
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build tools required for some Python C-extensions
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ─────────────────────────────────────────────────────────────────────────────
# Stage 2: lean runtime image
FROM python:3.11-slim AS runtime

# Security: run as non-root
RUN groupadd -r kavachx && useradd -r -g kavachx kavachx

# Runtime system deps (libpq for asyncpg, curl for healthcheck, pg_isready for start.sh)
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl postgresql-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy compiled Python packages from builder
COPY --from=builder /install /usr/local

# Copy application source
COPY . .

# Data directory for SQLite / runtime state
RUN mkdir -p /app/data && chown -R kavachx:kavachx /app

USER kavachx

# $PORT is injected by Render/Railway/Fly at runtime (default 8000)
EXPOSE 8000

# Health check — uses $PORT env var (falls back to 8000)
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8000}/health || exit 1

# start.sh handles DB readiness check + uvicorn launch
CMD ["bash", "start.sh"]
