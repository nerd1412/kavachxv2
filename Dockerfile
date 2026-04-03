# --- Build Stage 1: Frontend ---
FROM node:18-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

# --- Build Stage 2: Backend & Final Image ---
# Switching from -slim to full python:3.11 (Debian Bookworm) for world-class stability
FROM python:3.11-bookworm
WORKDIR /app

# Install only necessary system binaries (the full image already has build-essential)
# Adding --fix-missing to handle temporary network issues
RUN apt-get update --fix-missing && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    libgl1-mesa-glx \
    libglib2.0-0 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY backend/requirements.txt ./backend/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r backend/requirements.txt

# Copy backend code
COPY backend/ ./backend/

# Copy built frontend from Stage 1
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

# Set working directory to backend for runtime
WORKDIR /app/backend

# Ensure the log file exists and is writable
RUN touch kavachx.log && chmod 666 kavachx.log

# Expose port and start application
ENV PORT=8002
EXPOSE 8002

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8002"]
