# --- Build Stage 1: Frontend ---
FROM node:18-alpine AS frontend-builder
WORKDIR /app/frontend

# Copy dependency manifest
COPY frontend/package*.json ./

# RUN npm install with --ignore-scripts to skip postinstall for now (since scripts/ isn't here yet)
RUN npm install --ignore-scripts

# Now copy the rest of the source (including scripts/)
COPY frontend/ ./

# Now that scripts/ is copied, you could run postinstall manually if needed, 
# but usually it's not necessary in Docker since NPM already sets perms.
# RUN npm run postinstall  <-- (Optionally)

# Build the frontend
RUN npm run build

# --- Build Stage 2: Backend & Final Image ---
FROM python:3.11-bookworm
WORKDIR /app

# Install system dependencies (Tesseract for OCR, etc.)
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

# Ensure logging works
RUN touch kavachx.log && chmod 666 kavachx.log

# Expose port and start application
ENV PORT=8002
EXPOSE 8002

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8002"]
