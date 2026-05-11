# ── Elyria Pentest & API Client ──
FROM python:3.12-slim

WORKDIR /app

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App code
COPY app/ ./app/
COPY doc/ ./doc/

# Data directory — SQLite DB + persisted files live here
# Mount a volume at /data to keep your data across container rebuilds
RUN mkdir -p /data
VOLUME ["/data"]
ENV DB_PATH=/data/database.db

# Expose the API port
EXPOSE 8000

# Host special DNS for connecting to host-local Ollama / LM Studio
# On Mac/Windows Docker Desktop: host.docker.internal is auto-resolved
# On Linux: use --add-host=host.docker.internal:host-gateway at docker run

WORKDIR /app/app
CMD ["uvicorn", "entrypoint:app", "--host", "0.0.0.0", "--port", "8000"]
