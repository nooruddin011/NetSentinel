FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
# libgomp is required by LightGBM/XGBoost wheels
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 curl && rm -rf /var/lib/apt/lists/*
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ ./backend/
COPY models/ ./models/
COPY data/schemas/ ./data/schemas/
COPY collector/ ./collector/
RUN useradd -r -u 10001 appuser && mkdir -p /app/data && chown -R appuser /app
USER appuser
WORKDIR /app/backend
ENV DB_PATH=/app/data/cyberwatch.db MODEL_DIR=/app/models/active APP_ENV=production
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s CMD curl -fs http://localhost:8000/api/health || exit 1
# One worker: the live-stream hub, login throttle and model hot-swap are per-process (see docs/ARCHITECTURE.md)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
