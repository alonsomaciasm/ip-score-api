FROM python:3.11-slim as builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.11-slim

WORKDIR /app

COPY --from=builder /install /usr/local
COPY . /app

# Create necessary directories and set non-root user permissions
RUN mkdir -p /app/data/mmdb /app/data/feeds /app/logs /tmp && \
    useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app /tmp

USER appuser

EXPOSE 8000

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

HEALTHCHECK --interval=20s --timeout=5s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/v1/health/liveness')" || exit 1

CMD ["granian", "--interface", "asgi", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
