FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 appuser \
    && mkdir -p /workspace \
    && chown -R appuser:appuser /workspace
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/app ./app
COPY presets ./presets
# RulePackRegistry resolves these repository-root catalogs from /rules and /data.
COPY rules /rules
COPY data /data
COPY backend/alembic.ini ./alembic.ini
COPY backend/alembic ./alembic
USER appuser
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8000"]
