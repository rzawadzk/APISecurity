FROM python:3.12-slim AS base

# Run as a dedicated non-root user. UID/GID 10001 leaves room for system users.
ARG APP_UID=10001
ARG APP_GID=10001
RUN groupadd --system --gid ${APP_GID} apiscout \
 && useradd  --system --uid ${APP_UID} --gid ${APP_GID} --home /app --shell /sbin/nologin apiscout

# OS deps: curl is used by the HEALTHCHECK below.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps via pyproject so versions stay in one place.
COPY pyproject.toml ./
COPY api_scout/ api_scout/
COPY samples/ samples/
RUN pip install --no-cache-dir . \
 && python -c "import api_scout; print('api_scout', api_scout.__version__)"

# Volumes for persistent state. /data is the DB, /logs is mounted log sources.
RUN mkdir -p /data /logs && chown -R apiscout:apiscout /data /logs /app
VOLUME ["/data", "/logs"]

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

EXPOSE 8080

USER apiscout

# Liveness check hits /health (unauthenticated by design).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["python3", "-m", "api_scout.cli", "--db", "/data/api_scout.db"]
CMD ["dashboard", "-h", "0.0.0.0", "-p", "8080"]
