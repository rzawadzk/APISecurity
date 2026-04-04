FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir rich httpx pydantic click pyyaml fastapi uvicorn

# Copy application
COPY api_scout/ api_scout/
COPY samples/ samples/

# Data volume for DB and logs
VOLUME ["/data", "/logs"]

ENV PYTHONUNBUFFERED=1

EXPOSE 8080

ENTRYPOINT ["python3", "-m", "api_scout.cli", "--db", "/data/api_scout.db"]
CMD ["dashboard", "-h", "0.0.0.0", "-p", "8080"]
