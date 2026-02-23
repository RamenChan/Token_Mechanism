FROM python:3.11-slim

WORKDIR /app

# system deps (bcrypt wheels yetse de bazen iyi)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml /app/

RUN pip install --no-cache-dir -U pip && \
    pip install --no-cache-dir .

COPY app /app/app

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]