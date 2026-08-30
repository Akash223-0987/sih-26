FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY pytrace ./pytrace
COPY scripts ./scripts
COPY services/ML-Analyzer/ .

ENV PYTHONUNBUFFERED=1
EXPOSE 8000
CMD ["uvicorn", "ml_service:app", "--host", "0.0.0.0", "--port", "8000"]