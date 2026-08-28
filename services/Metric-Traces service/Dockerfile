FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy main.py from the service folder using JSON array syntax to handle spaces
COPY ["services/Metric-Traces service/main.py", "."]

# Standard OpenTelemetry HTTP default port is 4318
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "4318"]