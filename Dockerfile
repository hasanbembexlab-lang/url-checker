FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN python -m pip install --no-cache-dir -r requirements.txt \
    && python -m playwright install --with-deps chromium

COPY monitor.py .
COPY frontend ./frontend

RUN mkdir -p /app/screenshots

EXPOSE 3003

CMD ["python", "-m", "uvicorn", "monitor:app", "--host", "0.0.0.0", "--port", "3003"]
