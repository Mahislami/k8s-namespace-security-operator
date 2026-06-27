FROM python:3.10-slim

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app /app/app

RUN groupadd -g 10001 appuser \
    && useradd -u 10001 -g appuser -m appuser

USER appuser

ENV PYTHONPATH=/app

CMD ["kopf", "run", "/app/app/operator.py"]