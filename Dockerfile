# backend/Dockerfile
FROM python:Python 3.12.2-slim

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

COPY . /app/

.\BACKEND_:/app
RUN mkdir -p /vol/web/static /vol/web/media

ENV DOTENV_PATH=/app/.env
RUN pip install python-dotenv


CMD ["gunicorn", "Nextremitly.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3"]