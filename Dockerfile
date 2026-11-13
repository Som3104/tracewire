# Python image for the loader and the API (code is mounted at /app by docker-compose)
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
