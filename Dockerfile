FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml /app/pyproject.toml
RUN pip install --no-cache-dir uv && uv pip install --system flask pycryptodome requests docker

COPY common /app/common
COPY victim /app/victim
COPY attacker /app/attacker
COPY benign /app/benign
COPY soc /app/soc
COPY control /app/control

ENV PYTHONPATH=/app
