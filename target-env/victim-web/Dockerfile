FROM python:3.11-slim
LABEL description="Intentionally vulnerable web app — OWASP Top 10 lab target"

RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    gcc libmariadb-dev curl && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY app/ .
RUN pip install --no-cache-dir flask flask-sqlalchemy pymysql requests
EXPOSE 80
CMD ["python", "app.py"]
