FROM python:3.11-slim

LABEL maintainer="Adversary-in-a-Box Lab"
LABEL description="Forensic scoreboard — MTTD/MTTA tiered scoring dashboard (OQ-5)"

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py scorer.py ./
COPY templates ./templates

RUN mkdir -p /evidence

EXPOSE 5002

CMD ["python", "app.py"]
