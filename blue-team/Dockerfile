FROM python:3.11-slim

LABEL maintainer="Adversary-in-a-Box Lab"
LABEL description="Blue team dashboard — Flask alert triage and IR playbook runner"

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        curl \
        net-tools \
        iptables \
        iproute2 \
        && apt-get clean \
        && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /evidence /app/logs

EXPOSE 5000

CMD ["python", "dashboard/app.py"]
