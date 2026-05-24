FROM python:3.14-slim

LABEL maintainer="Adversary-in-a-Box Lab"
LABEL description="Blue team dashboard — Flask alert triage and IR playbook runner"

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        curl \
        net-tools \
        iptables \
        iproute2 \
        ca-certificates \
        gnupg \
        && install -m 0755 -d /etc/apt/keyrings \
        && curl -fsSL https://download.docker.com/linux/debian/gpg \
            | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
        && chmod a+r /etc/apt/keyrings/docker.gpg \
        && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
            https://download.docker.com/linux/debian $(. /etc/os-release && echo \"$VERSION_CODENAME\") stable" \
            > /etc/apt/sources.list.d/docker.list \
        && apt-get update -qq \
        && apt-get install -y --no-install-recommends docker-ce-cli \
        && apt-get clean \
        && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /evidence /app/logs

EXPOSE 5000

CMD ["python", "dashboard/app.py"]
