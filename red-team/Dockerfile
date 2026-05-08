FROM kalilinux/kali-rolling:latest

LABEL maintainer="Adversary-in-a-Box Lab"
LABEL description="Red team attacker container — Kali Linux base"

# Install core tooling
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-venv \
        nmap \
        netcat-traditional \
        curl \
        wget \
        git \
        openssh-client \
        dnsutils \
        iputils-ping \
        net-tools \
        john \
        hashcat \
        hydra \
        sqlmap \
        gobuster \
        nikto \
        && apt-get clean \
        && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create evidence output directory
RUN mkdir -p /evidence /app/logs

# Default command — interactive shell for manual exploration
CMD ["/bin/bash"]
