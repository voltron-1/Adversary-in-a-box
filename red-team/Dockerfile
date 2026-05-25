FROM kalilinux/kali-rolling:latest

LABEL maintainer="Adversary-in-a-Box Lab"
LABEL description="Red team attacker container — Kali Linux base"

# Install core tooling.
#
# Kali rolling's pool lags its index — half the time builds 404 on
# transitive libs (libexpat1, libgomp1, libatomic1...) whose .deb has
# already been rotated out. Configure apt retries AND retry the install
# loop a couple of times so a flaky upstream doesn't fail the build.
RUN echo 'Acquire::Retries "5";' > /etc/apt/apt.conf.d/80-retries && \
    for attempt in 1 2 3; do \
        apt-get update -qq && \
        apt-get install -y --no-install-recommends \
            python3 \
            python3-pip \
            python3-venv \
            python-is-python3 \
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
            && break ; \
        echo "[apt] attempt $attempt failed, refreshing index and retrying..." >&2 ; \
        rm -rf /var/lib/apt/lists/* ; \
        sleep 5 ; \
    done && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies.
# Phase F5: --break-system-packages bypasses PEP 668's
# externally-managed-environment marker that Kali (Debian-derived) sets
# on the system Python. The container is single-purpose so installing
# into the system site-packages is intentional, not a footgun.
COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# Copy application code
COPY . .

# Create evidence output directory
RUN mkdir -p /evidence /app/logs

# Default command — interactive shell for manual exploration
CMD ["/bin/bash"]
