FROM kalilinux/kali-rolling:latest

LABEL maintainer="Adversary-in-a-Box Lab"
LABEL description="Red team attacker container — Kali Linux base"

# Install core tooling.
#
# Kali rolling's pool lags its index -- the default `http.kali.org` mirror
# often has stale entries that 404 on transitive libs (libexpat1, libgomp1,
# libatomic1...) for hours at a time. Switch the sources to the CDN-fronted
# `kali.download` which stays consistent, set apt retries, AND retry the
# install loop with longer sleeps as belt-and-suspenders. If all 3 attempts
# fail, exit non-zero so the silent fall-through into `pip install` doesn't
# mask the real failure with an `exec: pip3: not found` cascade.
RUN set -e && \
    echo 'deb http://kali.download/kali kali-rolling main contrib non-free non-free-firmware' \
        > /etc/apt/sources.list && \
    echo 'Acquire::Retries "5";' > /etc/apt/apt.conf.d/80-retries && \
    rc=1 ; \
    for attempt in 1 2 3 ; do \
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
        && { rc=0 ; break ; } ; \
        echo "[apt] attempt ${attempt} failed, refreshing index and retrying in 30s..." >&2 ; \
        rm -rf /var/lib/apt/lists/* ; \
        sleep 30 ; \
    done ; \
    if [ "${rc}" -ne 0 ]; then \
        echo "[apt] all 3 install attempts failed -- aborting build" >&2 ; \
        exit 1 ; \
    fi ; \
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
