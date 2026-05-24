FROM debian:bullseye-slim
LABEL description="Victim mail server — Postfix SMTP for phishing lab"

RUN apt-get update -qq && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        postfix \
        mailutils \
        && apt-get clean && rm -rf /var/lib/apt/lists/*

# Postfix config (incl. mynetworks) is deferred to entrypoint.sh so the
# per-student LAB_NET_PREFIX env var actually flows through to the running
# postconf. See Phase 0 isolation and audit-2 Gap #2.
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 25

ENTRYPOINT ["/entrypoint.sh"]
CMD ["postfix", "start-fg"]
