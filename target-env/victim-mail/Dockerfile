FROM debian:bullseye-slim
LABEL description="Victim mail server — Postfix SMTP for phishing lab"

RUN apt-get update -qq && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        postfix \
        mailutils \
        && apt-get clean && rm -rf /var/lib/apt/lists/*

# Configure Postfix with permissive settings for lab
RUN postconf -e "myhostname = victim-mail.lab.local" \
    && postconf -e "mydomain = lab.local" \
    && postconf -e "mynetworks = 172.20.0.0/24 127.0.0.0/8" \
    && postconf -e "inet_interfaces = all" \
    && postconf -e "smtpd_recipient_restrictions = permit_mynetworks, permit_sasl_authenticated, defer_unauth_destination" \
    && postconf -e "smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, defer_unauth_destination"

EXPOSE 25

CMD ["postfix", "start-fg"]
