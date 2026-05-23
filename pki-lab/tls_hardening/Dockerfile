FROM nginx:1.27-alpine

LABEL maintainer="Adversary-in-a-Box Lab"
LABEL description="PKI lab TLS-hardened nginx (OQ-4) — Domain 3 Exercise 3.2"

# OpenSSL is already in the alpine base; curl is useful for in-container probes.
RUN apk add --no-cache curl

# The mounted server-block snippet lives at conf.d/default.conf and is included
# by the stock /etc/nginx/nginx.conf shipped with the base image.
# Certificates are bind-mounted at /etc/nginx/ssl (see docker-compose.yml).
RUN mkdir -p /etc/nginx/ssl

EXPOSE 443
EXPOSE 80
