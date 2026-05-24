#!/bin/sh
# pki-lab/tls_hardening/entrypoint.sh
#
# Audit-2 Gap #6: nginx will crash-loop forever if pki-lab/certs/ is empty
# (because the lab Root CA hasn't been bootstrapped yet via setup_ca.sh).
# Print a single actionable error and exit non-zero so the user sees the
# real problem in `docker compose logs pki-nginx` instead of a wall of
# SSL_CTX_use_PrivateKey_file failures.
set -eu

CERT=/etc/nginx/ssl/victim-web.cert.pem
KEY=/etc/nginx/ssl/victim-web.key.pem

if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
    cat >&2 <<'EOF'
====================================================================
pki-nginx: TLS certificate or key missing under /etc/nginx/ssl/.

The lab Root CA hasn't been bootstrapped. Run these from the host:

    docker compose --profile pki up -d pki-ca
    docker compose --profile pki exec pki-ca sh setup_ca.sh
    docker compose --profile pki exec pki-ca sh issue_cert.sh victim-web.lab.local

    cp pki-lab/ca/intermediate/certs/victim-web.lab.local.cert.pem  pki-lab/certs/victim-web.cert.pem
    cp pki-lab/ca/intermediate/private/victim-web.lab.local.key.pem pki-lab/certs/victim-web.key.pem
    cp pki-lab/ca/intermediate/certs/ca-chain.cert.pem              pki-lab/certs/ca-chain.cert.pem

    docker compose --profile pki up -d pki-nginx

(See pki-lab/certs/README.md for the canonical instructions.)
====================================================================
EOF
    exit 1
fi

echo "[pki-nginx] cert + key present; starting nginx..."
exec nginx -g 'daemon off;'
