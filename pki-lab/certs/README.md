# pki-lab/certs/

Bind-mounted into the `pki-nginx` container at `/etc/nginx/ssl/` (read-only).

This directory is intentionally empty in git. Generate certs **before** starting
the `pki` profile, otherwise nginx will fail to start:

```sh
# 1. Stand up the CA helper container (alpine/openssl with /workspace = pki-lab/)
docker compose --profile pki up -d pki-ca

# 2. Bootstrap the lab Root CA and issue the victim-web server cert
docker compose exec pki-ca sh setup_ca.sh
docker compose exec pki-ca sh issue_cert.sh victim-web.lab.local

# 3. Stage the certs where nginx expects them
cp pki-lab/ca/intermediate/certs/victim-web.lab.local.cert.pem  pki-lab/certs/victim-web.cert.pem
cp pki-lab/ca/intermediate/private/victim-web.lab.local.key.pem pki-lab/certs/victim-web.key.pem
cp pki-lab/ca/intermediate/certs/ca-chain.cert.pem              pki-lab/certs/ca-chain.cert.pem

# 4. Start the hardened nginx
docker compose --profile pki up -d pki-nginx
```

The exact paths nginx loads are defined in
`pki-lab/tls_hardening/nginx-tls.conf` (`ssl_certificate`,
`ssl_certificate_key`, `ssl_trusted_certificate`).

**Do not commit real keys.** The repo `.gitignore` already excludes `*.pem`,
`*.key`, and `*.crt`; the `.gitkeep` here is the only file that should ever be
tracked under `pki-lab/certs/`.
