# Exercise 02 — Issue, Revoke, and Verify Certificates
> **Domain 3 — Implementation | SY0-701 Objective 3.9**

## Overview
Practice the full certificate lifecycle: issuance, revocation, and CRL validation.

## Prerequisites
- Completed Exercise 01 (CA must exist)

## Steps

### 1. Issue a Server Certificate
```bash
bash pki-lab/issue_cert.sh victim-web 172.20.0.30 victim-web.lab.local
```

### 2. Inspect the Certificate
```bash
openssl x509 -in pki-lab/ca/intermediate-ca/certs/victim-web.cert.pem \
  -noout -text | grep -A5 "Subject Alternative Name"
```
Verify the SAN includes the IP and DNS entries.

### 3. Deploy to nginx
```bash
# Copy cert and key to victim-web container
docker compose cp pki-lab/ca/intermediate-ca/certs/victim-web.cert.pem victim-web:/etc/nginx/ssl/
docker compose cp pki-lab/ca/intermediate-ca/private/victim-web.key.pem victim-web:/etc/nginx/ssl/
docker compose cp pki-lab/tls_hardening/nginx-tls.conf victim-web:/etc/nginx/conf.d/default.conf
docker compose exec victim-web nginx -s reload
```

### 4. Revoke the Certificate
```bash
# Revoke using the Intermediate CA
openssl ca -config <(echo "[ca]
default_ca = CA_default
[CA_default]
certificate = pki-lab/ca/intermediate-ca/certs/intermediate.cert.pem
private_key = pki-lab/ca/intermediate-ca/private/intermediate.key.pem
database = pki-lab/ca/intermediate-ca/index.txt
crlnumber = pki-lab/ca/intermediate-ca/crlnumber
crl = pki-lab/ca/intermediate-ca/crl/intermediate.crl.pem
default_crl_days = 30") \
  -revoke pki-lab/ca/intermediate-ca/certs/victim-web.cert.pem \
  -crl_reason keyCompromise
```

### 5. Generate a CRL
```bash
openssl ca -gencrl -out pki-lab/ca/intermediate-ca/crl/intermediate.crl.pem ...
openssl crl -in pki-lab/ca/intermediate-ca/crl/intermediate.crl.pem -noout -text
```

### 6. Verify Against CRL
```bash
openssl verify -CAfile pki-lab/ca/intermediate-ca/certs/ca-chain.cert.pem \
  -crl_check -CRLfile pki-lab/ca/intermediate-ca/crl/intermediate.crl.pem \
  pki-lab/ca/intermediate-ca/certs/victim-web.cert.pem
```
Expected: `certificate revoked`

## Security+ Exam Connection
- Certificate lifecycle: request, issue, revoke, expire
- CRL and OCSP — online vs offline revocation
- Certificate pinning vs CA trust
