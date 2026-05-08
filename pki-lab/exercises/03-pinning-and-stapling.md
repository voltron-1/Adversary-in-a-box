# Exercise 03 — Certificate Pinning and OCSP Stapling
> **Domain 3 — Implementation | SY0-701 Objective 3.9**

## Overview
Advanced PKI hardening: implement certificate pinning to prevent MITM attacks and enable OCSP stapling for efficient revocation checking.

## Concepts Covered
- **Certificate Pinning**: Client hard-codes expected cert/key hash
- **Public Key Pinning (HPKP)**: HTTP header-based pinning (deprecated but good to understand)
- **OCSP Stapling**: Server fetches and caches OCSP response, reducing client round-trips
- **HSTS**: HTTP Strict Transport Security — forces HTTPS

## OCSP Stapling

### 1. Enable in nginx (already in nginx-tls.conf)
```nginx
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 valid=300s;
```

### 2. Verify OCSP Stapling is Working
```bash
openssl s_client -connect 172.20.0.30:443 -status -servername victim-web.lab.local \
  < /dev/null 2>&1 | grep -A20 "OCSP response:"
```
Look for: `OCSP Response Status: successful`

## Certificate Pinning

### Python Client with Pinned Certificate
```python
import ssl
import hashlib
import socket

PINNED_CERT_SHA256 = "abc123..."  # Replace with actual cert hash

def get_cert_hash(host, port=443):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port)) as s:
        with ctx.wrap_socket(s) as ss:
            cert_der = ss.getpeercert(binary_form=True)
            return hashlib.sha256(cert_der).hexdigest()

def pinned_connect(host, port=443):
    actual_hash = get_cert_hash(host, port)
    if actual_hash != PINNED_CERT_SHA256:
        raise ssl.SSLError(f"Certificate pin mismatch! Got: {actual_hash}")
    print(f"[✓] Certificate pin verified: {actual_hash}")
```

### Get the Current Certificate Hash
```bash
openssl x509 -in pki-lab/ca/intermediate-ca/certs/victim-web.cert.pem \
  -outform DER | openssl dgst -sha256 | awk '{print $2}'
```

## HSTS Configuration
The nginx config already includes:
```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```
This forces browsers to only connect via HTTPS for 2 years.

## Security+ Exam Connection
- Certificate pinning — prevents MITM even with valid CA-signed certs
- OCSP vs CRL — OCSP is real-time, CRL is periodic
- HSTS — protects against SSL stripping attacks
- Key concepts: trust on first use (TOFU), certificate transparency
