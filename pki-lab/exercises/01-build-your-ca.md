# Exercise 01 — Build Your Own Certificate Authority
> **Domain 3 — Implementation | SY0-701 Objective 3.9**

## Overview
In this exercise you will build a two-tier PKI hierarchy using OpenSSL: a Root CA and an Intermediate CA. This mirrors enterprise PKI deployments and covers core Security+ exam objectives on certificate management.

## Prerequisites
- OpenSSL 3.x installed: `openssl version`
- Lab running: `docker compose ps` shows all services Up

## Concepts Covered
- **Root CA**: The trust anchor. Kept offline in real deployments.
- **Intermediate CA**: Signs end-entity certificates. Limits Root CA exposure.
- **Certificate chain**: Root → Intermediate → End-entity
- **Key usage extensions**: digitalSignature, keyCertSign, cRLSign
- **Validity periods**: Root (10yr), Intermediate (5yr), Server (1yr)

## Steps

### 1. Run the Setup Script
```bash
bash pki-lab/setup_ca.sh
```
This creates the full CA directory structure and generates both CA certificates.

### 2. Inspect the Root CA Certificate
```bash
openssl x509 -in pki-lab/ca/root-ca/certs/ca.cert.pem -noout -text
```
Note:
- `CA:TRUE` in Basic Constraints
- `keyCertSign` in Key Usage
- 10-year validity

### 3. Verify the Certificate Chain
```bash
openssl verify -CAfile pki-lab/ca/root-ca/certs/ca.cert.pem \
  pki-lab/ca/intermediate-ca/certs/intermediate.cert.pem
```
Expected: `intermediate.cert.pem: OK`

### 4. Quiz Questions
1. Why is the Root CA kept offline in production?
2. What is `pathlen:0` in the Intermediate CA's Basic Constraints?
3. What happens if you revoke the Intermediate CA certificate?

## Security+ Exam Connection
- **3.9** — Given a scenario, implement public key infrastructure
- CA types: self-signed, root, intermediate, wildcard, SAN
- Trust models: hierarchical, web of trust, bridge CA
