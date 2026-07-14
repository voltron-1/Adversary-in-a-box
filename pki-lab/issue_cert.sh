#!/bin/bash
# pki-lab/issue_cert.sh — Issue a server or client certificate
# Usage: bash issue_cert.sh <common_name> [san_ip] [san_dns]

set -euo pipefail

CN="${1:-victim-web}"
SAN_IP="${2:-172.20.0.30}"
SAN_DNS="${3:-$CN.lab.local}"
PKI_DIR="${PKI_DIR:-./pki-lab/ca}"
CERT_TYPE="${4:-server}"  # server or client

echo "[+] Issuing $CERT_TYPE certificate for: $CN (IP: $SAN_IP)"

# Generate private key
openssl genrsa -out "$PKI_DIR/intermediate-ca/private/$CN.key.pem" 2048
chmod 400 "$PKI_DIR/intermediate-ca/private/$CN.key.pem"

# Create CSR
openssl req -new \
    -key "$PKI_DIR/intermediate-ca/private/$CN.key.pem" \
    -out "$PKI_DIR/intermediate-ca/certs/$CN.csr.pem" \
    -subj "/C=US/ST=Lab State/O=Adversary-in-a-Box Lab/CN=$CN"

# Create SAN extension config
EXT_FILE=$(mktemp)
cat > "$EXT_FILE" <<EOF
[ext]
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = $([ "$CERT_TYPE" = "client" ] && echo "clientAuth" || echo "serverAuth")
subjectAltName = IP:$SAN_IP, DNS:$SAN_DNS, DNS:$CN
EOF

# Sign with Intermediate CA
openssl x509 -req \
    -in "$PKI_DIR/intermediate-ca/certs/$CN.csr.pem" \
    -CA "$PKI_DIR/intermediate-ca/certs/intermediate.cert.pem" \
    -CAkey "$PKI_DIR/intermediate-ca/private/intermediate.key.pem" \
    -CAcreateserial \
    -out "$PKI_DIR/intermediate-ca/certs/$CN.cert.pem" \
    -days 365 \
    -extfile "$EXT_FILE" \
    -extensions ext

rm "$EXT_FILE"

echo "[✓] Certificate issued: $PKI_DIR/intermediate-ca/certs/$CN.cert.pem"
echo "[✓] Private key:        $PKI_DIR/intermediate-ca/private/$CN.key.pem"

# Verify
openssl verify \
    -CAfile "$PKI_DIR/intermediate-ca/certs/ca-chain.cert.pem" \
    "$PKI_DIR/intermediate-ca/certs/$CN.cert.pem" && \
    echo "[✓] Certificate verified against CA chain"

# Show cert details
echo ""
echo "[i] Certificate details:"
openssl x509 -in "$PKI_DIR/intermediate-ca/certs/$CN.cert.pem" \
    -noout -subject -issuer -dates -ext subjectAltName
