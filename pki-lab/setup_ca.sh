#!/bin/bash
# pki-lab/setup_ca.sh — Build a two-tier PKI with OpenSSL
# Domain 3 Exercise: Certificate Authority setup (SY0-701 Objective 3.9)

set -euo pipefail

PKI_DIR="${PKI_DIR:-./pki-lab/ca}"
COUNTRY="${COUNTRY:-US}"
STATE="${STATE:-Lab State}"
ORG="${ORG:-Adversary-in-a-Box Lab}"

echo "=============================================="
echo "  Adversary-in-a-Box PKI Lab Setup"
echo "  SY0-701 Domain 3 — PKI & Cryptography"
echo "=============================================="

# Create directory structure
# POSIX sh: no brace expansion, so iterate (audit-4 G3a -- this script is
# now run by the pki-init one-shot under alpine `sh`, not just bash).
for _ca in root-ca intermediate-ca; do
    for _sub in certs crl newcerts private; do
        mkdir -p "$PKI_DIR/$_ca/$_sub"
    done
done
chmod 700 "$PKI_DIR"/root-ca/private "$PKI_DIR"/intermediate-ca/private
touch "$PKI_DIR"/root-ca/index.txt "$PKI_DIR"/intermediate-ca/index.txt
echo 1000 > "$PKI_DIR"/root-ca/serial
echo 1000 > "$PKI_DIR"/intermediate-ca/serial
echo 1000 > "$PKI_DIR"/root-ca/crlnumber
echo 1000 > "$PKI_DIR"/intermediate-ca/crlnumber

echo "[+] Directory structure created: $PKI_DIR"

# Step 1: Generate Root CA private key (RSA 4096)
echo "[+] Generating Root CA private key (RSA 4096)..."
openssl genrsa -out "$PKI_DIR/root-ca/private/ca.key.pem" 4096
chmod 400 "$PKI_DIR/root-ca/private/ca.key.pem"

# Step 2: Self-sign Root CA certificate (10 years)
echo "[+] Creating self-signed Root CA certificate..."
ROOT_CONF=$(mktemp)
cat > "$ROOT_CONF" <<EOF
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no

[dn]
C = $COUNTRY
ST = $STATE
O = $ORG
CN = Lab Root CA

[v3_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
EOF
openssl req -config "$ROOT_CONF" \
    -key "$PKI_DIR/root-ca/private/ca.key.pem" \
    -new -x509 -days 3650 \
    -out "$PKI_DIR/root-ca/certs/ca.cert.pem"
rm -f "$ROOT_CONF"

echo "[✓] Root CA certificate created"

# Step 3: Generate Intermediate CA private key
echo "[+] Generating Intermediate CA private key (RSA 4096)..."
openssl genrsa -out "$PKI_DIR/intermediate-ca/private/intermediate.key.pem" 4096
chmod 400 "$PKI_DIR/intermediate-ca/private/intermediate.key.pem"

# Step 4: Create Intermediate CA CSR
echo "[+] Creating Intermediate CA CSR..."
openssl req -new \
    -key "$PKI_DIR/intermediate-ca/private/intermediate.key.pem" \
    -out "$PKI_DIR/intermediate-ca/certs/intermediate.csr.pem" \
    -subj "/C=$COUNTRY/ST=$STATE/O=$ORG/CN=Lab Intermediate CA"

# Step 5: Sign Intermediate CA with Root CA
echo "[+] Signing Intermediate CA with Root CA..."
INT_EXT=$(mktemp)
cat > "$INT_EXT" <<EOF
[v3_ca]
basicConstraints = critical,CA:TRUE,pathlen:0
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
EOF
openssl x509 -req \
    -in "$PKI_DIR/intermediate-ca/certs/intermediate.csr.pem" \
    -CA "$PKI_DIR/root-ca/certs/ca.cert.pem" \
    -CAkey "$PKI_DIR/root-ca/private/ca.key.pem" \
    -CAcreateserial \
    -out "$PKI_DIR/intermediate-ca/certs/intermediate.cert.pem" \
    -days 1825 \
    -extensions v3_ca \
    -extfile "$INT_EXT"
rm -f "$INT_EXT"

# Step 6: Create certificate chain
cat "$PKI_DIR/intermediate-ca/certs/intermediate.cert.pem" \
    "$PKI_DIR/root-ca/certs/ca.cert.pem" \
    > "$PKI_DIR/intermediate-ca/certs/ca-chain.cert.pem"

echo ""
echo "=============================================="
echo "  PKI Setup Complete!"
echo "=============================================="
echo "  Root CA:         $PKI_DIR/root-ca/certs/ca.cert.pem"
echo "  Intermediate CA: $PKI_DIR/intermediate-ca/certs/intermediate.cert.pem"
echo "  Chain:           $PKI_DIR/intermediate-ca/certs/ca-chain.cert.pem"
echo ""
echo "  Next: bash pki-lab/issue_cert.sh <hostname> <ip>"
echo "=============================================="

# Verify the chain
echo "[+] Verifying certificate chain..."
openssl verify -CAfile "$PKI_DIR/root-ca/certs/ca.cert.pem" \
    "$PKI_DIR/intermediate-ca/certs/intermediate.cert.pem" && \
    echo "[✓] Certificate chain verified successfully"
