#!/bin/sh
# pki-lab/issue_cert.sh — Issue a server or client certificate
# Usage: sh issue_cert.sh <common_name> [san_ip] [san_dns] [cert_type]
#
# POSIX sh, not bash: this runs under alpine/openssl's `sh` in the
# pki-init/pki-ca services (docker-compose.yml), which invokes it as
# `sh issue_cert.sh ...` and ignores this file's own shebang -- no
# `[[ ]]`, no `=~`, no bash arrays anywhere in this script.

set -eu

CN="${1:-victim-web}"
SAN_IP="${2:-172.20.0.30}"
SAN_DNS="${3:-$CN.lab.local}"
PKI_DIR="${PKI_DIR:-./pki-lab/ca}"
CERT_TYPE="${4:-server}"  # server or client

# G6.2 (Gap M): $CN reaches openssl argv AND becomes the on-disk basename
# for the new key/cert/CSR -- a crafted CN of "intermediate" (or "ca" /
# "ca-chain" / "root") would overwrite the CA's own key material or the
# served chain file, destroying the whole PKI. Reject anything outside a
# safe hostname charset (this also blocks a leading '-' from being read
# as an openssl flag, CWE-88, and blocks any subject/SAN-extension-config
# injection character like '=', ',', or a newline) and refuse the CA's
# own reserved basenames, before $CN, $SAN_DNS, or $SAN_IP touches a
# single openssl invocation or file path.
validate_hostname_charset() {
    label="$1"
    value="$2"
    case "$value" in
        '' | -*)
            echo "[ERROR] invalid $label '$value': empty or starts with '-'" >&2
            exit 1
            ;;
        *[!A-Za-z0-9._-]*)
            echo "[ERROR] invalid $label '$value': must match [A-Za-z0-9._-]+, not starting with '-'" >&2
            exit 1
            ;;
    esac
    if [ "${#value}" -gt 253 ]; then
        echo "[ERROR] invalid $label '$value': longer than 253 characters" >&2
        exit 1
    fi
}

validate_hostname_charset "CN" "$CN"
validate_hostname_charset "SAN DNS name" "$SAN_DNS"

case "$CN" in
    ca | intermediate | ca-chain | root)
        echo "[ERROR] refusing to issue a certificate for reserved CA basename '$CN'" >&2
        exit 1
        ;;
esac

case "$SAN_IP" in
    '' | -*)
        echo "[ERROR] invalid SAN IP '$SAN_IP': empty or starts with '-'" >&2
        exit 1
        ;;
    *[!0-9.]*)
        echo "[ERROR] invalid SAN IP '$SAN_IP': must be a dotted-decimal IPv4 address" >&2
        exit 1
        ;;
esac

case "$CERT_TYPE" in
    server | client) ;;
    *)
        echo "[ERROR] invalid cert type '$CERT_TYPE': must be 'server' or 'client'" >&2
        exit 1
        ;;
esac

echo "[+] Issuing $CERT_TYPE certificate for: $CN (IP: $SAN_IP)"

INTERMEDIATE_DIR="$PKI_DIR/intermediate-ca"

# Generate private key
openssl genrsa -out "$INTERMEDIATE_DIR/private/$CN.key.pem" 2048
chmod 400 "$INTERMEDIATE_DIR/private/$CN.key.pem"

# Create CSR
openssl req -new \
    -key "$INTERMEDIATE_DIR/private/$CN.key.pem" \
    -out "$INTERMEDIATE_DIR/certs/$CN.csr.pem" \
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

# G6.2 (Gap M): sign via `openssl ca` against the intermediate CA's real
# index.txt/serial database (set up by setup_ca.sh) instead of the old
# ad-hoc `openssl x509 -req -CAcreateserial`, which never touched that
# database at all -- it existed but was completely unused, so there was
# no queryable record of what had ever been issued or to whom. `-batch`
# skips the interactive "commit?" prompt this non-interactive script
# can't answer.
CA_CONF=$(mktemp)
cat > "$CA_CONF" <<EOF
[ca]
default_ca = intermediate_ca

[intermediate_ca]
dir             = $INTERMEDIATE_DIR
database        = $INTERMEDIATE_DIR/index.txt
serial          = $INTERMEDIATE_DIR/serial
new_certs_dir   = $INTERMEDIATE_DIR/newcerts
certificate     = $INTERMEDIATE_DIR/certs/intermediate.cert.pem
private_key     = $INTERMEDIATE_DIR/private/intermediate.key.pem
default_md      = sha256
default_days    = 365
policy          = policy_loose
email_in_dn     = no

[policy_loose]
countryName             = optional
stateOrProvinceName     = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional
EOF

# `openssl ca` reads unique_subject from <database>.attr (NOT from the
# main config's CA section -- that key there is silently ignored). Set
# it up front so re-issuing the same CN across separate exercise runs
# doesn't hard-fail with "TXT_DB error: already exists".
if [ ! -f "$INTERMEDIATE_DIR/index.txt.attr" ]; then
    echo "unique_subject = no" > "$INTERMEDIATE_DIR/index.txt.attr"
fi

openssl ca -config "$CA_CONF" -batch \
    -in "$INTERMEDIATE_DIR/certs/$CN.csr.pem" \
    -out "$INTERMEDIATE_DIR/certs/$CN.cert.pem" \
    -days 365 \
    -extfile "$EXT_FILE" \
    -extensions ext

rm -f "$EXT_FILE" "$CA_CONF"

echo "[✓] Certificate issued: $INTERMEDIATE_DIR/certs/$CN.cert.pem"
echo "[✓] Private key:        $INTERMEDIATE_DIR/private/$CN.key.pem"
echo "[✓] Ledger entry:       $INTERMEDIATE_DIR/index.txt (openssl ca database)"

# G6.2 (Gap M): a local, verifiable issuance record independent of the
# openssl ca database's own semicolon-delimited format -- one JSON line
# per issuance, easy to grep/parse for an audit trail. issue_cert.sh runs
# in a minimal alpine/openssl container with no guaranteed network
# logging tool (busybox `logger` doesn't support a remote UDP
# destination the way GNU inetutils' does), so this stays local rather
# than attempting an unverifiable syslog delivery.
ISSUANCE_LOG="$INTERMEDIATE_DIR/issuance.log"
printf '{"timestamp":"%s","cn":"%s","cert_type":"%s","san_ip":"%s","san_dns":"%s"}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$CN" "$CERT_TYPE" "$SAN_IP" "$SAN_DNS" >> "$ISSUANCE_LOG"

# Verify
openssl verify \
    -CAfile "$INTERMEDIATE_DIR/certs/ca-chain.cert.pem" \
    "$INTERMEDIATE_DIR/certs/$CN.cert.pem" && \
    echo "[✓] Certificate verified against CA chain"

# Show cert details
echo ""
echo "[i] Certificate details:"
openssl x509 -in "$INTERMEDIATE_DIR/certs/$CN.cert.pem" \
    -noout -subject -issuer -dates -ext subjectAltName
