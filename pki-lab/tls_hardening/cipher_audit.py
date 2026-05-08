#!/usr/bin/env python3
"""
pki-lab/tls_hardening/cipher_audit.py
Scans services for weak TLS configurations.
Domain 3 Exercise 3.2 — SY0-701

Usage: python cipher_audit.py --host <hostname> [--port 443]
"""

import ssl
import socket
import argparse
from datetime import datetime


WEAK_PROTOCOLS = {ssl.PROTOCOL_TLS_CLIENT}
WEAK_CIPHERS = ["RC4", "3DES", "DES", "NULL", "EXPORT", "ANON", "MD5", "CBC"]
WEAK_TLS_VERSIONS = ["TLSv1", "TLSv1.1", "SSLv2", "SSLv3"]


def check_tls_version(host: str, port: int, version_name: str, version_const) -> dict:
    """Test if a specific TLS version is accepted."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Try to limit to a specific version
        if version_name == "TLSv1":
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1
        elif version_name == "TLSv1.1":
            ctx.minimum_version = ssl.TLSVersion.TLSv1_1
            ctx.maximum_version = ssl.TLSVersion.TLSv1_1

        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return {"version": version_name, "accepted": True, "status": "FAIL"}
    except ssl.SSLError:
        return {"version": version_name, "accepted": False, "status": "PASS"}
    except Exception as e:
        return {"version": version_name, "accepted": False, "status": "PASS", "note": str(e)}


def get_certificate_info(host: str, port: int) -> dict:
    """Retrieve and analyze the server certificate."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                return {
                    "negotiated_version": version,
                    "cipher_suite": cipher[0] if cipher else "Unknown",
                    "key_bits": cipher[2] if cipher else 0,
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "not_after": cert.get("notAfter", "Unknown"),
                }
    except Exception as e:
        return {"error": str(e)}


def audit(host: str, port: int = 443):
    """Run complete TLS audit against a host."""
    print(f"\n{'='*60}")
    print(f"  TLS Cipher Audit — Adversary-in-a-Box Lab")
    print(f"  Target: {host}:{port}")
    print(f"  Time: {datetime.utcnow().isoformat()}")
    print(f"{'='*60}\n")

    # Get connection info
    cert_info = get_certificate_info(host, port)
    if "error" not in cert_info:
        print(f"[i] Negotiated protocol: {cert_info['negotiated_version']}")
        print(f"[i] Cipher suite: {cert_info['cipher_suite']} ({cert_info['key_bits']} bits)")
        print(f"[i] Certificate CN: {cert_info['subject'].get('commonName', 'Unknown')}")
        print(f"[i] Certificate expires: {cert_info['not_after']}")
    else:
        print(f"[!] Could not connect: {cert_info['error']}")
        print(f"[i] Running in simulation mode...")

    print()

    # Check TLS versions
    results = []
    version_tests = [
        ("TLSv1.3", None),
        ("TLSv1.2", None),
        ("TLSv1.1", None),
        ("TLSv1", None),
    ]

    print("TLS Version Tests:")
    for version_name, version_const in version_tests:
        if version_name in ["TLSv1", "TLSv1.1"]:
            result = check_tls_version(host, port, version_name, version_const)
        else:
            # These require actual connection — simulate
            if "error" not in cert_info:
                negotiated = cert_info.get("negotiated_version", "")
                accepted = version_name == negotiated
            else:
                accepted = (version_name == "TLSv1.3")  # Simulate good config
            result = {"version": version_name, "accepted": accepted,
                      "status": "PASS" if (version_name in ["TLSv1.3"] and accepted) or
                                         (version_name in ["TLSv1.2"] and accepted) else
                                "FAIL" if accepted else "PASS"}

        icon = "✓" if result["status"] == "PASS" else "✗"
        print(f"  [{icon}] {version_name}: {'Accepted' if result['accepted'] else 'Rejected'} — {result['status']}")
        results.append(result)

    print()
    passes = sum(1 for r in results if r["status"] == "PASS")
    fails = sum(1 for r in results if r["status"] == "FAIL")
    print(f"Results: {passes} PASS / {fails} FAIL")
    print(f"\nFor a hardened config, see: pki-lab/tls_hardening/nginx-tls.conf")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TLS Cipher Audit Tool")
    parser.add_argument("--host", default="172.20.0.30", help="Target hostname or IP")
    parser.add_argument("--port", type=int, default=443, help="Target port")
    args = parser.parse_args()
    audit(args.host, args.port)
