"""
tests/test_pki.py — Unit tests for PKI lab scripts and TLS hardening tools
"""
import sys
import os
import ssl
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

PKI_DIR = Path(__file__).parent.parent / "pki-lab"


class TestCipherAudit(unittest.TestCase):
    """Tests for the TLS cipher audit tool."""

    def setUp(self):
        sys.path.insert(0, str(PKI_DIR / "tls_hardening"))

    def test_cipher_audit_module_imports(self):
        import cipher_audit
        self.assertTrue(hasattr(cipher_audit, "audit"))
        self.assertTrue(hasattr(cipher_audit, "get_certificate_info"))

    def test_get_cert_info_handles_connection_error(self):
        import cipher_audit
        # Should return error dict, not raise
        result = cipher_audit.get_certificate_info("nonexistent.lab.local", 443)
        self.assertIn("error", result)

    def test_check_tls_version_returns_dict(self):
        import cipher_audit
        result = cipher_audit.check_tls_version("nonexistent.lab.local", 443, "TLSv1", None)
        self.assertIn("version", result)
        self.assertIn("status", result)
        self.assertIn("accepted", result)

    def test_weak_ciphers_list_is_defined(self):
        import cipher_audit
        self.assertIsInstance(cipher_audit.WEAK_CIPHERS, list)
        self.assertIn("RC4", cipher_audit.WEAK_CIPHERS)
        self.assertIn("3DES", cipher_audit.WEAK_CIPHERS)
        self.assertIn("NULL", cipher_audit.WEAK_CIPHERS)


class TestChainOfCustody(unittest.TestCase):
    """Tests for the forensic chain of custody script."""

    def setUp(self):
        sys.path.insert(0, str(Path(__file__).parent.parent / "forensics"))

    def test_sha256_file_produces_correct_hash(self):
        from chain_of_custody import sha256_file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("test content for hashing")
            path = Path(f.name)

        expected = hashlib.sha256(b"test content for hashing").hexdigest()
        result = sha256_file(path)
        path.unlink()
        self.assertEqual(result, expected)

    def test_hash_directory_creates_manifest(self):
        from chain_of_custody import hash_directory
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test files
            p = Path(tmpdir)
            (p / "test1.txt").write_text("file one content")
            (p / "test2.json").write_text('{"key": "value"}')
            subdir = p / "subdir"
            subdir.mkdir()
            (subdir / "nested.log").write_text("nested file")

            manifest = hash_directory(p)

        self.assertIn("files", manifest)
        self.assertIn("algorithm", manifest)
        self.assertIn("timestamp", manifest)
        self.assertEqual(manifest["algorithm"], "SHA-256")
        self.assertEqual(manifest["total_files"], 3)

    def test_manifest_file_entries_have_sha256(self):
        from chain_of_custody import hash_directory
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir)
            (p / "evidence.txt").write_text("some evidence data")
            manifest = hash_directory(p)

        for entry in manifest["files"]:
            self.assertIn("sha256", entry)
            self.assertEqual(len(entry["sha256"]), 64)
            self.assertIn("path", entry)
            self.assertIn("size_bytes", entry)

    def test_verify_detects_tampered_file(self):
        from chain_of_custody import hash_directory, verify_manifest
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir)
            evidence_file = p / "evidence.txt"
            evidence_file.write_text("original content")

            # Create manifest
            manifest = hash_directory(p)
            custody_path = p / "custody.json"
            with open(custody_path, "w") as f:
                json.dump(manifest, f)

            # Tamper with file
            evidence_file.write_text("TAMPERED CONTENT")

            # Verify should return False
            result = verify_manifest(custody_path)
            self.assertFalse(result)

    def test_verify_passes_for_intact_files(self):
        from chain_of_custody import hash_directory, verify_manifest
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir)
            (p / "evidence.txt").write_text("original content — untampered")

            manifest = hash_directory(p)
            custody_path = p / "custody.json"
            with open(custody_path, "w") as f:
                json.dump(manifest, f)

            result = verify_manifest(custody_path)
            self.assertTrue(result)


class TestPKIScripts(unittest.TestCase):
    """Tests that PKI shell scripts exist and have valid content."""

    def test_setup_ca_script_exists(self):
        script = PKI_DIR / "setup_ca.sh"
        self.assertTrue(script.exists(), "setup_ca.sh not found")

    def test_issue_cert_script_exists(self):
        script = PKI_DIR / "issue_cert.sh"
        self.assertTrue(script.exists(), "issue_cert.sh not found")

    def test_setup_ca_contains_root_ca_creation(self):
        content = (PKI_DIR / "setup_ca.sh").read_text()
        self.assertIn("genrsa", content)
        self.assertIn("Root CA", content)
        self.assertIn("Intermediate CA", content)

    def test_issue_cert_contains_san_support(self):
        content = (PKI_DIR / "issue_cert.sh").read_text()
        self.assertIn("subjectAltName", content)
        self.assertIn("openssl", content)

    def test_nginx_tls_config_has_tls13_only(self):
        config = (PKI_DIR / "tls_hardening" / "nginx-tls.conf").read_text()
        self.assertIn("TLSv1.3", config)
        self.assertNotIn("TLSv1.0", config)
        self.assertIn("ssl_stapling on", config)
        self.assertIn("Strict-Transport-Security", config)

    def test_pki_exercises_exist(self):
        exercises = ["01-build-your-ca.md", "02-issue-and-revoke.md", "03-pinning-and-stapling.md"]
        for ex in exercises:
            path = PKI_DIR / "exercises" / ex
            self.assertTrue(path.exists(), f"Exercise missing: {ex}")

    def test_pki_exercises_contain_exam_references(self):
        exercises_dir = PKI_DIR / "exercises"
        for ex_file in exercises_dir.glob("*.md"):
            content = ex_file.read_text()
            self.assertIn("Security+", content, f"{ex_file.name} missing Security+ reference")
            self.assertIn("3.9", content, f"{ex_file.name} missing objective 3.9 reference")


if __name__ == "__main__":
    unittest.main(verbosity=2)
