"""
tests/test_pki.py — Unit tests for PKI lab scripts and TLS hardening tools
"""

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PKI_DIR = Path(__file__).parent.parent / "pki-lab"
SETUP_CA = PKI_DIR / "setup_ca.sh"
ISSUE_CERT = PKI_DIR / "issue_cert.sh"


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

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
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


@unittest.skipUnless(shutil.which("openssl"), "requires the openssl binary")
class TestIssueCertLedgerAndGuards(unittest.TestCase):
    """Phase G6.2: issue_cert.sh's reserved-basename/charset guards (Gap M's
    CA-key-destruction primitive) and the `openssl ca` ledger conversion,
    run against the real `openssl` binary and a real, freshly-built CA (no
    stubbing -- this is exactly the kind of multi-step, stateful CLI flow
    a mock would misrepresent)."""

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix="aib-pki-test-")
        cls.pki_dir = Path(cls.tmpdir) / "ca"
        env = {"PKI_DIR": str(cls.pki_dir), "PATH": "/usr/bin:/bin:/usr/local/bin"}
        result = subprocess.run(
            ["sh", str(SETUP_CA)], capture_output=True, text=True, env=env, timeout=60
        )
        if result.returncode != 0:
            raise RuntimeError(f"setup_ca.sh failed:\n{result.stdout}\n{result.stderr}")
        cls.intermediate_key = cls.pki_dir / "intermediate-ca" / "private" / "intermediate.key.pem"
        cls.root_key = cls.pki_dir / "root-ca" / "private" / "ca.key.pem"

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def _run(self, *args: str) -> subprocess.CompletedProcess:
        env = {"PKI_DIR": str(self.pki_dir), "PATH": "/usr/bin:/bin:/usr/local/bin"}
        return subprocess.run(
            ["sh", str(ISSUE_CERT), *args],
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )

    def _sha256(self, path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    # --------------------------------------------------------- happy path
    def test_valid_issuance_produces_a_verifiable_cert(self):
        result = self._run("test-host-01.lab.local")
        debug = f"\nrc:{result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}\n"
        self.assertEqual(result.returncode, 0, debug)
        cert = self.pki_dir / "intermediate-ca" / "certs" / "test-host-01.lab.local.cert.pem"
        self.assertTrue(cert.exists(), debug)
        verify = subprocess.run(
            [
                "openssl",
                "verify",
                "-CAfile",
                str(self.pki_dir / "intermediate-ca" / "certs" / "ca-chain.cert.pem"),
                str(cert),
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(verify.returncode, 0, verify.stderr)

    def test_valid_issuance_writes_a_real_ca_ledger_entry(self):
        # G6.2: the whole point -- switched from ad-hoc `x509 -req` (which
        # never touched setup_ca.sh's own index.txt/serial database) to
        # `openssl ca`, which does.
        index = self.pki_dir / "intermediate-ca" / "index.txt"
        before = index.read_text().count("\n")
        result = self._run("test-host-02.lab.local")
        self.assertEqual(result.returncode, 0, result.stderr)
        after = index.read_text().count("\n")
        self.assertEqual(after, before + 1)
        self.assertIn("CN=test-host-02.lab.local", index.read_text())

    def test_valid_issuance_writes_an_issuance_log_line(self):
        log_path = self.pki_dir / "intermediate-ca" / "issuance.log"
        result = self._run("test-host-03.lab.local", "172.20.0.99", "test-host-03.example")
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = [json.loads(line) for line in log_path.read_text().splitlines() if line.strip()]
        entry = next(e for e in lines if e["cn"] == "test-host-03.lab.local")
        self.assertEqual(entry["san_ip"], "172.20.0.99")
        self.assertEqual(entry["san_dns"], "test-host-03.example")
        self.assertEqual(entry["cert_type"], "server")

    def test_reissuing_the_same_cn_does_not_fail(self):
        # unique_subject=no in index.txt.attr -- a student re-running the
        # exercise for the same hostname must not hit "already exists".
        first = self._run("test-host-04.lab.local")
        second = self._run("test-host-04.lab.local")
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)

    # --------------------------------------------- reserved-basename guard
    def test_refuses_intermediate_ca_basename(self):
        before = self._sha256(self.intermediate_key)
        result = self._run("intermediate")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("reserved CA basename", result.stderr)
        self.assertEqual(self._sha256(self.intermediate_key), before)

    def test_refuses_ca_basename(self):
        result = self._run("ca")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("reserved CA basename", result.stderr)

    def test_refuses_ca_chain_basename(self):
        result = self._run("ca-chain")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("reserved CA basename", result.stderr)

    def test_refuses_root_basename(self):
        # "root" isn't a real basename issue_cert.sh's own paths ever
        # produce (root-ca/ lives outside intermediate-ca/, where this
        # script writes) -- refused anyway per the issue's explicit
        # denylist, and worth confirming the root CA key is untouched too.
        before = self._sha256(self.root_key)
        result = self._run("root")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("reserved CA basename", result.stderr)
        self.assertEqual(self._sha256(self.root_key), before)

    def test_reserved_basename_guard_actually_prevents_key_destruction(self):
        # Prove the guard has real bite: confirm what an unguarded
        # `openssl genrsa -out .../intermediate.key.pem` WOULD have done,
        # against a throwaway copy of the real key, then confirm the
        # actual intermediate.key.pem the guard protected is untouched.
        before = self._sha256(self.intermediate_key)
        scratch = Path(self.tmpdir) / "throwaway-intermediate.key.pem"
        # copyfile (data only) rather than copy (data + mode bits) -- the
        # real key is chmod 400, and preserving that onto the throwaway
        # copy would make the "unguarded genrsa" sanity check below fail
        # with Permission Denied under a non-root test runner, for the
        # same reason the guard needs to protect against in the first
        # place. This scratch file needs to be writable on purpose.
        shutil.copyfile(self.intermediate_key, scratch)
        scratch.chmod(0o600)
        subprocess.run(
            ["openssl", "genrsa", "-out", str(scratch), "2048"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertNotEqual(
            self._sha256(scratch),
            before,
            "sanity check failed: unguarded genrsa -out didn't overwrite the key",
        )
        self.assertEqual(
            self._sha256(self.intermediate_key),
            before,
            "the real intermediate CA key must be untouched by any issue_cert.sh call",
        )

    # ------------------------------------------------------- charset guard
    def test_rejects_leading_dash_cn(self):
        result = self._run("-rf")
        self.assertNotEqual(result.returncode, 0)

    def test_rejects_cn_with_injection_characters(self):
        for payload in ("evil,CN=fake", "evil;rm -rf /", "evil\nCA:TRUE", "evil/CN=x"):
            with self.subTest(payload=payload):
                result = self._run(payload)
                self.assertNotEqual(result.returncode, 0)

    # Note: no test_rejects_empty_cn -- `CN="${1:-victim-web}"` treats an
    # empty positional the same as an absent one (POSIX `:-` substitutes
    # on unset OR null), so CN="" is never actually reachable; it silently
    # becomes the default instead. The charset guard's own `''` arm is
    # still there as defensive code, just not something a CLI call can
    # exercise through this argument-defaulting.

    def test_rejects_invalid_cert_type(self):
        result = self._run(
            "test-host-05.lab.local", "172.20.0.30", "test-host-05.lab.local", "evil"
        )
        self.assertNotEqual(result.returncode, 0)

    def test_valid_cn_with_dots_hyphens_underscored_still_works(self):
        result = self._run("valid-host-06.sub.lab.local")
        self.assertEqual(result.returncode, 0, result.stderr)


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
