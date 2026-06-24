"""
tests/test_dashboard_security.py — Wave 2 / P6 (S5)

Locks in the IR-dashboard hardening:
  * both Flask apps refuse to boot on an unset / known-default SECRET_KEY
  * the blue-team playbook runner (POST /api/run-playbook) requires a token
    and fails closed when no token is configured.

Each app file is named app.py, so they are loaded under unique module names
via importlib to avoid a sys.modules collision.
"""

import importlib.util
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).parent.parent
BLUE_APP = ROOT / "blue-team" / "dashboard" / "app.py"
SCORE_APP = ROOT / "forensics" / "scoreboard" / "app.py"
SCORE_DIR = ROOT / "forensics" / "scoreboard"

STRONG_KEY = "x7f2" * 12  # 48 chars, not in the insecure denylist


def _load(module_name, path, env, extra_path=None):
    """Load a module fresh with a controlled environment."""
    saved_env = dict(os.environ)
    # Apply env: keys with value None are removed.
    for key, value in env.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    sys.modules.pop(module_name, None)
    added_path = False
    try:
        if extra_path:
            sys.path.insert(0, str(extra_path))
            added_path = True
        spec = importlib.util.spec_from_file_location(module_name, path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = mod
        spec.loader.exec_module(mod)
        return mod
    finally:
        if added_path:
            sys.path.remove(str(extra_path))
        os.environ.clear()
        os.environ.update(saved_env)


class TestSecretKeyEnforcement(unittest.TestCase):
    def test_blue_rejects_default_secret(self):
        with self.assertRaises(RuntimeError):
            _load("blue_dash_app", BLUE_APP, {"SECRET_KEY": "lab-secret-key"})

    def test_blue_rejects_unset_secret(self):
        with self.assertRaises(RuntimeError):
            _load("blue_dash_app", BLUE_APP, {"SECRET_KEY": None})

    def test_blue_rejects_default_with_surrounding_whitespace(self):
        # The guard must strip before checking the denylist.
        with self.assertRaises(RuntimeError):
            _load("blue_dash_app", BLUE_APP, {"SECRET_KEY": "  lab-secret-key  "})

    def test_blue_rejects_compose_default(self):
        with self.assertRaises(RuntimeError):
            _load("blue_dash_app", BLUE_APP, {"SECRET_KEY": "lab-secret-change-me"})

    def test_blue_accepts_strong_secret(self):
        mod = _load(
            "blue_dash_app",
            BLUE_APP,
            {"SECRET_KEY": STRONG_KEY, "PLAYBOOK_AUTH_TOKEN": "tok"},
        )
        self.assertEqual(mod.app.secret_key, STRONG_KEY)

    def test_scoreboard_rejects_default_secret(self):
        with self.assertRaises(RuntimeError):
            _load(
                "score_app",
                SCORE_APP,
                {"SECRET_KEY": "scoreboard-secret"},
                extra_path=SCORE_DIR,
            )

    def test_scoreboard_accepts_strong_secret(self):
        mod = _load(
            "score_app",
            SCORE_APP,
            {"SECRET_KEY": STRONG_KEY},
            extra_path=SCORE_DIR,
        )
        self.assertEqual(mod.app.secret_key, STRONG_KEY)


class TestPlaybookAuth(unittest.TestCase):
    def _client(self, token_env):
        env = {"SECRET_KEY": STRONG_KEY}
        env.update(token_env)
        mod = _load("blue_dash_app", BLUE_APP, env)
        return mod.app.test_client()

    def test_missing_token_rejected(self):
        client = self._client({"PLAYBOOK_AUTH_TOKEN": "s3cret-token"})
        resp = client.post("/api/run-playbook", json={"playbook_id": "phishing_ir"})
        self.assertEqual(resp.status_code, 401)

    def test_wrong_token_rejected(self):
        client = self._client({"PLAYBOOK_AUTH_TOKEN": "s3cret-token"})
        resp = client.post(
            "/api/run-playbook",
            json={"playbook_id": "phishing_ir"},
            headers={"X-Auth-Token": "wrong"},
        )
        self.assertEqual(resp.status_code, 401)

    def test_correct_token_passes_auth(self):
        client = self._client({"PLAYBOOK_AUTH_TOKEN": "s3cret-token"})
        resp = client.post(
            "/api/run-playbook",
            json={"playbook_id": "phishing_ir"},
            headers={"X-Auth-Token": "s3cret-token"},
        )
        # Auth passed; engine may succeed or 500, but it must not be 401.
        self.assertNotEqual(resp.status_code, 401)

    def test_bearer_token_accepted(self):
        client = self._client({"PLAYBOOK_AUTH_TOKEN": "s3cret-token"})
        resp = client.post(
            "/api/run-playbook",
            json={"playbook_id": "phishing_ir"},
            headers={"Authorization": "Bearer s3cret-token"},
        )
        self.assertNotEqual(resp.status_code, 401)

    def test_disabled_when_no_token_configured(self):
        # Fail closed: no token configured -> endpoint disabled.
        client = self._client({"PLAYBOOK_AUTH_TOKEN": ""})
        resp = client.post(
            "/api/run-playbook",
            json={"playbook_id": "phishing_ir"},
            headers={"X-Auth-Token": "anything"},
        )
        self.assertEqual(resp.status_code, 401)

    def test_default_placeholder_token_disables_endpoint(self):
        # A token left at a committed default is treated as unset (fail closed),
        # so even presenting that exact value is rejected.
        default = "adversary-in-a-box-lab-secret-key-change-me"
        client = self._client({"PLAYBOOK_AUTH_TOKEN": default})
        resp = client.post(
            "/api/run-playbook",
            json={"playbook_id": "phishing_ir"},
            headers={"X-Auth-Token": default},
        )
        self.assertEqual(resp.status_code, 401)

    def test_unknown_playbook_id_rejected(self):
        # Authenticated, but the id is not in the PLAYBOOKS registry -> 400,
        # never reaching PlaybookEngine (path-traversal guard).
        client = self._client({"PLAYBOOK_AUTH_TOKEN": "s3cret-token"})
        resp = client.post(
            "/api/run-playbook",
            json={"playbook_id": "../../../etc/passwd"},
            headers={"X-Auth-Token": "s3cret-token"},
        )
        self.assertEqual(resp.status_code, 400)

    def test_malformed_body_does_not_500(self):
        client = self._client({"PLAYBOOK_AUTH_TOKEN": "s3cret-token"})
        resp = client.post(
            "/api/run-playbook",
            data="not json",
            content_type="text/plain",
            headers={"X-Auth-Token": "s3cret-token"},
        )
        self.assertEqual(resp.status_code, 400)


if __name__ == "__main__":
    unittest.main()
