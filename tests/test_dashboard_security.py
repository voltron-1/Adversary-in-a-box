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
from unittest import mock

ROOT = Path(__file__).parent.parent
BLUE_APP = ROOT / "blue-team" / "dashboard" / "app.py"
SCORE_APP = ROOT / "forensics" / "scoreboard" / "app.py"
SCORE_DIR = ROOT / "forensics" / "scoreboard"

STRONG_KEY = "x7f2" * 12  # 48 chars, not in the insecure denylist


def _load(module_name, path, env, extra_path=None):
    """Load a module fresh with a controlled environment.

    Env is applied via mock.patch.dict, which snapshots os.environ and restores
    it exactly on exit -- including if exec_module raises. This is safer than a
    manual clear()/update() in a finally (which loses concurrent edits and
    leaves a half-applied env if the snapshot/restore is interrupted). Keys
    whose requested value is None are removed for the duration of the load.
    """
    overrides = {k: v for k, v in env.items() if v is not None}
    remove = [k for k, v in env.items() if v is None]
    sys.modules.pop(module_name, None)
    added_path = False
    with mock.patch.dict(os.environ, overrides):
        for key in remove:
            os.environ.pop(key, None)
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
            # Don't leave a half-initialized module registered if exec_module
            # raised (e.g. a bad SECRET_KEY): drop the name so the next load
            # starts clean.
            sys.modules.pop(module_name, None)


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


class TestAwardAuth(unittest.TestCase):
    """#143: POST /api/award is an instructor-only, state-changing endpoint.
    It must require SCOREBOARD_AUTH_TOKEN (same pattern as the playbook runner),
    fail closed when unset, and never 500 on a malformed body."""

    def _client(self, token_env):
        env = {"SECRET_KEY": STRONG_KEY}
        env.update(token_env)
        mod = _load("score_app", SCORE_APP, env, extra_path=SCORE_DIR)
        return mod.app.test_client()

    def _award_body(self):
        return {"team": "red_team", "event": "extra_credit_red", "detail": "x"}

    def test_no_auth_header_rejected(self):
        # Endpoint configured, but the caller presents no token.
        client = self._client({"SCOREBOARD_AUTH_TOKEN": "s3cret-token"})
        resp = client.post("/api/award", json=self._award_body())
        self.assertEqual(resp.status_code, 401)

    def test_token_env_absent_disables_endpoint(self):
        # Distinct from set-to-empty: the env var is not present at all
        # (_load pops it). Must still fail closed.
        client = self._client({"SCOREBOARD_AUTH_TOKEN": None})
        resp = client.post(
            "/api/award", json=self._award_body(), headers={"X-Auth-Token": "anything"}
        )
        self.assertEqual(resp.status_code, 401)

    def test_wrong_token_rejected(self):
        client = self._client({"SCOREBOARD_AUTH_TOKEN": "s3cret-token"})
        resp = client.post("/api/award", json=self._award_body(), headers={"X-Auth-Token": "wrong"})
        self.assertEqual(resp.status_code, 401)

    def test_correct_token_awards(self):
        client = self._client({"SCOREBOARD_AUTH_TOKEN": "s3cret-token"})
        resp = client.post(
            "/api/award",
            json=self._award_body(),
            headers={"X-Auth-Token": "s3cret-token"},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["awarded"], 10)

    def test_bearer_token_accepted(self):
        # The award route is deterministic post-auth (200 or 400, never 500),
        # so pin the full happy path for the Bearer scheme rather than just !=401.
        client = self._client({"SCOREBOARD_AUTH_TOKEN": "s3cret-token"})
        resp = client.post(
            "/api/award",
            json=self._award_body(),
            headers={"Authorization": "Bearer s3cret-token"},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["awarded"], 10)

    def test_disabled_when_no_token_configured(self):
        # Fail closed: no token configured -> endpoint disabled.
        client = self._client({"SCOREBOARD_AUTH_TOKEN": ""})
        resp = client.post(
            "/api/award", json=self._award_body(), headers={"X-Auth-Token": "anything"}
        )
        self.assertEqual(resp.status_code, 401)

    def test_default_placeholder_token_disables_endpoint(self):
        default = "adversary-in-a-box-lab-secret-key-change-me"
        client = self._client({"SCOREBOARD_AUTH_TOKEN": default})
        resp = client.post("/api/award", json=self._award_body(), headers={"X-Auth-Token": default})
        self.assertEqual(resp.status_code, 401)

    def test_invalid_event_rejected_when_authed(self):
        client = self._client({"SCOREBOARD_AUTH_TOKEN": "s3cret-token"})
        resp = client.post(
            "/api/award",
            json={"team": "red_team", "event": "not_a_rule"},
            headers={"X-Auth-Token": "s3cret-token"},
        )
        self.assertEqual(resp.status_code, 400)

    def test_malformed_body_does_not_500(self):
        client = self._client({"SCOREBOARD_AUTH_TOKEN": "s3cret-token"})
        resp = client.post(
            "/api/award",
            data="not json",
            content_type="text/plain",
            headers={"X-Auth-Token": "s3cret-token"},
        )
        self.assertEqual(resp.status_code, 400)

    def test_garbled_json_body_does_not_500(self):
        # Content-Type says JSON but the body is invalid JSON: get_json(silent=True)
        # returns None, the `or {}` guard absorbs it -> clean 400, not a 500.
        client = self._client({"SCOREBOARD_AUTH_TOKEN": "s3cret-token"})
        resp = client.post(
            "/api/award",
            data="{broken",
            content_type="application/json",
            headers={"X-Auth-Token": "s3cret-token"},
        )
        self.assertEqual(resp.status_code, 400)


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


class TestInsecureKeyDenylistSync(unittest.TestCase):
    """#146: the dashboard and scoreboard apps build from separate Docker
    contexts and cannot share a Python import, so INSECURE_SECRET_KEYS is
    duplicated. This guard fails CI if the two copies drift apart or if a
    committed .env.example placeholder is missing from either copy."""

    def _denylist(self, name, path, extra_path=None):
        mod = _load(name, path, {"SECRET_KEY": STRONG_KEY}, extra_path=extra_path)
        return set(mod.INSECURE_SECRET_KEYS)

    def _committed_placeholders(self):
        # The literal values assigned to the secret/token vars in .env.example.
        wanted = ("FLASK_SECRET_KEY", "PLAYBOOK_AUTH_TOKEN", "SCOREBOARD_AUTH_TOKEN")
        values = set()
        for line in (ROOT / ".env.example").read_text().splitlines():
            line = line.strip()
            if line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            if key.strip() in wanted and value.strip():
                values.add(value.strip())
        return values

    def test_denylists_are_identical(self):
        blue = self._denylist("blue_dash_app", BLUE_APP)
        score = self._denylist("score_app_sync", SCORE_APP, extra_path=SCORE_DIR)
        self.assertEqual(blue, score)

    def test_denylists_cover_env_example_placeholders(self):
        placeholders = self._committed_placeholders()
        self.assertTrue(placeholders, "no placeholders parsed from .env.example")
        blue = self._denylist("blue_dash_app", BLUE_APP)
        score = self._denylist("score_app_sync", SCORE_APP, extra_path=SCORE_DIR)
        self.assertTrue(placeholders <= blue, placeholders - blue)
        self.assertTrue(placeholders <= score, placeholders - score)


class TestPlaybookContextValidation(unittest.TestCase):
    """#144: the operator-supplied `context` is .format()'d into argv for
    privileged IR scripts. Validate it at the trust boundary: dict only,
    whitelisted keys, string values, IPs where an IP is expected, and no
    shell/format metacharacters in host/id values."""

    def _module(self):
        return _load("blue_dash_app", BLUE_APP, {"SECRET_KEY": STRONG_KEY})

    def _client(self):
        env = {"SECRET_KEY": STRONG_KEY, "PLAYBOOK_AUTH_TOKEN": "s3cret-token"}
        return _load("blue_dash_app", BLUE_APP, env).app.test_client()

    # --- the validator, unit-tested directly (fast, no engine side effects) ---

    def test_none_context_becomes_empty_dict(self):
        mod = self._module()
        self.assertEqual(mod._validate_context(None), {})

    def test_non_dict_context_raises(self):
        mod = self._module()
        for bad in ("a string", 123, ["list"], True):
            with self.assertRaises(ValueError):
                mod._validate_context(bad)

    def test_unknown_key_raises(self):
        mod = self._module()
        with self.assertRaises(ValueError):
            mod._validate_context({"evil_key": "x"})

    def test_non_string_value_raises(self):
        mod = self._module()
        with self.assertRaises(ValueError):
            mod._validate_context({"affected_host": 1234})

    def test_invalid_ip_value_raises(self):
        mod = self._module()
        with self.assertRaises(ValueError):
            mod._validate_context({"attacker_ip": "not-an-ip"})

    def test_injection_chars_in_host_raises(self):
        mod = self._module()
        for payload in ("victim; rm -rf /", "a b", "{evil}", "$(id)", "a|b"):
            with self.assertRaises(ValueError):
                mod._validate_context({"affected_host": payload})

    def test_leading_hyphen_host_rejected(self):
        # secaudit MEDIUM: a value starting with '-' is otherwise charset-valid
        # but reaches docker/bash argv as a flag (argument injection, CWE-88).
        mod = self._module()
        for payload in ("--help", "-D", "-rf"):
            with self.assertRaises(ValueError):
                mod._validate_context({"affected_host": payload})

    def test_valid_context_passes_through(self):
        mod = self._module()
        ctx = {
            "campaign_id": "kc-2026-06-24",
            "affected_host": "victim-web",
            "attacker_ip": "172.20.0.10",
            "c2_ip": "10.0.0.5",
            "pivot_host": "victim-db",
            "source_host": "victim-web",
        }
        self.assertEqual(mod._validate_context(ctx), ctx)

    # --- and through the route: a bad context is a 400, never reaches engine ---

    def test_route_rejects_non_dict_context(self):
        client = self._client()
        resp = client.post(
            "/api/run-playbook",
            json={"playbook_id": "phishing_ir", "context": "bad"},
            headers={"X-Auth-Token": "s3cret-token"},
        )
        self.assertEqual(resp.status_code, 400)

    def test_route_rejects_injection_context(self):
        client = self._client()
        resp = client.post(
            "/api/run-playbook",
            json={
                "playbook_id": "phishing_ir",
                "context": {"affected_host": "x; reboot"},
            },
            headers={"X-Auth-Token": "s3cret-token"},
        )
        self.assertEqual(resp.status_code, 400)


if __name__ == "__main__":
    unittest.main()
