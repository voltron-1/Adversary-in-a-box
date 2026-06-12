"""
campaigns/impact/ransomware_sim.py -- T1486 Data Encrypted for Impact

MITRE ATT&CK: T1486 | Tactic: Impact

Phase B1d. Simulates ransomware on a fixed decoy directory:
  * Creates /tmp/ransom-decoys/ with a small set of plausible-looking
    docs (notes.txt, q4_report.docx, contacts.csv).
  * Renames each to <name>.locked (NO actual encryption).
  * Drops a ransom_note.txt explaining what would have happened.

Cleanup reverses every rename and removes the note. Drives the existing
ransomware_ir.yml playbook end-to-end without any data being at risk.
"""

import json
import os
from datetime import UTC, datetime

from campaigns.base_campaign import BaseCampaign


class RansomwareSimCampaign(BaseCampaign):
    TECHNIQUE_ID = "T1486"
    TECHNIQUE_NAME = "Data Encrypted for Impact"
    TACTIC = "Impact"

    DECOY_DIR = "/tmp/ransom-decoys"
    NOTE_FILENAME = "ransom_note.txt"
    LOCKED_EXT = ".locked"

    # Plausible decoy file set seeded into DECOY_DIR if missing.
    DECOYS = {
        "notes.txt": "Personal notes -- lab simulation.\n",
        "q4_report.docx": "Confidential Q4 results -- lab simulation.\n",
        "contacts.csv": "name,email\nAlice,alice@lab.local\nBob,bob@lab.local\n",
    }

    RANSOM_NOTE = """\
==========================================================
  LAB SIMULATION -- NO ACTUAL ENCRYPTION
==========================================================

In a real T1486 incident, every file in your home directory
would now be encrypted with attacker-held keys. This is the
Adversary-in-a-Box lab; files were *renamed* with a .locked
suffix only. Restore with:

    python runner.py --cleanup-all

Or trigger the paired IR playbook from the blue-team container:

    docker compose exec blue-team python -c "from response.playbook_engine \\
      import PlaybookEngine; PlaybookEngine('ransomware_ir').execute( \\
        {'affected_host':'red-team','attacker_ip':'172.20.0.10'})"

==========================================================
"""

    # Audit-2 Gap #10 / OQ-1 surface for --cleanup-all without prior run().
    WELL_KNOWN_ARTIFACTS = (DECOY_DIR,)

    def run(self) -> dict:
        self.log_step("init", f"Simulating ransomware against {self.DECOY_DIR}")
        os.makedirs(self.DECOY_DIR, exist_ok=True)

        # Step 1: seed decoys (idempotent).
        for name, content in self.DECOYS.items():
            path = os.path.join(self.DECOY_DIR, name)
            if not os.path.exists(path):
                with open(path, "w") as f:
                    f.write(content)
        self.log_step("seed", f"{len(self.DECOYS)} decoy files staged")

        # Step 2: rename each decoy to .locked (NOT encrypted).
        renames: list[dict] = []
        for name in self.DECOYS:
            src = os.path.join(self.DECOY_DIR, name)
            dst = src + self.LOCKED_EXT
            if os.path.exists(src):
                os.rename(src, dst)
                renames.append({"from": src, "to": dst})
        self.log_step("lock", f"Renamed {len(renames)} files with {self.LOCKED_EXT}")

        # Step 3: write ransom note.
        note_path = os.path.join(self.DECOY_DIR, self.NOTE_FILENAME)
        with open(note_path, "w") as f:
            f.write(self.RANSOM_NOTE)
        self.log_step("note", f"Ransom note dropped at {note_path}")

        # Cleanup will scrub the whole decoy directory.
        self.register_cleanup_path(self.DECOY_DIR)

        results = {
            "technique": self.TECHNIQUE_ID,
            "decoy_dir": self.DECOY_DIR,
            "renames": renames,
            "ransom_note": note_path,
            "timestamp": datetime.now(UTC).isoformat(),
        }
        self.save_artifact("ransomware_sim_results.json", json.dumps(results, indent=2))
        # audit-4 G2b: syslog advisory so impact_ransomware.yml (logsource:
        # syslog) has a doc carrying the .locked/ransom-note markers + decoy
        # path to match -- the file_event ingest path never existed.
        self.emit_syslog_advisory(
            {
                "signature": "ransomware_simulation",
                "rename_marker": self.LOCKED_EXT,
                "ransom_note": self.NOTE_FILENAME,
                "decoy_path": self.DECOY_DIR,
                "technique": self.TECHNIQUE_ID,
            },
            program="aib-ransomware",
        )
        return self.build_result(True, f"Ransomware simulated -- {len(renames)} files locked")

    def cleanup(self) -> dict:
        """
        Reverse the simulation: rename .locked files back to their original
        names, delete the ransom note, then defer to the default cleanup()
        for the decoy directory (so we leave nothing behind even on a
        cleanup-without-prior-run invocation).
        """
        restored: list[str] = []
        errors: list[dict] = []

        if os.path.isdir(self.DECOY_DIR):
            for fname in os.listdir(self.DECOY_DIR):
                full = os.path.join(self.DECOY_DIR, fname)
                if fname == self.NOTE_FILENAME:
                    try:
                        os.remove(full)
                    except OSError as exc:
                        errors.append({"path": full, "error": str(exc)})
                    continue
                if fname.endswith(self.LOCKED_EXT):
                    orig = full[: -len(self.LOCKED_EXT)]
                    try:
                        os.rename(full, orig)
                        restored.append(orig)
                    except OSError as exc:
                        errors.append({"path": full, "error": str(exc)})

        # Defer to default cleanup() to wipe DECOY_DIR entirely (since the
        # restored files were a simulation -- not real user data we'd want
        # to keep around). This matches the "leaves no lab artifact behind"
        # contract from OQ-1.
        default_cleanup = super().cleanup()
        default_cleanup["restored_renames"] = restored
        default_cleanup["errors"].extend(errors)
        return default_cleanup
