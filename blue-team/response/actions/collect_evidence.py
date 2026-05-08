#!/usr/bin/env python3
"""
blue-team/response/actions/collect_evidence.py
Forensic artifact collector — gathers logs and hashes them for chain of custody.
"""

import os
import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

EVIDENCE_DIR = Path(os.environ.get("EVIDENCE_DIR", "/evidence"))
LOG_SOURCES = [
    Path("/var/log/suricata/eve.json"),
    Path("/var/log/suricata/fast.log"),
    Path("/var/log/zeek/conn.log"),
    Path("/var/log/zeek/dns.log"),
    Path("/var/log/zeek/http.log"),
    Path("/var/log/zeek/notice.log"),
    Path("/app/logs"),
]

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def collect():
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    session_dir = EVIDENCE_DIR / f"collection_{timestamp}"
    session_dir.mkdir()

    manifest = {
        "collection_time": datetime.now(timezone.utc).isoformat(),
        "collector": "collect_evidence.py",
        "artifacts": [],
    }

    for src in LOG_SOURCES:
        if src.exists():
            try:
                dest = session_dir / src.name
                if src.is_dir():
                    shutil.copytree(src, dest, dirs_exist_ok=True)
                    for f in dest.rglob("*"):
                        if f.is_file():
                            manifest["artifacts"].append({"path": str(f), "sha256": sha256_file(f)})
                else:
                    shutil.copy2(src, dest)
                    manifest["artifacts"].append({"path": str(dest), "sha256": sha256_file(dest)})
                print(f"  [✓] Collected: {src}")
            except Exception as e:
                print(f"  [!] Could not collect {src}: {e}")
        else:
            print(f"  [–] Not found: {src}")

    manifest_path = session_dir / "manifest.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"\n[✓] Evidence collected: {session_dir}")
    print(f"[✓] Manifest: {manifest_path}")
    print(f"[i] Artifacts: {len(manifest['artifacts'])}")
    return manifest

if __name__ == "__main__":
    collect()
