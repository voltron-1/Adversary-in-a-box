#!/usr/bin/env python3
"""
forensics/chain_of_custody.py — SHA-256 Chain of Custody for Evidence Files

Hashes all evidence files and maintains a tamper-evident JSON custody log.
Usage: python chain_of_custody.py --hash-dir /evidence [--verify]
"""

import hashlib
import json
import os
import argparse
from datetime import datetime, timezone
from pathlib import Path


def sha256_file(path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_directory(directory: Path) -> dict:
    """Hash all files in a directory and return a custody manifest."""
    manifest = {
        "tool": "chain_of_custody.py",
        "version": "1.0",
        "algorithm": "SHA-256",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "evidence_dir": str(directory),
        "files": [],
    }

    for path in sorted(directory.rglob("*")):
        if path.is_file() and path.name != "custody.json":
            try:
                file_hash = sha256_file(path)
                stat = path.stat()
                manifest["files"].append({
                    "path": str(path.relative_to(directory)),
                    "sha256": file_hash,
                    "size_bytes": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                })
                print(f"  [✓] {path.name}: {file_hash}")
            except (PermissionError, OSError) as e:
                print(f"  [!] Could not hash {path}: {e}")

    manifest["total_files"] = len(manifest["files"])
    return manifest


def verify_manifest(custody_path: Path) -> bool:
    """Verify current file hashes match the custody manifest."""
    with open(custody_path) as f:
        manifest = json.load(f)

    base_dir = Path(manifest["evidence_dir"])
    all_ok = True

    print(f"\n[i] Verifying {manifest['total_files']} files from {manifest['timestamp']}\n")

    for entry in manifest["files"]:
        full_path = base_dir / entry["path"]
        if not full_path.exists():
            print(f"  [✗] MISSING: {entry['path']}")
            all_ok = False
            continue

        current_hash = sha256_file(full_path)
        if current_hash == entry["sha256"]:
            print(f"  [✓] INTACT: {entry['path']}")
        else:
            print(f"  [✗] TAMPERED: {entry['path']}")
            print(f"      Expected: {entry['sha256']}")
            print(f"      Got:      {current_hash}")
            all_ok = False

    return all_ok


def main():
    parser = argparse.ArgumentParser(description="Chain of Custody Evidence Hasher")
    parser.add_argument("--hash-dir", type=Path, default=Path("/evidence"),
                        help="Directory to hash")
    parser.add_argument("--verify", action="store_true",
                        help="Verify against existing custody.json")
    parser.add_argument("--output", type=Path, default=None,
                        help="Output path for custody.json")
    args = parser.parse_args()

    if not args.hash_dir.exists():
        print(f"[!] Directory not found: {args.hash_dir}")
        args.hash_dir.mkdir(parents=True)
        print(f"[+] Created: {args.hash_dir}")

    custody_path = args.output or args.hash_dir / "custody.json"

    if args.verify:
        if not custody_path.exists():
            print(f"[!] No custody manifest found at: {custody_path}")
            return
        ok = verify_manifest(custody_path)
        print(f"\n{'[✓] All files intact.' if ok else '[✗] INTEGRITY FAILURE — evidence may be compromised!'}")
        return

    print(f"\n[+] Hashing evidence in: {args.hash_dir}\n")
    manifest = hash_directory(args.hash_dir)

    with open(custody_path, "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"\n[✓] Chain of custody manifest saved: {custody_path}")
    print(f"[i] Total files hashed: {manifest['total_files']}")
    print(f"[i] Timestamp: {manifest['timestamp']}")


if __name__ == "__main__":
    main()
