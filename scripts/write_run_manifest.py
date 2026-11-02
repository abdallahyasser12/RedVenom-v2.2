#!/usr/bin/env python3
"""Write a private run manifest with timing, tool versions, and artifact hashes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


VERSION_COMMANDS: dict[str, list[str]] = {
    "subfinder": ["-version"],
    "httpx": ["-version"],
    "gau": ["--version"],
    "sqlmap": ["--version"],
    "nuclei": ["-version"],
    "curl": ["--version"],
    "jq": ["--version"],
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect_artifacts(run_dir: Path) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    for path in sorted(run_dir.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        relative = path.relative_to(run_dir).as_posix()
        if relative in {"run_manifest.json", "openvpn.pid"}:
            continue
        try:
            artifacts.append(
                {
                    "path": relative,
                    "size_bytes": path.stat().st_size,
                    "sha256": sha256_file(path),
                }
            )
        except OSError:
            # One unreadable artifact must not prevent the rest of the manifest.
            continue
    return artifacts


def tool_versions() -> dict[str, str]:
    versions: dict[str, str] = {}
    for command, args in VERSION_COMMANDS.items():
        executable = shutil.which(command)
        if not executable:
            versions[command] = "not-installed"
            continue
        try:
            result = subprocess.run(
                [executable, *args],
                capture_output=True,
                text=True,
                timeout=4,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            versions[command] = "unknown"
            continue
        output = (result.stdout or "") + "\n" + (result.stderr or "")
        first_line = next((line.strip() for line in output.splitlines() if line.strip()), "")
        versions[command] = first_line[:240] if first_line else "unknown"
    return versions


def build_manifest(run_dir: Path, run_id: str, target: str, started_at: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "run_id": run_id,
        "target_root": target,
        "started_at": started_at,
        "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tool_versions": tool_versions(),
        "artifacts": collect_artifacts(run_dir),
        "limitations": [
            "Artifact hashes establish file identity, not finding validity.",
            "Third-party tool versions are recorded only where a bounded version command is available.",
            "The manifest does not include credentials, response bodies, or raw artifact contents.",
        ],
    }


def write_manifest_atomic(run_dir: Path, manifest: dict[str, Any]) -> Path:
    """Replace run_manifest.json atomically and with owner-only permissions."""
    run_dir.mkdir(parents=True, exist_ok=True)
    output = run_dir / "run_manifest.json"
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".run_manifest.",
        suffix=".tmp",
        dir=run_dir,
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(manifest, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, output)
        return output
    except BaseException:
        # fdopen owns the descriptor after it succeeds; close only if still open.
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--started-at", required=True)
    args = parser.parse_args()

    try:
        manifest = build_manifest(args.run_dir, args.run_id, args.target, args.started_at)
        output = write_manifest_atomic(args.run_dir, manifest)
    except (OSError, ValueError, TypeError) as exc:
        print(f"Run manifest creation failed: {exc}", file=sys.stderr)
        return 2

    print(f"Run manifest written: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
