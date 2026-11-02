#!/usr/bin/env python3
"""Verify a RedVenom run manifest against the files currently on disk."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _safe_artifact_path(run_dir: Path, raw_path: Any) -> tuple[Path | None, str | None]:
    if not isinstance(raw_path, str) or not raw_path:
        return None, "artifact path must be a non-empty string"
    if "\\" in raw_path:
        return None, f"artifact path uses a non-portable separator: {raw_path!r}"

    relative = PurePosixPath(raw_path)
    if relative.is_absolute() or any(part in ("", ".", "..") for part in relative.parts):
        return None, f"artifact path is not a safe relative path: {raw_path!r}"

    root = run_dir.resolve()
    candidate = run_dir
    for part in relative.parts:
        candidate = candidate / part
        if candidate.is_symlink():
            return None, f"artifact path traverses a symbolic link: {raw_path!r}"

    try:
        candidate.resolve(strict=False).relative_to(root)
    except ValueError:
        return None, f"artifact path escapes the run directory: {raw_path!r}"
    return candidate, None


def verify_manifest(manifest: Any, run_dir: Path) -> list[str]:
    """Return integrity errors; an empty list means every listed artifact matches."""
    if not isinstance(manifest, dict):
        return ["manifest root must be a JSON object"]
    if type(manifest.get("schema_version")) is not int or manifest["schema_version"] != 1:
        return ["unsupported or missing manifest schema_version"]
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        return ["manifest artifacts must be a JSON array"]

    errors: list[str] = []
    seen: set[str] = set()
    for index, artifact in enumerate(artifacts):
        prefix = f"artifacts[{index}]"
        if not isinstance(artifact, dict):
            errors.append(f"{prefix}: entry must be a JSON object")
            continue

        raw_path = artifact.get("path")
        path, path_error = _safe_artifact_path(run_dir, raw_path)
        if path_error:
            errors.append(f"{prefix}: {path_error}")
            continue

        assert path is not None and isinstance(raw_path, str)
        if raw_path in seen:
            errors.append(f"{prefix}: duplicate artifact path {raw_path!r}")
            continue
        seen.add(raw_path)

        expected_size = artifact.get("size_bytes")
        expected_hash = artifact.get("sha256")
        if type(expected_size) is not int or expected_size < 0:
            errors.append(f"{prefix} ({raw_path}): size_bytes must be a non-negative integer")
            continue
        if not isinstance(expected_hash, str) or not SHA256_RE.fullmatch(expected_hash):
            errors.append(f"{prefix} ({raw_path}): sha256 must be 64 lowercase hexadecimal characters")
            continue

        try:
            if not path.exists():
                errors.append(f"{prefix} ({raw_path}): file is missing")
                continue
            if not path.is_file():
                errors.append(f"{prefix} ({raw_path}): path is not a regular file")
                continue
            actual_size = path.stat().st_size
            if actual_size != expected_size:
                errors.append(
                    f"{prefix} ({raw_path}): size mismatch (expected {expected_size}, got {actual_size})"
                )
                continue

            digest = hashlib.sha256()
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            actual_hash = digest.hexdigest()
            if actual_hash != expected_hash:
                errors.append(f"{prefix} ({raw_path}): SHA-256 mismatch")
        except OSError as exc:
            errors.append(f"{prefix} ({raw_path}): could not read artifact ({exc})")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, type=Path, help="Directory containing run_manifest.json")
    args = parser.parse_args()
    manifest_path = args.run_dir / "run_manifest.json"

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"Could not read a valid run manifest at {manifest_path}: {exc}", file=sys.stderr)
        return 2

    errors = verify_manifest(manifest, args.run_dir)
    if errors:
        print("Run manifest verification failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    count = len(manifest["artifacts"])
    print(f"Run manifest verified: {count} artifact(s) match their recorded size and SHA-256.")
    print("This verifies file integrity only; it does not validate findings or prove target security.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
