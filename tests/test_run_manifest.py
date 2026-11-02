from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.write_run_manifest import (
    build_manifest,
    collect_artifacts,
    sha256_file,
    write_manifest_atomic,
)


class RunManifestTests(unittest.TestCase):
    def test_sha256_matches_standard_library_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            file_path = Path(directory) / "artifact.txt"
            file_path.write_text("RedVenom evidence\n", encoding="utf-8")
            expected = hashlib.sha256(file_path.read_bytes()).hexdigest()
            self.assertEqual(sha256_file(file_path), expected)

    def test_artifact_collection_excludes_manifest_and_pid_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "raw.jsonl").write_text('{"id":"1"}\n', encoding="utf-8")
            (root / "openvpn.pid").write_text("1234\n", encoding="utf-8")
            (root / "run_manifest.json").write_text("{}\n", encoding="utf-8")
            (root / "nested").mkdir()
            (root / "nested" / "report.tsv").write_text("candidate\n", encoding="utf-8")
            artifacts = collect_artifacts(root)
        self.assertEqual([item["path"] for item in artifacts], ["nested/report.tsv", "raw.jsonl"])

    def test_manifest_contains_run_identity_and_artifact_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scan.txt").write_text("output", encoding="utf-8")
            with patch("scripts.write_run_manifest.tool_versions", return_value={"curl": "curl test"}):
                manifest = build_manifest(root, "run-123", "example.test", "2026-11-02T00:00:00Z")
        self.assertEqual(manifest["schema_version"], 1)
        self.assertEqual(manifest["run_id"], "run-123")
        self.assertEqual(manifest["target_root"], "example.test")
        self.assertEqual(manifest["artifacts"][0]["sha256"], hashlib.sha256(b"output").hexdigest())
        self.assertIn("finished_at", manifest)
        self.assertIn("tool_versions", manifest)

    def test_manifest_is_written_atomically_with_private_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = write_manifest_atomic(root, {"schema_version": 1, "artifacts": []})
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["schema_version"], 1)
            self.assertEqual(list(root.glob(".run_manifest.*.tmp")), [])
            if os.name == "posix":
                self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_failed_replace_preserves_previous_manifest_and_cleans_temporary_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "run_manifest.json"
            output.write_text('{"old": true}\n', encoding="utf-8")
            with patch("scripts.write_run_manifest.os.replace", side_effect=OSError("simulated replace failure")):
                with self.assertRaises(OSError):
                    write_manifest_atomic(root, {"new": True})
            self.assertEqual(output.read_text(encoding="utf-8"), '{"old": true}\n')
            self.assertEqual(list(root.glob(".run_manifest.*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
