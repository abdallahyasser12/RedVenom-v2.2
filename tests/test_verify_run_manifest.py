from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from scripts.verify_run_manifest import verify_manifest


def record(path: str, content: bytes) -> dict[str, object]:
    return {
        "path": path,
        "size_bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


class VerifyRunManifestTests(unittest.TestCase):
    def test_valid_artifact_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            content = b"candidate evidence\n"
            (root / "finding.txt").write_bytes(content)
            manifest = {"schema_version": 1, "artifacts": [record("finding.txt", content)]}
            self.assertEqual(verify_manifest(manifest, root), [])

    def test_same_size_modified_artifact_fails_digest_check(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "finding.txt").write_bytes(b"tampered")
            manifest = {"schema_version": 1, "artifacts": [record("finding.txt", b"original")]}
            errors = verify_manifest(manifest, root)
        self.assertTrue(any("SHA-256 mismatch" in error for error in errors))

    def test_size_mismatch_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "finding.txt").write_bytes(b"short")
            manifest = {"schema_version": 1, "artifacts": [record("finding.txt", b"longer")]}
            errors = verify_manifest(manifest, root)
        self.assertTrue(any("size mismatch" in error for error in errors))

    def test_missing_artifact_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = {"schema_version": 1, "artifacts": [record("missing.txt", b"x")]}
            errors = verify_manifest(manifest, root)
        self.assertTrue(any("missing" in error for error in errors))

    def test_path_traversal_and_absolute_paths_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = {
                "schema_version": 1,
                "artifacts": [
                    {"path": "../outside", "size_bytes": 0, "sha256": "0" * 64},
                    {"path": "/tmp/outside", "size_bytes": 0, "sha256": "0" * 64},
                ],
            }
            errors = verify_manifest(manifest, root)
        self.assertEqual(len(errors), 2)
        self.assertTrue(all("safe relative path" in error for error in errors))

    def test_invalid_schema_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            errors = verify_manifest({"schema_version": 2, "artifacts": []}, Path(directory))
        self.assertIn("unsupported or missing manifest schema_version", errors)

    def test_duplicate_artifact_paths_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            content = b"same"
            (root / "a.txt").write_bytes(content)
            entry = record("a.txt", content)
            errors = verify_manifest({"schema_version": 1, "artifacts": [entry, entry.copy()]}, root)
        self.assertTrue(any("duplicate artifact path" in error for error in errors))

    def test_malformed_digest_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a.txt").write_bytes(b"a")
            entry = record("a.txt", b"a")
            entry["sha256"] = "not-a-digest"
            errors = verify_manifest({"schema_version": 1, "artifacts": [entry]}, root)
        self.assertTrue(any("sha256 must be" in error for error in errors))

    def test_symlink_artifact_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.txt"
            target.write_text("secret", encoding="utf-8")
            link = root / "linked.txt"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks are not available on this platform")
            manifest = {"schema_version": 1, "artifacts": [record("linked.txt", b"secret")]}
            errors = verify_manifest(manifest, root)
        self.assertTrue(any("symbolic link" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
