from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class PrivateRunPermissionsTests(unittest.TestCase):
    def test_redvenom_sets_restrictive_umask_before_workflow(self) -> None:
        script = (ROOT / "redvenom.sh").read_text(encoding="utf-8")
        self.assertRegex(script, r"(?m)^umask 077$")
        self.assertLess(script.index("umask 077"), script.index('read -p "[?] Enter the target domain'))

    @unittest.skipUnless(os.name == "posix", "POSIX permission bits are required")
    def test_umask_creates_owner_only_files_and_directories(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(
                ["bash", "-c", "umask 077; mkdir run; touch run/artifact.txt"],
                cwd=root,
                check=True,
            )
            self.assertEqual((root / "run").stat().st_mode & 0o777, 0o700)
            self.assertEqual((root / "run" / "artifact.txt").stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
