from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.preflight import REQUIRED_COMMANDS, check_dependencies


class DependencyPreflightTests(unittest.TestCase):
    def test_all_required_commands_and_xsstrike_pass(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "XSStrike").mkdir()
            (root / "XSStrike" / "xsstrike.py").write_text("# fixture\n")
            with patch("shutil.which", side_effect=lambda name: "/usr/bin/" + name):
                missing, optional = check_dependencies(cwd=root)
        self.assertEqual(missing, [])
        self.assertEqual(optional, [])

    def test_missing_required_commands_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with patch("shutil.which", return_value=None):
                missing, optional = check_dependencies(cwd=Path(directory))
        self.assertEqual(missing, list(REQUIRED_COMMANDS) + [
            "xsstrike (command or XSStrike/xsstrike.py)"
        ])
        self.assertEqual(optional, ["nuclei"])

    def test_nuclei_is_optional(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "XSStrike").mkdir()
            (root / "XSStrike" / "xsstrike.py").write_text("# fixture\n")
            with patch(
                "shutil.which",
                side_effect=lambda name: None if name == "nuclei" else "/usr/bin/" + name,
            ):
                missing, optional = check_dependencies(cwd=root)
        self.assertEqual(missing, [])
        self.assertEqual(optional, ["nuclei"])


if __name__ == "__main__":
    unittest.main()
