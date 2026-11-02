from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class OfflineTestRunnerContractTests(unittest.TestCase):
    def test_runner_covers_documented_local_checks(self) -> None:
        runner = (ROOT / "scripts/test.sh").read_text(encoding="utf-8")
        for expected in (
            "bash -n redvenom.sh",
            "python3 -m compileall -q scripts tests",
            "python3 scripts/check_docs.py",
            "python3 -m unittest discover -s tests -p 'test_*.py' -v",
        ):
            with self.subTest(command=expected):
                self.assertIn(expected, runner)

    def test_runner_is_offline_and_uses_fail_fast_shell_mode(self) -> None:
        runner = (ROOT / "scripts/test.sh").read_text(encoding="utf-8")
        self.assertIn("set -euo pipefail", runner)
        self.assertNotIn("curl ", runner)
        self.assertNotIn("nuclei ", runner)


if __name__ == "__main__":
    unittest.main()
