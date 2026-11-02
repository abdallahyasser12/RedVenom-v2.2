from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ConcurrencyConfigContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = (ROOT / "redvenom.sh").read_text(encoding="utf-8")
        cls.install = (ROOT / "docs/INSTALLATION.md").read_text(encoding="utf-8")

    def test_worker_limits_have_defaults_and_hard_ceilings(self) -> None:
        self.assertIn('"${REDVENOM_MAX_XS_JOBS:-4}" 4 10', self.script)
        self.assertIn('"${REDVENOM_MAX_FUZZ_JOBS:-5}" 5 20', self.script)

    def test_invalid_limits_fall_back_to_defaults(self) -> None:
        self.assertIn("numeric_value < 1 || numeric_value > maximum", self.script)
        self.assertIn("using default", self.script)

    def test_operator_documentation_distinguishes_stage_caps_from_rate_limits(self) -> None:
        self.assertIn("REDVENOM_MAX_XS_JOBS", self.install)
        self.assertIn("REDVENOM_MAX_FUZZ_JOBS", self.install)
        self.assertIn("not a global request-rate limiter", self.install)


if __name__ == "__main__":
    unittest.main()
