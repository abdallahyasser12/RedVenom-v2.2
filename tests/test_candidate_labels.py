from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class CandidateLabelContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = (ROOT / "redvenom.sh").read_text(encoding="utf-8")

    def test_heuristic_matches_are_not_labeled_vulnerable_or_confirmed(self) -> None:
        self.assertNotIn("[VULNERABLE]", self.script)
        self.assertNotIn("[Not Vulnerable]", self.script)
        self.assertNotIn("confirmed_nuclei.txt", self.script)
        self.assertIn("[CANDIDATE - VERIFY]", self.script)
        self.assertIn("candidates/nuclei/nuclei_candidates.txt", self.script)

    def test_xsstrike_candidate_file_name_is_explicit(self) -> None:
        self.assertIn("xsstrike_candidates.txt", self.script)
        self.assertNotIn("xsstrike_vulns.txt", self.script)


if __name__ == "__main__":
    unittest.main()
