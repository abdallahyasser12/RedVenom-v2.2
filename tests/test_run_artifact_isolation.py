from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class RunArtifactIsolationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = (ROOT / "redvenom.sh").read_text(encoding="utf-8")

    def test_run_directory_is_unique_per_bash_process(self) -> None:
        self.assertIn('RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-${BASHPID}"', self.script)
        self.assertIn('RUN_DIR="recon_venom/runs/${RUN_ID}"', self.script)

    def test_previous_shared_output_is_not_deleted(self) -> None:
        self.assertNotIn("rm -rf recon_venom/*", self.script)
        self.assertNotIn("rm -rf ${RUN_DIR}/*", self.script)

    def test_payload_and_confirmation_outputs_are_run_scoped(self) -> None:
        self.assertIn('PAYLOAD_DIR="${RUN_DIR}/payloads"', self.script)
        self.assertIn('${RUN_DIR}/confirmed/nuclei', self.script)
        self.assertNotIn("cat > payloads/", self.script)


if __name__ == "__main__":
    unittest.main()
