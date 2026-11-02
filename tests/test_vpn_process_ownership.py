from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class VPNProcessOwnershipTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = (ROOT / "redvenom.sh").read_text(encoding="utf-8")

    def test_no_global_openvpn_kill_is_used(self) -> None:
        self.assertNotIn("killall openvpn", self.script)
        self.assertNotIn("pkill openvpn", self.script)

    def test_cleanup_uses_a_run_owned_pid_file(self) -> None:
        self.assertIn('VPN_PID_FILE="${RUN_DIR}/openvpn.pid"', self.script)
        self.assertIn('--writepid "$VPN_PID_FILE"', self.script)
        self.assertIn('sudo kill "$vpn_pid"', self.script)

    def test_existing_vpn_is_left_untouched(self) -> None:
        self.assertIn("An OpenVPN process is already running; RedVenom will leave it untouched.", self.script)
        self.assertIn('VPN_STARTED_BY_REDVENOM=0', self.script)


if __name__ == "__main__":
    unittest.main()
