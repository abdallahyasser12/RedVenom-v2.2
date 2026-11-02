from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class CurlTransportSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = (ROOT / "redvenom.sh").read_text(encoding="utf-8")

    def test_builtin_requests_do_not_disable_tls_verification(self) -> None:
        self.assertNotIn(" -sk ", self.script)
        self.assertNotIn("--insecure", self.script)
        self.assertNotIn(" -k ", self.script)

    def test_builtin_requests_have_connect_and_total_timeouts(self) -> None:
        for fragment in (
            '--connect-timeout 5 --max-time 15 "$jsurl"',
            '--connect-timeout 5 --max-time 10 "$url"',
            '--connect-timeout 5 --max-time 10 "$fuzzed"',
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.script)

    def test_external_ai_request_remains_bounded(self) -> None:
        self.assertIn("--connect-timeout 10 --max-time 60", self.script)


if __name__ == "__main__":
    unittest.main()
