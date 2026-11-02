from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class OpenRouterRequestContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = (ROOT / "redvenom.sh").read_text(encoding="utf-8")

    def test_all_user_content_is_encoded_as_json_arguments(self) -> None:
        self.assertIn('openrouter_chat_completion()', self.script)
        self.assertIn('--arg system "$system_message"', self.script)
        self.assertIn('--arg user "$user_message"', self.script)
        self.assertIn('--data-binary "$request_body"', self.script)

    def test_requests_have_bounded_timeouts_and_http_error_handling(self) -> None:
        self.assertIn('--fail --silent --show-error', self.script)
        self.assertIn('--connect-timeout 10 --max-time 60', self.script)

    def test_unsafe_interpolated_json_heredoc_is_absent(self) -> None:
        self.assertNotIn('<<EOF', self.script)
        self.assertNotIn('curl -s https://openrouter.ai', self.script)


if __name__ == "__main__":
    unittest.main()
