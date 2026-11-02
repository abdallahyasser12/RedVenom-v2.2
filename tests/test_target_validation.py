from __future__ import annotations

import unittest

from scripts.validate_target import normalize_target


class TargetValidationTests(unittest.TestCase):
    def test_normalizes_dns_names(self) -> None:
        self.assertEqual(normalize_target("Example.COM"), "example.com")
        self.assertEqual(normalize_target("example.com."), "example.com")

    def test_normalizes_idn_and_ip_addresses(self) -> None:
        self.assertEqual(normalize_target("bücher.example"), "xn--bcher-kva.example")
        self.assertEqual(normalize_target("192.0.2.10"), "192.0.2.10")
        self.assertEqual(normalize_target("[2001:db8::1]"), "2001:db8::1")

    def test_rejects_urls_ports_paths_and_wildcards(self) -> None:
        for value in (
            "",
            "https://example.com",
            "example.com:443",
            "example.com/path",
            "example.com?x=1",
            "user@example.com",
            "*.example.com",
            "example",
            "example.c",
            "bad..example",
            "bad_label.example",
            "example.com other.com",
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    normalize_target(value)


if __name__ == "__main__":
    unittest.main()
