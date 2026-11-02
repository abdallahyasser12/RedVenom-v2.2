from __future__ import annotations

import unittest

from scripts.filter_scope import entry_host, filter_entries, host_is_in_scope


class ScopeFilterTests(unittest.TestCase):
    def test_root_and_subdomains_are_in_scope(self) -> None:
        self.assertTrue(host_is_in_scope("example.com", "example.com"))
        self.assertTrue(host_is_in_scope("api.example.com", "example.com"))
        self.assertTrue(host_is_in_scope("deep.api.example.com", "example.com"))

    def test_suffix_lookalikes_and_external_hosts_are_rejected(self) -> None:
        self.assertFalse(host_is_in_scope("notexample.com", "example.com"))
        self.assertFalse(host_is_in_scope("example.com.attacker.test", "example.com"))
        self.assertFalse(host_is_in_scope("attacker.test", "example.com"))

    def test_ip_root_requires_exact_ip_match(self) -> None:
        self.assertTrue(host_is_in_scope("192.0.2.10", "192.0.2.10"))
        self.assertFalse(host_is_in_scope("sub.192.0.2.10", "192.0.2.10"))
        self.assertFalse(host_is_in_scope("192.0.2.11", "192.0.2.10"))

    def test_entry_host_rejects_userinfo_and_non_http_schemes(self) -> None:
        self.assertEqual(entry_host("https://api.example.com/a"), "api.example.com")
        self.assertIsNone(entry_host("ftp://example.com/a"))
        self.assertIsNone(entry_host("https://user@example.com/a"))
        self.assertIsNone(entry_host("example.com/path"))

    def test_malformed_and_out_of_range_ports_are_rejected(self) -> None:
        for value in (
            "https://example.com:abc/path",
            "https://example.com:65536/path",
            "https://example.com:0/path",
            "https://[2001:db8::1/path",
        ):
            with self.subTest(value=value):
                self.assertIsNone(entry_host(value))

    def test_valid_ports_and_ipv6_authorities_are_accepted(self) -> None:
        self.assertEqual(entry_host("https://example.com:443/a"), "example.com")
        self.assertEqual(entry_host("http://[2001:db8::1]:8080/a"), "2001:db8::1")

    def test_filter_preserves_only_in_scope_lines(self) -> None:
        lines = [
            "https://example.com/a?x=1",
            "https://api.example.com/b",
            "https://example.com.evil.test/",
            "https://evil.test/",
            "https://example.com:bad/",
            "",
        ]
        accepted, rejected = filter_entries("example.com", lines)
        self.assertEqual(accepted, lines[:2])
        self.assertEqual(rejected, 3)


if __name__ == "__main__":
    unittest.main()
