from __future__ import annotations

import unittest

from scripts.parse_nuclei_jsonl import candidate_row, clean_cell, parse_jsonl


class NucleiJsonlParserTests(unittest.TestCase):
    def test_extracts_candidate_fields(self) -> None:
        row = candidate_row({
            "templateID": "http/missing-header",
            "info": {"name": "Missing Header", "severity": "low"},
            "matched-at": "https://app.example.test/",
        })
        self.assertEqual(
            row,
            ("http/missing-header", "Missing Header", "low", "https://app.example.test/"),
        )

    def test_missing_optional_fields_get_explicit_fallbacks(self) -> None:
        self.assertEqual(
            candidate_row({"template_id": "custom/test"}),
            ("custom/test", "unnamed-template", "unknown-severity", "unknown-location"),
        )

    def test_tabs_and_newlines_are_sanitized(self) -> None:
        row = candidate_row({
            "templateID": "t\t1",
            "info": {"name": "line\nname", "severity": "medium"},
            "host": "https://host.example.test/\r",
        })
        self.assertEqual(row, ("t 1", "line name", "medium", "https://host.example.test/"))

    def test_spreadsheet_formula_prefixes_are_exported_as_text(self) -> None:
        examples = (
            "=HYPERLINK(\"https://example.invalid\")",
            "  +1+1",
            "-1+2",
            "@SUM(A1:A2)",
            "\t=cmd|'/C calc'!A0",
        )
        for value in examples:
            with self.subTest(value=value):
                self.assertTrue(clean_cell(value, "fallback").startswith("'"))

    def test_plain_cells_are_not_modified(self) -> None:
        self.assertEqual(clean_cell("severity: low", "fallback"), "severity: low")
        self.assertEqual(clean_cell("0.0", "fallback"), "0.0")

    def test_malformed_and_non_object_records_are_skipped(self) -> None:
        lines = [
            '{"templateID":"ok","info":{"name":"Good","severity":"info"},"host":"x"}',
            '{"broken":',
            '[]',
            '',
        ]
        rows, skipped = parse_jsonl(lines)
        self.assertEqual(len(rows), 1)
        self.assertEqual(skipped, 2)


if __name__ == "__main__":
    unittest.main()
