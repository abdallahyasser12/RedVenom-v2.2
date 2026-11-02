#!/usr/bin/env python3
"""Parse Nuclei JSONL into a small, review-oriented candidate TSV."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def clean_cell(value: Any, fallback: str) -> str:
    if value is None:
        text = fallback
    elif isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=True, sort_keys=True)
    else:
        text = str(value)
    text = " ".join(text.replace("\t", " ").replace("\r", " ").replace("\n", " ").split())

    # TSV files are commonly opened in spreadsheet applications. Prefix formula
    # starters after leading whitespace so untrusted scanner output stays text.
    first_visible = text.lstrip(" \t\r\n\v\f")
    if first_visible.startswith(("=", "+", "-", "@")):
        text = "'" + text
    return text


def candidate_row(record: Any) -> tuple[str, str, str, str] | None:
    if not isinstance(record, dict):
        return None
    info = record.get("info")
    if not isinstance(info, dict):
        info = {}

    template_id = record.get("templateID") or record.get("template_id") or record.get("template-id")
    name = info.get("name")
    severity = info.get("severity")
    matched = (
        record.get("matched-at")
        or record.get("matched_at")
        or record.get("host")
        or record.get("url")
    )
    return (
        clean_cell(template_id, "unknown-template"),
        clean_cell(name, "unnamed-template"),
        clean_cell(severity, "unknown-severity"),
        clean_cell(matched, "unknown-location"),
    )


def parse_jsonl(lines: list[str]) -> tuple[list[tuple[str, str, str, str]], int]:
    rows: list[tuple[str, str, str, str]] = []
    skipped = 0
    for line in lines:
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            skipped += 1
            continue
        row = candidate_row(record)
        if row is None:
            skipped += 1
            continue
        rows.append(row)
    return rows, skipped


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    try:
        lines = args.input.read_text(encoding="utf-8").splitlines()
        rows, skipped = parse_jsonl(lines)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", encoding="utf-8", newline="\n") as handle:
            for row in rows:
                handle.write("\t".join(row) + "\n")
    except OSError as exc:
        print(f"Nuclei JSONL parsing failed: {exc}", file=sys.stderr)
        return 2

    print(
        f"Nuclei candidate parser: wrote {len(rows)} rows; skipped {skipped} malformed/non-object records.",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
