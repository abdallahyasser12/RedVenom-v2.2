#!/usr/bin/env python3
"""Check RedVenom's required docs, Markdown fences, and local links."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_FILES = (
    "README.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "docs/INSTALLATION.md",
    "docs/SAFETY.md",
    "docs/MAINTENANCE.md",
)
LINK_RE = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")
FENCE_RE = re.compile(r"^\s*(```+|~~~+)")


def markdown_files() -> list[Path]:
    return sorted(
        path
        for path in ROOT.rglob("*.md")
        if ".git" not in path.parts and ".venv" not in path.parts
    )


def check_fences(path: Path, content: str) -> list[str]:
    fences: list[tuple[str, int]] = []
    errors: list[str] = []
    for line_number, line in enumerate(content.splitlines(), 1):
        match = FENCE_RE.match(line)
        if not match:
            continue
        marker = match.group(1)
        if not fences:
            fences.append((marker[0], line_number))
        elif marker[0] == fences[-1][0]:
            fences.pop()
        else:
            errors.append(f"{path.relative_to(ROOT)}:{line_number}: mismatched fence")
    if fences:
        errors.append(
            f"{path.relative_to(ROOT)}:{fences[-1][1]}: unclosed code fence"
        )
    return errors


def check_links(path: Path, content: str) -> list[str]:
    errors: list[str] = []
    for match in LINK_RE.finditer(content):
        raw_target = match.group(1).strip()
        target = raw_target.split(maxsplit=1)[0].strip("<>")
        parsed = urlsplit(target)
        if parsed.scheme or parsed.netloc or not parsed.path:
            continue
        local_path = unquote(parsed.path)
        candidate = (path.parent / local_path).resolve()
        try:
            candidate.relative_to(ROOT)
        except ValueError:
            errors.append(
                f"{path.relative_to(ROOT)}: link escapes repository: {target}"
            )
            continue
        if not candidate.exists():
            errors.append(
                f"{path.relative_to(ROOT)}: missing local link target: {target}"
            )
    return errors


def main() -> int:
    errors: list[str] = []
    for relative in REQUIRED_FILES:
        if not (ROOT / relative).is_file():
            errors.append(f"missing required file: {relative}")

    for path in markdown_files():
        content = path.read_text(encoding="utf-8")
        errors.extend(check_fences(path, content))
        errors.extend(check_links(path, content))

    if errors:
        print("Documentation checks failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print(f"Documentation checks passed ({len(markdown_files())} Markdown files).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
