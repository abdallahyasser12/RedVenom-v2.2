#!/usr/bin/env python3
"""Fail-fast dependency check for the currently implemented RedVenom workflow."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path
from typing import Callable

REQUIRED_COMMANDS = (
    "subfinder",
    "httpx",
    "gau",
    "paramspider",
    "arjun",
    "sqlmap",
    "curl",
    "jq",
)


def check_dependencies(
    which: Callable[[str], str | None] = shutil.which,
    cwd: Path | None = None,
) -> tuple[list[str], list[str]]:
    """Return missing required dependencies and missing optional dependencies."""
    root = cwd or Path.cwd()
    missing = [name for name in REQUIRED_COMMANDS if not which(name)]

    if not which("xsstrike") and not (root / "XSStrike" / "xsstrike.py").is_file():
        missing.append("xsstrike (command or XSStrike/xsstrike.py)")

    optional_missing = [] if which("nuclei") else ["nuclei"]
    return missing, optional_missing


def main() -> int:
    missing, optional_missing = check_dependencies()
    if missing:
        print("Missing required RedVenom dependencies:", file=sys.stderr)
        for name in missing:
            print(f"  - {name}", file=sys.stderr)
        print(
            "Install the missing tools before running the workflow. "
            "See docs/INSTALLATION.md.",
            file=sys.stderr,
        )
        return 1

    if optional_missing:
        print(
            "Optional tools not found (their stages will be skipped): "
            + ", ".join(optional_missing),
            file=sys.stderr,
        )

    print("Dependency preflight passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
