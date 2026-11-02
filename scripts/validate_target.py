#!/usr/bin/env python3
"""Validate and normalize a single DNS hostname or IP address."""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys


def normalize_target(value: str) -> str:
    raw = value.strip()
    if not raw:
        raise ValueError("target is empty")
    if any(character.isspace() for character in raw):
        raise ValueError("whitespace is not permitted in a target")
    if any(character in raw for character in "/?#@"):
        raise ValueError("enter a hostname or IP address, not a URL or path")

    candidate = raw[1:-1] if raw.startswith("[") and raw.endswith("]") else raw
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        pass

    if ":" in candidate:
        raise ValueError("ports are not accepted; enter only the hostname")

    try:
        hostname = candidate.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("target is not a valid internationalized hostname") from exc

    if len(hostname) > 253:
        raise ValueError("hostname exceeds 253 characters")

    labels = hostname.split(".")
    if len(labels) < 2:
        raise ValueError("enter a fully qualified hostname with at least two labels")

    label_pattern = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    if any(not label_pattern.fullmatch(label) for label in labels):
        raise ValueError("hostname contains an invalid DNS label")

    if len(labels[-1]) < 2:
        raise ValueError("top-level DNS label must contain at least two characters")

    return hostname


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Bare DNS hostname or IP address")
    args = parser.parse_args()

    try:
        print(normalize_target(args.target))
    except ValueError as exc:
        print(f"Invalid target: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
