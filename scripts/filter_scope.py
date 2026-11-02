#!/usr/bin/env python3
"""Keep only URLs whose host is the authorized root domain or its subdomain.

This is a defense-in-depth list filter. It is not a network proxy and cannot
prevent an external scanner from following redirects or making its own requests.
"""

from __future__ import annotations

import argparse
import ipaddress
import sys
from pathlib import Path
from urllib.parse import urlsplit

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from scripts.validate_target import normalize_target


def host_is_in_scope(host: str, root: str) -> bool:
    try:
        normalized_host = normalize_target(host)
    except ValueError:
        return False

    try:
        root_ip = ipaddress.ip_address(root)
    except ValueError:
        root_ip = None

    if root_ip is not None:
        try:
            return ipaddress.ip_address(normalized_host) == root_ip
        except ValueError:
            return False

    try:
        ipaddress.ip_address(normalized_host)
        return False
    except ValueError:
        pass

    return normalized_host == root or normalized_host.endswith("." + root)


def entry_host(value: str) -> str | None:
    candidate = value.strip()
    if not candidate or any(char.isspace() for char in candidate):
        return None

    if "://" in candidate:
        parsed = urlsplit(candidate)
        if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        return parsed.hostname

    if any(char in candidate for char in "/?#@"):
        return None
    return candidate


def filter_entries(root_value: str, lines: list[str]) -> tuple[list[str], int]:
    root = normalize_target(root_value)
    accepted: list[str] = []
    rejected = 0

    for line in lines:
        value = line.strip()
        if not value:
            continue
        host = entry_host(value)
        if host and host_is_in_scope(host, root):
            accepted.append(line.rstrip("\r\n"))
        else:
            rejected += 1

    return accepted, rejected


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, help="Authorized root hostname or IP")
    parser.add_argument("--input", required=True, type=Path, help="Input list")
    parser.add_argument("--output", required=True, type=Path, help="Filtered output")
    args = parser.parse_args()

    try:
        source = args.input.read_text(encoding="utf-8").splitlines()
        accepted, rejected = filter_entries(args.root, source)
    except (OSError, ValueError) as exc:
        print(f"Scope filter failed: {exc}", file=sys.stderr)
        return 2

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        "".join(line + "\n" for line in accepted),
        encoding="utf-8",
    )
    print(
        f"Scope filter: kept {len(accepted)} in-scope entries; "
        f"discarded {rejected} out-of-scope or invalid entries.",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
