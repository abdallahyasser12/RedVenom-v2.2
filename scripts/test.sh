#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for command_name in bash python3; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        printf 'Required local test command is missing: %s\n' "$command_name" >&2
        exit 2
    fi
done

printf '\n== Bash syntax ==\n'
bash -n redvenom.sh

printf '\n== Python syntax ==\n'
python3 -m compileall -q scripts tests

printf '\n== Documentation and local links ==\n'
python3 scripts/check_docs.py

printf '\n== Unit and contract tests ==\n'
PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
    python3 -m unittest discover -s tests -p 'test_*.py' -v

printf '\nAll local checks passed. No network scans or external API calls were made by this runner.\n'
