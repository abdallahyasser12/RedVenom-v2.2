# Security Policy

## Supported versions

RedVenom is an independently maintained, early-stage project. Security fixes are generally considered for the current default branch. Older snapshots and forks may not receive updates; check the repository's commit history before relying on a fix.

## Reporting a vulnerability

Please do not disclose suspected vulnerabilities, exploit details, credentials, session data, private target information, or scan output in a public GitHub issue or pull request.

1. Prefer GitHub's **Report a vulnerability** option in the repository's Security tab when private vulnerability reporting is enabled.
2. If that option is unavailable, contact the maintainer privately through the contact method on the maintainer's GitHub profile.
3. Include only the minimum information needed to understand and reproduce the issue safely: affected commit or version, affected component, impact, prerequisites, and a minimal reproduction using a local test fixture or a system you own.
4. Redact tokens, API keys, VPN profiles, cookies, customer data, and third-party target identifiers from all material.

Do not test the project against systems you do not own or have explicit written permission to assess. Do not access, modify, or retain other users' data while investigating a report.

## What to expect

The maintainer will review reports as time and availability permit and may ask for additional information. There is no guaranteed response time, service-level agreement, paid bug bounty, or commitment to issue a CVE. Please coordinate disclosure privately and allow time for a fix before publishing details.

## Scope

Reports about vulnerabilities in this repository's code, documentation, packaging, or supported workflows are in scope for review. A vulnerability in an external scanner or service should be reported to that upstream project's security team; include only enough context to explain how RedVenom integrates with it.

This policy does not grant authorization to scan any target and does not expand the project's permitted-use boundaries.
