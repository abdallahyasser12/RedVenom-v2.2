# Maintenance and verification status

This document records the current maintenance practices and known implementation gaps. It distinguishes local checks from runtime behavior that has not been validated in a live assessment.

## Repository layout

- redvenom.sh: interactive Bash orchestration and embedded payload/response-matching routines.
- README.md: project overview and entry point.
- docs/: installation, safety, and maintenance documentation.
- scripts/check_docs.py: standard-library documentation and local-link checker.

## Local checks

Run these from the repository root:

```bash
bash -n redvenom.sh
python3 scripts/check_docs.py
```

If ShellCheck is installed, it can provide an additional static review:

```bash
shellcheck redvenom.sh
```

Review ShellCheck findings rather than blindly auto-fixing them. The script uses interactive prompts, background processes, and external tools. The repository does not currently publish a CI status or claim that ShellCheck is clean.

The documentation checker validates required documentation files, balanced Markdown code fences, and local Markdown links. It does not run the scanner, install third-party dependencies, validate remote URLs, or prove that instructions work on every distribution.

## Current gaps for future engineering work

1. Scope enforcement: no canonical scope file or per-request host allowlist is enforced across discovered URLs.
2. Dry run: there is no mode that prints planned actions without sending network traffic.
3. Request budgeting: bounded per-stage concurrency can be configured with environment variables; a global request-rate limiter and engagement-wide request budget are still absent.
4. Run retention: each invocation now writes to a unique `recon_venom/runs/<timestamp>-<pid>/` directory, preserving prior results. A cleanup policy is still needed because old runs accumulate.
5. Dependency preflight: missing dependencies do not consistently stop execution before later stages call missing commands.
6. VPN integration: cleanup now records a PID and checks the process name before signaling; a local integration test with the installed OpenVPN binary and configuration is still required.
7. Finding validation: heuristic output is now labeled as candidate observations; stronger evidence gates and dedicated regression coverage are still needed before any built-in check can claim a confirmed vulnerability.
8. Reproducible testing: no safe local test harness currently covers the orchestration flow or built-in detection routines.

These are known limitations, not claims that the repository has already solved them. Changes that address them should include focused tests and preserve explicit authorization boundaries.

## Dependency maintenance

- Install tools from their upstream projects and review each project's release notes before upgrading.
- Record tested tool versions in bug reports when behavior changes.
- Do not vendor third-party tools into this repository unless their licenses and update responsibilities have been reviewed.
- Re-check CLI names and flags after upgrades. RedVenom expects the ProjectDiscovery httpx binary, not a different tool with the same command name.
- Treat external AI provider behavior and data handling as a separate dependency boundary.

## Release discipline

Before publishing a change:

1. Review the complete diff and confirm no API keys, target data, scan outputs, or local configuration files are included.
2. Run bash -n redvenom.sh after shell changes.
3. Run python3 scripts/check_docs.py after documentation changes.
4. Run ShellCheck when available and record unresolved findings.
5. Test network behavior only in a lab or environment for which you have explicit authorization.
6. Update this document when implementation limitations change; do not claim a control exists until it is implemented and tested.

## Project and version notes

The repository name is RedVenom-v2.2. The script contains older internal comments and console text referring to other RedVenom version labels. Until a single version constant and release process are introduced, use the repository name when referring to this source snapshot and avoid implying that every internal label represents a separately published release.
