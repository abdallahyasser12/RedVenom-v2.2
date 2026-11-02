# Contributing to RedVenom

Thank you for considering a contribution. RedVenom is an early-stage, MIT-licensed security automation project. Contributions should improve reliability, clarity, responsible use, or maintainability without weakening authorization boundaries.

## Before opening a change

- Search existing issues and pull requests to avoid duplicate work.
- For a substantial change, open an issue first and describe the problem, expected behavior, affected workflow, and validation plan.
- Never include API keys, VPN profiles, credentials, session cookies, private target data, raw customer responses, or scan output from systems you do not own.
- Do not add target-specific payloads, hard-coded customer domains, or logic that bypasses authorization or program scope.

## Development workflow

1. Fork the repository.
2. Create a focused branch from `main`.
3. Make the smallest coherent change.
4. Add or update documentation for changed commands, dependencies, outputs, and safety implications.
5. Run the relevant local checks listed below.
6. Open a pull request describing the change, its risks, and the evidence used to validate it.

## Local checks

For changes to the Bash script:

```bash
bash -n redvenom.sh
```

When available, also run:

```bash
shellcheck redvenom.sh
```

For documentation changes:

```bash
python3 scripts/check_docs.py
```

The repository does not yet have a scanner integration-test harness. Do not claim that a change is fully tested merely because the shell parser or documentation checker passes. Any network testing must use an isolated lab or a target with explicit written authorization.

## Pull request expectations

Include:

- The problem and the intended behavior change.
- Files and workflows affected.
- Commands run and their actual results.
- Any tests not run and why.
- Security, privacy, compatibility, and operational risks.
- Documentation updates and any remaining limitations.

Keep pull requests focused. Avoid mixing refactors, new scanner capabilities, dependency upgrades, and unrelated documentation edits in one change unless they are inseparable.

## Security reports

Do not publish sensitive vulnerability details, secrets, exploit material, or private target information in a public issue. Contact the maintainer privately through the contact method listed on the maintainer's GitHub profile and include only the minimum information needed to coordinate a responsible fix.

## Code of conduct

Be respectful, factual, and constructive. Assume good intent, explain disagreements with technical evidence, and respect maintainers' decisions about project scope and release timing.
