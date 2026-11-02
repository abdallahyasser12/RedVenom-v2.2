# RedVenom v2.2

**A Bash-based workflow for authorized web reconnaissance and security testing.**

RedVenom combines established command-line tools for host discovery, historical URL collection, parameter discovery, vulnerability scanning, and result collection. It is intended for security practitioners working on assets they own or have explicit written permission to assess.

> **Read before running:** RedVenom is an early-stage, interactive prototype—not a production-grade scanner or a safe passive-recon-only tool. The current script sends active test payloads, runs third-party scanners, and has broad VPN cleanup behavior. Review the documented operational risks before executing it. Review [the safety notes](docs/SAFETY.md) before executing it.

## What it currently does

The checked-in `redvenom.sh` orchestrates these tools when they are installed and available:

| Stage | Tooling | Purpose |
| --- | --- | --- |
| Passive discovery | Subfinder | Enumerate candidate subdomains from passive sources |
| Historical URL collection | gau | Collect URLs known to public web archives |
| HTTP probing | ProjectDiscovery httpx | Identify responding hosts from discovered subdomains |
| Parameter discovery | ParamSpider, Arjun | Gather archived and candidate HTTP parameters |
| Active checks | SQLMap, XSStrike | Run focused SQL injection and XSS testing against collected URLs |
| Additional probes | Built-in Bash/curl routines | Send experimental payloads and look for response patterns |
| Template scanning | Nuclei | Run templates against the collected URL list |
| Optional AI assistance | OpenRouter API | Interactive Q&A and a text summary of selected output files |

The presence of a tool in this table does not mean every stage is reliably guarded when that dependency is missing. See [installation and dependency notes](docs/INSTALLATION.md) and [known limitations](docs/MAINTENANCE.md).

## Requirements

- Linux or a Linux environment such as WSL2.
- Bash 4 or newer.
- Git, Go, Python 3, `curl`, `jq`, and standard command-line utilities.
- The scanner tools listed in [Installation](docs/INSTALLATION.md) for a complete run.

RedVenom does not currently ship a dependency lockfile, installer, container image, automated integration-test suite, or built-in scope allowlist/dry-run mode. Install third-party tools separately and review their licenses and documentation.

## Installation

Clone the repository and enter the actual directory name:

```bash
git clone https://github.com/abdallahyasser12/RedVenom-v2.2.git
cd RedVenom-v2.2
```

Follow the step-by-step [installation guide](docs/INSTALLATION.md). Before any scan, perform the local syntax check:

```bash
bash -n redvenom.sh
```

A successful syntax check only confirms that Bash can parse the script; it does not validate scanner behavior, target scope, or safety.

## Running

**Do not run this against a domain just because it is publicly reachable.** First confirm that the exact domain and all discovered subdomains are explicitly in scope, that active scanning and fuzzing are permitted, and that the system owner has approved the expected request volume and test methods.

After reviewing [Safety and operational risks](docs/SAFETY.md), start the interactive script from the repository root:

```bash
chmod +x redvenom.sh
./redvenom.sh
```

The current interface asks for a target domain and a VPN choice, then proceeds through discovery, parameter collection, active scanning, fuzzing, Nuclei, and an optional AI menu. It does not provide a reliable dry run or a complete per-request scope enforcement mechanism.

## Output and local state

The script writes each invocation under a unique `recon_venom/runs/<UTC timestamp>-<process id>/` directory. Payload files and scan outputs are kept inside that run directory, so a later invocation does not overwrite or delete earlier results. Treat these directories as generated, potentially sensitive scan data. They are not automatically pruned; manage retention and backups deliberately. Do not commit them or upload them without the target owner's approval.

The repository `.gitignore` excludes common generated outputs, local environments, and the optional `XSStrike/` checkout. It is not a substitute for checking `git status` before committing.

## Optional OpenRouter integration

The AI features are optional. The current script reads an API key from `~/.openrouter_key`:

```bash
umask 077
read -r -s -p 'OpenRouter API key: ' OPENROUTER_API_KEY
echo
printf '%s' "$OPENROUTER_API_KEY" > "$HOME/.openrouter_key"
unset OPENROUTER_API_KEY
chmod 600 "$HOME/.openrouter_key"
```

Do not paste keys into source files, command history, issue reports, or commits. Review the data sent to the provider before enabling AI summaries; the script includes excerpts from local scan output in its API request.

## Documentation

- [Installation and dependency setup](docs/INSTALLATION.md)
- [Safety, scope, and data handling](docs/SAFETY.md)
- [Maintenance status and verification](docs/MAINTENANCE.md)
- [Contributing](CONTRIBUTING.md)
- [MIT License](LICENSE)

## Project status and claims

RedVenom is an independently maintained, early-stage security automation project. Its output is exploratory and must be manually validated. The built-in response matching is heuristic; it is not a proof engine and can produce false positives or miss vulnerabilities. A completed run does not establish that a target is secure.

The related VulnGPT work at NovaSecLabs is a separate application-security research and product effort. RedVenom is not the VulnGPT scanning engine, and this repository does not include VulnGPT's proprietary implementation.

## Responsible use

Use RedVenom only on systems you own or are explicitly authorized to test, within written scope and agreed operating limits. You are responsible for complying with applicable law, program rules, and third-party tool terms. See [Safety](docs/SAFETY.md) before use.
