# Safety, scope, and data handling

RedVenom is a security testing utility. Its current implementation performs active requests and should be treated as potentially intrusive. A repository disclaimer is not a substitute for authorization, a tested scope boundary, or operator controls.

## Required before use

1. Obtain written authorization from the system owner.
2. Confirm that the exact root domain, discovered subdomains, URL paths, and third-party services are in scope. A domain's DNS relationship does not automatically authorize testing every host returned by discovery.
3. Confirm that active scanning, parameter discovery, fuzzing, SQL injection checks, XSS checks, and Nuclei templates are permitted by the engagement rules.
4. Agree on request volume, timing, test accounts, data-handling rules, and an emergency contact.
5. Prefer a disposable staging environment. Do not start with production systems or targets whose owners have not approved intrusive tests.
6. Preserve a backup of any output you need before starting another run.

## Current implementation behaviors to understand

The following observations are based on the checked-in `redvenom.sh` and are not hypothetical future features:

- **Defense-in-depth scope filtering, not a network boundary:** the script validates a bare root hostname/IP and filters discovered host/URL lists to that root or its subdomains before downstream processing. This does not constrain every request an external tool may make, follow redirects, or contact third parties. A true network-level allowlist and dry-run are still absent.
- **Active traffic:** it invokes SQLMap, XSStrike, Nuclei, and built-in payload routines. The payload lists include probes for XSS, SQL injection, local-file inclusion, server-side request forgery, server-side template injection, command execution, redirects, and JSON input handling.
- **Concurrent requests:** several stages run jobs in the background. The script does not expose an operator-configurable global rate limit or a reliable engagement-wide request budget.
- **Run-specific output and manifest:** each invocation writes under a unique `recon_venom/runs/<timestamp>-<pid>/` directory and creates `run_manifest.json` with the target root, timing, available tool versions, artifact names, sizes, and hashes. The manifest does not include raw artifact contents, but target identifiers and filenames can still be sensitive. Results are retained until an operator removes them; plan storage and retention accordingly.
- **Generated payload files:** payload files are written under the current run's `payloads/` directory, avoiding shared repository-root payload paths.
- **Run-owned VPN cleanup:** the VPN option starts OpenVPN with a per-run PID file and only attempts to stop the recorded PID after checking that its process name is `openvpn`. An already-running OpenVPN process is left untouched. This code path has not been integration-tested against a live local VPN configuration; validate it in a disposable environment before relying on it.
- **Heuristic response matching:** built-in checks look for simple response strings. These checks can produce false positives and false negatives; they do not prove exploitability or impact.
- **External AI processing:** the optional OpenRouter features send prompts and selected local scan-output excerpts to an external API. Review what data is included and whether disclosure is authorized.

- **TLS verification and request timeouts:** built-in curl requests use normal certificate verification (no `--insecure` / `-k`) and bounded connect/total timeouts. Third-party scanner TLS behavior is managed by those tools and must be reviewed separately.

## Safe operating boundaries

- **Private file creation:** the shell sets `umask 077` before creating run artifacts. Newly created files and directories therefore default to owner-only permissions on normal POSIX tools. This does not retroactively change existing paths, and a third-party tool may explicitly override inherited permissions; review the resulting run directory before sharing it.
- Run from a dedicated, disposable working copy and a non-privileged user account whenever possible.
- Do not use `sudo` to run RedVenom itself. The script's optional VPN path may invoke `sudo` internally.
- Do not use real customer credentials, session cookies, production data, or secrets in test workflows.
- Do not treat a discovered subdomain, archived URL, or third-party-hosted asset as automatically in scope.
- Stop the run if the target owner reports instability, unexpected load, data changes, or out-of-scope traffic.
- Keep scan output private. It may contain hostnames, paths, parameters, response excerpts, and other sensitive assessment data.
- Redact target identifiers and sensitive values before creating public issues or support requests.

## Findings are leads, not proof

A string match or scanner alert is a candidate observation, not a confirmed vulnerability. RedVenom labels heuristic matches as candidates for human review. Confirm the behavior with a controlled reproduction, verify the affected identity and authorization boundary, assess impact, and document limitations before describing it as a vulnerability. A clean run is not evidence that an application is secure.

## Known safety work still needed

The project needs, at minimum, a scope allowlist applied to every discovered URL before requests are sent, a true no-network dry-run mode, configurable rate and concurrency budgets, non-destructive run-specific output directories, dependency preflight that fails closed, and VPN process ownership that terminates only the process RedVenom started. Until those controls exist and are tested, operators must enforce scope and operational limits externally.
