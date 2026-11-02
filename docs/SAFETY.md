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

- **No enforced scope allowlist or dry-run:** the script accepts a free-form target string and does not provide a complete per-request authorization boundary for URLs discovered by its tools.
- **Active traffic:** it invokes SQLMap, XSStrike, Nuclei, and built-in payload routines. The payload lists include probes for XSS, SQL injection, local-file inclusion, server-side request forgery, server-side template injection, command execution, redirects, and JSON input handling.
- **Concurrent requests:** several stages run jobs in the background. The script does not expose an operator-configurable global rate limit or a reliable engagement-wide request budget.
- **Prior output deletion:** at startup it runs `rm -rf recon_venom/*`. Existing files inside that directory are deleted. Back up any results you need before rerunning.
- **Generated payload files:** it writes files under `payloads/`, replacing files with matching names.
- **Broad VPN cleanup:** when the VPN option is enabled, it starts OpenVPN using `~/vpn-config.ovpn` and later runs `sudo killall openvpn`. This can stop unrelated OpenVPN processes on the same machine. Avoid the VPN option until this behavior is redesigned.
- **Heuristic response matching:** built-in checks look for simple response strings. These checks can produce false positives and false negatives; they do not prove exploitability or impact.
- **External AI processing:** the optional OpenRouter features send prompts and selected local scan-output excerpts to an external API. Review what data is included and whether disclosure is authorized.

## Safe operating boundaries

- Run from a dedicated, disposable working copy and a non-privileged user account whenever possible.
- Do not use `sudo` to run RedVenom itself. The script's optional VPN path may invoke `sudo` internally.
- Do not use real customer credentials, session cookies, production data, or secrets in test workflows.
- Do not treat a discovered subdomain, archived URL, or third-party-hosted asset as automatically in scope.
- Stop the run if the target owner reports instability, unexpected load, data changes, or out-of-scope traffic.
- Keep scan output private. It may contain hostnames, paths, parameters, response excerpts, and other sensitive assessment data.
- Redact target identifiers and sensitive values before creating public issues or support requests.

## Findings are leads, not proof

A string match or scanner alert is an observation that requires human review. Confirm the behavior with a controlled reproduction, verify the affected identity and authorization boundary, assess impact, and document limitations before describing it as a vulnerability. A clean run is not evidence that an application is secure.

## Known safety work still needed

The project needs, at minimum, a scope allowlist applied to every discovered URL before requests are sent, a true no-network dry-run mode, configurable rate and concurrency budgets, non-destructive run-specific output directories, dependency preflight that fails closed, and VPN process ownership that terminates only the process RedVenom started. Until those controls exist and are tested, operators must enforce scope and operational limits externally.
