# Installation

This guide documents the dependencies used by the current `redvenom.sh`. It does not install or pin a single tested toolchain: the repository has no lockfile or installer, and upstream tools release independently. Check each upstream project's current instructions before installing or updating it.

## 1. Base environment

The script is written for Bash and uses GNU/Linux-style command-line utilities. Use a current Linux distribution or WSL2 with a Linux distribution installed.

On Debian, Ubuntu, or Kali, install the basic packages:

```bash
sudo apt update
sudo apt install -y bash git curl jq python3 python3-venv python3-pip
```

The script uses `mapfile`, so use Bash 4 or newer. Confirm the basic tools are available:

```bash
bash --version
python3 --version
git --version
curl --version
jq --version
```

## 2. Get the repository

```bash
git clone https://github.com/abdallahyasser12/RedVenom-v2.2.git
cd RedVenom-v2.2
```

## 3. Install the Python command-line tools

Use a virtual environment so Python packages are not installed into the operating system's managed Python environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install arjun sqlmap
```

Install ParamSpider from its upstream repository. The upstream README documents cloning the project and installing it from the checkout:

```bash
mkdir -p "$HOME/tools"
git clone https://github.com/devanshbatham/ParamSpider.git "$HOME/tools/ParamSpider"
python -m pip install "$HOME/tools/ParamSpider"
```

Install XSStrike in the repository's `XSStrike/` directory. The current RedVenom script has a fallback that invokes `python3 XSStrike/xsstrike.py` when it finds that exact path:

```bash
git clone https://github.com/s0md3v/XSStrike.git XSStrike
python -m pip install -r XSStrike/requirements.txt
```

Keep the `.venv` activated when running RedVenom so `arjun`, `paramspider`, and `sqlmap` resolve from that environment and XSStrike can import its installed dependencies.

## 4. Install the Go-based tools

The current script uses Subfinder, ProjectDiscovery httpx, Nuclei, and gau. Install a current Go release from the [official Go downloads page](https://go.dev/dl/), then install the command-line tools:

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
```

Add Go's binary directory to the current shell's `PATH`:

```bash
export PATH="$(go env GOPATH)/bin:$PATH"
```

Add the same line to the startup file for your shell if you want it to persist. The latest releases of these projects can require a recent Go toolchain; follow the upstream installation pages if a build reports a Go version requirement.

## 5. Verify command discovery

With the Python virtual environment active and Go's binary directory on `PATH`, check the exact commands RedVenom expects:

```bash
for tool in subfinder httpx gau paramspider arjun sqlmap nuclei curl jq; do
  if command -v "$tool" >/dev/null 2>&1; then
    printf 'found: %s -> %s\n' "$tool" "$(command -v "$tool")"
  else
    printf 'missing: %s\n' "$tool"
  fi
done

test -f XSStrike/xsstrike.py && echo 'found: XSStrike/xsstrike.py'
```

Be aware that another program named `httpx` may be earlier on `PATH`. RedVenom expects the ProjectDiscovery HTTP toolkit, not the Python `httpx` library or a different command with the same name. Check `httpx -version` and compare it with the [ProjectDiscovery httpx project](https://github.com/projectdiscovery/httpx).

**Important implementation limitation:** the script detects several missing tools and prints warnings, but later calls `paramspider`, `arjun`, `sqlmap`, and XSStrike without consistently stopping when they are absent. A partial installation is not a verified full run. Resolve missing dependencies before use.

## 6. Check the script without scanning

Run the parser check from the repository root:

```bash
bash -n redvenom.sh
```

This does not contact a target. It only checks Bash syntax. Do not use an arbitrary public domain as an installation test: the normal script proceeds into active scanning and fuzzing. Test network behavior only in an isolated lab that you control and have explicitly authorized.

## 7. Optional VPN integration

The current script's VPN option expects `~/vpn-config.ovpn`, invokes OpenVPN with `sudo`, and later runs `sudo killall openvpn`. That cleanup can terminate OpenVPN processes that were not started by RedVenom. For that reason, this guide does **not** recommend enabling the VPN option. Manage VPN connectivity outside RedVenom until its process lifecycle is corrected.

## 8. Optional OpenRouter integration

The current script looks for an API key in `~/.openrouter_key`. Create it without putting the key directly into the shell command history:

```bash
umask 077
read -r -s -p 'OpenRouter API key: ' OPENROUTER_API_KEY
echo
printf '%s' "$OPENROUTER_API_KEY" > "$HOME/.openrouter_key"
unset OPENROUTER_API_KEY
chmod 600 "$HOME/.openrouter_key"
```

The script sends selected scan-output excerpts and prompts to OpenRouter for its AI features. Do not send confidential customer data, secrets, personal data, or data you are not authorized to disclose to an external provider.

## Upstream installation references

- [ProjectDiscovery tools](https://projectdiscovery.io/open-source)
- [gau installation](https://github.com/lc/gau#installation)
- [ParamSpider](https://github.com/devanshbatham/ParamSpider)
- [Arjun](https://github.com/s0md3v/Arjun)
- [sqlmap](https://github.com/sqlmapproject/sqlmap)
- [XSStrike](https://github.com/s0md3v/XSStrike)
