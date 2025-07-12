# 🐍 RedVenom v2.2 — Offensive Security Automation Framework

**RedVenom** is a powerful Bash-based offensive security automation tool designed for **bug bounty hunters** and **penetration testers**.  
It automates **recon**, **vulnerability scanning**, **fuzzing**, and **AI-assisted reporting** in a fast, parallelized workflow.

---

### 👨‍💻 Created by
**Abdallah Yasser** — Bug Hunter | Red Team Enthusiast

---

## 🚀 Features

### 🔍 Automated Reconnaissance
- 🌐 Subdomain enumeration with `subfinder`
- 🕸️ URL extraction using `gau`
- ⚡ Live host detection via `httpx`
- 🎯 Parameter discovery with `ParamSpider`

### 🛡️ Vulnerability Scanning
- 💉 SQL Injection detection with `SQLMap`
- 🧪 XSS detection with `XSStrike`

### 💥 Fuzzing Engine
Parallelized fuzzing with embedded payloads for:
- [XSS]
- [SQL Injection]
- [LFI]
- [RCE]
- [SSTI]
- [SSRF]
- [Open Redirect]
- [JSON Injection]

✔️ Fuzzing is logged in detail to `fuzzing_log.txt`.

### 🤖 AI Assistant (RedVenom AI)
- Ask anything during recon or fuzzing
- Auto-generates summary reports
- Powered by **OpenRouter** (`mistralai/mistral-7b-instruct`)

### 🌐 VPN Integration (Optional)
- Automatically starts & disconnects VPN using `openvpn`

---

## 🛠️ Installation

git clone https://github.com/AbdallahYasser1213/RedVenom
cd RedVenom
chmod +x redvenom.sh
./redvenom.sh
📦 Dependencies
Ensure the following tools are installed and in your $PATH:

subfinder

httpx

gau

paramspider

sqlmap

XSStrike

curl, jq, sed, grep, bash

Optional: openvpn, python3

Quick install for common dependencies:

sudo apt install curl jq python3 -y
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/lc/gau@latest
pip3 install xsstrike paramspider

🤖 AI Integration Setup
To use RedVenom AI:

Get a free API key from https://openrouter.ai

Save your key to ~/.openrouter_key:


echo "sk-or-xxxxxxxxxxxxxxxxxxxxxxxx" > ~/.openrouter_key
chmod 600 ~/.openrouter_key
RedVenom will use it to:

Answer your recon/fuzzing questions

Generate auto summary in ai_report.txt

📁 Output Directory
All results are saved in recon_venom/:


├── subdomains.txt
├── gau_urls.txt
├── httpx_live.txt
├── paramspider_raw.txt
├── all_cleaned_urls.txt
├── sqlmap_results/
├── xsstrike_results.txt
├── fuzzing_log.txt
└── ai_report.txt
🧠 Fuzzing Payload Coverage
Category	Example Payloads
XSS	<script>alert(1)</script>

SQLi	' OR 1=1 --

LFI	../../../../etc/passwd

RCE	; ping -c 1 127.0.0.1

SSTI	{{7*7}}, <%= 7 * 7 %>

SSRF	http://127.0.0.1

Open Redirect	/?next=http://evil.com

JSON Injection	{"input":"<script>alert(1)</script>"}

🧪 Sample Usage

./redvenom.sh
You’ll be prompted for:

✅ Target domain (e.g. example.com)

🔐 VPN toggle

⚙️ URL filtering

🤖 AI queries after scan

💡 Example RedVenom AI Prompts
"Summarize my XSS scan results"

"Any critical findings in the recon phase?"

"What’s the most likely exploitable vector?"

🧼 Cleanup
If VPN was enabled, RedVenom will automatically disconnect openvpn after execution.

⚠️ Disclaimer
This tool is for educational use and authorized penetration testing only.
Do NOT scan targets without permission. Unauthorized use is illegal and unethical.

📃 License
MIT License — Feel free to use, modify, and contribute.

⭐ Support the Project
If RedVenom helps you:

⭐ Star the repo

🍴 Fork it and contribute

💬 Share it with other hackers
