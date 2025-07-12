🐍 RedVenom v2.2
RedVenom is a powerful Bash-based offensive security automation tool designed for bug bounty hunters and penetration testers. It automates recon, scanning, fuzzing, and AI-assisted reporting in a fast, parallelized workflow.

🧑‍💻 Created by Abdallah Yasser — Bug Hunter | Red Team Enthusiast

🚀 Features
🔍 Automated Reconnaissance
Subdomain enumeration with subfinder

URL extraction with gau

Live host detection with httpx

Parameter discovery with ParamSpider

🛡️ Vulnerability Scanning
SQLi detection with SQLMap

XSS detection with XSStrike

💥 Fuzzing Engine
Embedded payloads for:

XSS

SQLi

LFI

RCE

SSTI

SSRF

Open Redirect

JSON Injection

Parallelized fuzzing with detailed logging

🤖 AI Assistant
Ask RedVenom AI anything during recon or fuzzing

Automatically generates summary reports using the OpenAI API

🌐 VPN Integration (Optional)
Automatically starts and disconnects your VPN using openvpn

🛠️ Installation

git clone https://github.com/AbdallahYasser1213/RedVenom
cd RedVenom
chmod +x redvenom.sh
./redvenom.sh

📦 Dependencies
Ensure the following tools are installed:

subfinder

httpx

gau

paramspider

sqlmap

XSStrike

curl, jq, sed, grep, bash

Optional: openvpn, python3

Install common dependencies:


sudo apt install jq curl python3
📂 Output
All results are saved in the recon_venom/ directory:

subdomains.txt, httpx_live.txt, gau_urls.txt

all_cleaned_urls.txt — merged & filtered targets

sqlmap_results/, xsstrike_results.txt

fuzzing_log.txt — tested payloads per URL

ai_report.txt — AI-generated security summary

🤖 AI Integration
To use RedVenom AI:

Get your OpenAI API key

Save it as ~/.openai_key (or enter it when prompted)

Let RedVenom generate vulnerability summaries and answer security queries

🧪 Sample Usage

./redvenom.sh
🔎 Example RedVenom AI Prompts
"Summarize my XSS scan results"

"Any critical findings in the recon phase?"

"What’s the most likely exploitable vector?"

🧠 Fuzzing Payload Coverage
Category	Payload Examples
XSS	<script>alert(1)</script>
SQLi	' OR 1=1 --
LFI	../../../../etc/passwd
RCE	; ping -c 1 127.0.0.1
SSTI	{{7*7}}, <%= 7 * 7 %>
SSRF	http://127.0.0.1
Open Redirect	/?next=http://evil.com
JSON Injection	{"input":"<script>alert(1)</script>"}

🧼 Cleanup
If VPN was enabled, RedVenom auto-disconnects it after execution.

⚠️ Disclaimer
This tool is for educational and authorized penetration testing only. Unauthorized use is strictly prohibited.

📃 License
MIT License
