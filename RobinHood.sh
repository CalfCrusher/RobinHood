#!/usr/bin/env bash

## RobinHood - Bug Hunting Recon Automation Script
## https://github.com/CalfCrusher

## Usage: Run in background mod with: nohup ./RobinHood.sh LARGE_SCOPE_DOMAIN OUT_OF_SCOPE_LIST 2>&1 &
## Esample: nohup ./RobinHood.sh example.com vpn.example.com,test.example.com 2>&1 &

# Save starting execution time
start=`date +%s`

echo ''
echo 'RobinHood - Bug Hunting Recon Automation Script (https://github.com/CalfCrusher)'
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
NUCLEI_TEMPLATES="" # Directory templates for Nuclei (EDIT THIS)
LINKFINDER="" # Directory for LinkFinder tool (EDIT THIS)
VHOSTS_SIEVE="" # Directory for VHosts Sieve tool (EDIT THIS)
CLOUD_ENUM="" # Directory for cloud_enum, Multi-cloud OSINT tool (EDIT THIS)

SUBFINDER=$(command -v subfinder)
AMASS=$(command -v amass)
SUBLIST3R=$(command -v sublist3r)
HTTPX=$(command -v httpx)
GF=$(command -v gf)
GAU=$(command -v gau)
QSREPLACE=$(command -v qsreplace)
SUBJACK=$(command -v subjack)
GOWITNESS=$(command -v gowitness)
JSUBFINDER=$(command -v jsubfinder)
NUCLEI=$(command -v nuclei)
NMAP=$(command -v nmap)
SUBJS=$(command -v subjs)

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

# Check live subdomains and status code
cat subdomains_$HOST.txt | $HTTPX -silent -mc 200,403,404,500 | tee live_subdomains_$HOST.txt

# Scan with NMAP and Vulners
if [ ! -z "$VULSCAN_NMAP_NSE" ]
then
    $NMAP -Pn -sV -oN nmap_results_$HOST.txt -iL subdomains_$HOST.txt --script=$VULSCAN_NMAP_NSE -T2 --top-ports 1000
    sed -i '/Failed to resolve/d' nmap_results_$HOST.txt
fi

# Get screenshots of subdomains
$GOWITNESS file -f live_subdomains_$HOST.txt

# Searching for virtual hosts
python3 $VHOSTS_SIEVE -d live_subdomains_$HOST.txt -o vhost_$HOST.txt

# Searching for public resources in AWS, Azure, and Google Cloud
python3 $CLOUD_ENUM -kf live_subdomains_$HOST.txt

# Search for secrets
$JSUBFINDER search -f live_subdomains_$HOST.txt -s -o jsubfinder_secrets_$HOST.txt

# Get URLs with gau
cat live_subdomains_$HOST.txt | $GAU --mc 200 --blacklist png,jpg,gif,jpeg,swf,woff,gif,svg | tee live_urls_$HOST.txt

# Extracts js endpoints
cat live_urls_$HOST.txt | $SUBJS | tee javascript_urls_$HOST.txt

# Discover others endpoints and params from javascript urls list
python3 $LINKFINDER -i javascript_urls_$HOST.txt -o linkfinder_results_$HOST.html

# Run Nuclei on all urls
if [ ! -z "$NUCLEI_TEMPLATES" ]
then
    $NUCLEI -silent -t $NUCLEI_TEMPLATES -list live_urls_$HOST.txt -timeout 10 -rl 10 -bs 5 -c 5 -hc 2 -es info -o nuclei_results_$HOST.txt
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
cat xss_urls_$HOST.txt | $QSREPLACE -a | tee xss_urls_$HOST.txt

# Extract urls with possible SQLi params
cat live_urls_$HOST.txt | $GF sqli > sqli_urls_$HOST.txt
cat sqli_urls_$HOST.txt | $QSREPLACE -a | tee sqli_urls_$HOST.txt

# Extract urls with possible LFI params
cat live_urls_$HOST.txt | $GF lfi > lfi_urls_$HOST.txt
cat lfi_urls_$HOST.txt | $QSREPLACE -a | tee lfi_urls_$HOST.txt

# Extract urls with possible SSRF params
cat live_urls_$HOST.txt | $GF ssrf > ssrf_urls_$HOST.txt
cat ssrf_urls_$HOST.txt | $QSREPLACE -a | tee ssrf_urls_$HOST.txt

# Extract urls with possible OPEN REDIRECT params
cat live_urls_$HOST.txt | $GF redirect > redirect_urls_$HOST.txt
cat redirect_urls_$HOST.txt | $QSREPLACE -a | tee redirect_urls_$HOST.txt

# Search for subdomains takeover
if [ ! -z "$FINGERPRINTS" ]
then
    $SUBJACK -w subdomains_$HOST.txt -t 50 -timeout 25 -o sub_takeover_$HOST.txt -ssl -c $FINGERPRINTS -v
fi

# Test for basic SSRF using Burp Collaborator
if [ ! -z "$BURP_COLLAB_URL" ]
then
    cat ssrf_urls_$HOST.txt | grep "=" | $QSREPLACE $BURP_COLLAB_URL
fi

# Save finish execution time
end=`date +%s`
echo ''
echo "********* COMPLETED ! *********"
echo ''
echo "Fork it on https://github.com/CalfCrusher/RobinHood and make the world a better place"
echo ''
echo Execution time was `expr $end - $start` seconds
