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
echo '* Running..'
echo ''
echo ''

# Save locations of tools and file
BURP_COLLAB_URL="" # Burp Collaborator (EDIT THIS)
FINGERPRINTS="/root/fingerprints.json" # Subjack fingerprints location (EDIT THIS)
CLOUDFLAIR="/root/CloudFlair/cloudflair.py" # CloudFlair tool location (EDIT THIS)
CENSYS_API_ID="" # Censys api id for CloudFlair(EDIT THIS)
CENSYS_API_SECRET="" # Censys api secret for CloudFlir (EDIT THIS)
VULSCAN_NMAP_NSE="/root/vulscan/vulscan.nse" # Vulscan NSE script for Nmap (EDIT THIS)
JSUBFINDER_SIGN="/root/.jsf_signatures.yaml" # Signature location for jsubfinder (EDIT THIS)
NUCLEI_TEMPLATES="/root/nuclei-templates" # Directory templates for Nuclei (EDIT THIS)
LINKFINDER="/root/LinkFinder/linkfinder.py" # Directory for LinkFinder tool (EDIT THIS)
SECRETFINDER="/root/SecretFinder/SecretFinder.py" # Directory for SecretFinder tool (EDIT THIS)
VHOSTS_SIEVE="/root/vhosts-sieve/vhosts-sieve.py" # Directory for VHosts Sieve tool (EDIT THIS)
CLOUD_ENUM="/root/cloud_enum/cloud_enum.py" # Directory for cloud_enum, Multi-cloud OSINT tool (EDIT THIS)
SUBLIST3R="/root/Sublist3r/sublist3r.py" # Directory for sublist3r

SUBFINDER=$(command -v subfinder)
AMASS=$(command -v amass)
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
ANEW=$(command -v anew)

# Get large scope domain as first argument
HOST=$1

# Get list of excluded subdomains as second argument
OUT_OF_SCOPE_SUBDOMAINS=$2

# Subdomains Enumeration
python3 $SUBLIST3R -d $HOST -o subdomains_$HOST.txt
$SUBFINDER -d $HOST -silent | awk -F[ ' {print $1}' | tee -a subdomains_$HOST.txt
$AMASS enum -passive -d $HOST | tee -a subdomains_$HOST.txt

# Remove duplicated subdomains
cat subdomains_$HOST.txt | $QSREPLACE -a | tee subdomains_temp_$HOST.txt
rm subdomains_$HOST.txt
mv subdomains_temp_$HOST.txt subdomains_$HOST.txt


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
cat subdomains_$HOST.txt | $HTTPX -silent | tee live_subdomains_$HOST.txt

# Scan with NMAP and Vulners
if [ ! -z "$VULSCAN_NMAP_NSE" ]
then
    $NMAP -sV -oN nmap_results_$HOST.txt -iL subdomains_$HOST.txt --script=$VULSCAN_NMAP_NSE --top-ports 100
    sed -i '/Failed to resolve/d' nmap_results_$HOST.txt
fi

# Get screenshots of subdomains
$GOWITNESS file -f live_subdomains_$HOST.txt

# Searching for virtual hosts
python3 $VHOSTS_SIEVE -d subdomains_$HOST.txt -o vhost_$HOST.txt

# Searching for public resources in AWS, Azure, and Google Cloud
python3 $CLOUD_ENUM -k $HOST -l cloud_enum_$HOST.txt

# Search for secrets
$JSUBFINDER search -f live_subdomains_$HOST.txt -s jsubfinder_secrets_$HOST.txt

# Get URLs with gau
cat live_subdomains_$HOST.txt | $GAU --blacklist png,jpg,gif,jpeg,swf,woff,gif,svg,pdf,tiff,zip,bmp,webp,ico,txt,xml | tee all_urls_$HOST.txt

# Get live urls with httpx
cat all_urls_$HOST.txt | $HTTPX -silent | $ANEW | tee live_urls_$HOST.txt

# Extracts js urls
cat live_urls_$HOST.txt | $SUBJS | tee javascript_urls_$HOST.txt

# Remove duplicates
cat javascript_urls_$HOST.txt | $QSREPLACE -a | tee javascript_urls_temp_$HOST.txt
rm javascript_urls_$HOST.txt
mv javascript_urls_temp_$HOST.txt javascript_urls_$HOST.txt

# Remove third-part domains from js file urls
awk '/$HOST/' javascript_urls_$HOST.txt > javascript_urls_temp_$HOST.txt
rm javascript_urls_$HOST.txt
mv javascript_urls_temp_$HOST.txt javascript_urls_$HOST.txt

# Discover url endpoints in javascript urls
if [ ! -z "$LINKFINDER" ]
then
    while IFS='' read -r URL || [ -n "${URL}" ]; do
        echo "\n*** ${URL} ***\n" >> linkfinder_results_$HOST.txt
        python3 $LINKFINDER -i $URL -o cli | tee -a linkfinder_results_$HOST.txt
        echo "\n**************\n" >> linkfinder_results_$HOST.txt
    done < javascript_urls_$HOST.txt
fi

# Discover sensitive data in js files
if [ ! -z "$SECRETFINDER" ]
then
    while IFS='' read -r URL || [ -n "${URL}" ]; do
        python3 $SECRETFINDER -i $URL -o cli | tee -a secretfinder_results_$HOST.txt
    done < javascript_urls_$HOST.txt
fi

# Run Nuclei on all urls and subdomains
if [ ! -z "$NUCLEI_TEMPLATES" ]
then
    $NUCLEI -silent -t $NUCLEI_TEMPLATES -list live_urls_$HOST.txt -es info -o nuclei_urls_$HOST.txt
    $NUCLEI -silent -t $NUCLEI_TEMPLATES -list subdomains_$HOST.txt -o nuclei_subdomains_$HOST.txt
fi

# Extract cloudflare protected hosts from nuclei output
cat nuclei_subdomains_$HOST.txt | grep ":cloudflare" | awk '{print $(NF)}' | sed -E 's/^\s*.*:\/\///g' | sed 's/\///'g | tee cloudflare_hosts_$HOST.txt

# Remove duplicates
cat cloudflare_hosts_$HOST.txt | $QSREPLACE -a | tee cloudflare_hosts_temp_$HOST.txt
rm cloudflare_hosts_$HOST.txt
mv cloudflare_hosts_temp_$HOST.txt cloudflare_hosts_$HOST.txt

# Try to get origin ip using SSL certificate (cloudflair and censys)
if [ ! -z "$CENSYS_API_ID" ]
then
    while IFS='' read -r DOMAIN || [ -n "${DOMAIN}" ]; do
        python3 $CLOUDFLAIR $DOMAIN --censys-api-id $CENSYS_API_ID --censys-api-secret $CENSYS_API_SECRET | tee -a origin_$HOST.txt
        sleep 15
    done < cloudflare_hosts_$HOST.txt
fi

# Extract urls with possible XSS params
cat live_urls_$HOST.txt | $GF xss > xss_urls_$HOST.txt

# Extract urls with possible SQLi params
cat live_urls_$HOST.txt | $GF sqli > sqli_urls_$HOST.txt

# Extract urls with possible LFI params
cat live_urls_$HOST.txt | $GF lfi > lfi_urls_$HOST.txt

# Extract urls with possible SSRF params
cat live_urls_$HOST.txt | $GF ssrf > ssrf_urls_$HOST.txt

# Extract urls with possible OPEN REDIRECT params
cat live_urls_$HOST.txt | $GF redirect > redirect_urls_$HOST.txt

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
