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
FINGERPRINTS="/root/go/pkg/mod/github.com/haccer/subjack@v0.0.0-20201112041112-49c51e57deab/fingerprints.json" # Path for subjack fingerprints (EDIT THIS)
CLOUDFLAIR="/root/CloudFlair/cloudflair.py" # Path for CloudFlair tool location (EDIT THIS)
CENSYS_API_ID="" # Censys api id for CloudFlair(EDIT THIS)
CENSYS_API_SECRET="" # Censys api secret for CloudFlair (EDIT THIS)
VULSCAN_NMAP_NSE="/root/vulscan/vulscan.nse" # Vulscan NSE script for Nmap (EDIT THIS)
JSUBFINDER_SIGN="/root/.jsf_signatures.yaml" # Path signature location for jsubfinder (EDIT THIS)
LINKFINDER="/root/LinkFinder/linkfinder.py" # Path for LinkFinder tool (EDIT THIS)
VHOSTS_SIEVE="/root/vhosts-sieve/vhosts-sieve.py" # Path for VHosts Sieve tool (EDIT THIS)
CLOUD_ENUM="/root/cloud_enum/cloud_enum.py" # Path for cloud_enum tool, Multi-cloud OSINT tool (EDIT THIS)
SUBLIST3R="/root/Sublist3r/sublist3r.py" # Path for sublist3r tool (EDIT THIS)
ALTDNS_WORDS="/root/altdns/words-medium.txt" # Path to altdns words permutations file (EDIT THIS)
DNSREAPER="/root/dnsReaper/main.py" # Path to dnsrepaer tool (EDIT THIS)
XSSHUNTER="calfcrusher.xss.ht" # XSS Hunter url for Dalfox (blind xss)
ORALYZER="/root/Oralyzer/oralyzer.py" # Oralyzer path url tool (EDIT THIS)
ORALYZER_PAYLOADS="/root/Oralyzer/payloads.txt" # Oralyzer payloads file
SMUGGLER="/root/smuggler/smuggler.py" # Smuggler tool
PARAMS="/root/params.txt" # List of params for bruteforcing GET/POST hidden params
SQLMAP="/snap/bin/sqlmap"

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
DALFOX=$(command -v dalfox)
ALTDNS=$(command -v altdns)
URO=$(command -v uro)
CRLFUZZ=$(command -v crlfuzz)
PPMAP=$(command -v ppmap)
FFUF=$(command -v ffuf)

# Get large scope domain as first argument
HOST=$1

# Get list of excluded subdomains as second argument
OUT_OF_SCOPE_SUBDOMAINS=$2

# Subdomains Enumeration
python3 $SUBLIST3R -d $HOST -o subdomains_$HOST.txt
$SUBFINDER -d $HOST -silent | awk -F[ ' {print $1}' | tee -a subdomains_$HOST.txt
$AMASS enum -passive -d $HOST | tee -a subdomains_$HOST.txt

# Subdomains permutations with altdns
$ALTDNS -i subdomains_$HOST.txt -o temp_output -w $ALTDNS_WORDS -r -s altdns_temp_subdomains_$HOST.txt
cat altdns_temp_subdomains_$HOST.txt | cut -f1 -d":" | tee -a subdomains_$HOST.txt
rm temp_output && rm altdns_temp_subdomains_$HOST.txt

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
cat subdomains_$HOST.txt | $HTTPX -mc 200,403,404,500,401 -silent | tee live_subdomains_$HOST.txt

# Fuzzing CRLF vulnerabilities
$CRLFUZZ -l live_subdomains_$HOST.txt -o crlfuzz_results_$HOST.txt

# Run Smuggler, a HTTP Request Smuggling / Desync testing tool
cat live_subdomains_$HOST.txt | python3 $SMUGGLER -x -q -l smuggler_results_$HOST.txt

# Search for subdomains takeover with DNS Reaper
if [ ! -z "$DNSREAPER" ]
then
    python3 $DNSREAPER file --filename subdomains_$HOST.txt --out dnsreaper_$HOST --out-format json
fi

# Search for subdomains takeover with subjack
if [ ! -z "$FINGERPRINTS" ]
then
    $SUBJACK -w subdomains_$HOST.txt -a -o subjack_$HOST.txt -ssl -c $FINGERPRINTS -v
fi

# Scan with NMAP and Vulners
if [ ! -z "$VULSCAN_NMAP_NSE" ]
then
    $NMAP -sV -oN nmap_results_$HOST.txt -iL subdomains_$HOST.txt --script=$VULSCAN_NMAP_NSE --top-ports 50
    sed -i '/Failed to resolve/d' nmap_results_$HOST.txt
fi

# Get screenshots of subdomains
$GOWITNESS file -f live_subdomains_$HOST.txt -P screenshots_$HOST -t 2 -X 800 -Y 600 --delay 5

# Searching for virtual hosts
python3 $VHOSTS_SIEVE -d subdomains_$HOST.txt -o vhost_$HOST.txt

# Searching for public resources in AWS, Azure, and Google Cloud
KEYWORD=$(echo ${HOST} | cut -d"." -f1)
python3 $CLOUD_ENUM -k $HOST -k $KEYWORD -l cloud_enum_$HOST.txt

# Search for secrets
$JSUBFINDER search -f live_subdomains_$HOST.txt -s jsubfinder_secrets_$HOST.txt

# Get URLs with gau
cat live_subdomains_$HOST.txt | $GAU --blacklist png,jpg,gif,jpeg,swf,woff,svg,pdf,tiff,tif,bmp,webp,ico,mp4,mov,js,css,eps,raw | tee all_urls_$HOST.txt

# Decrease numbers of URLs using URO and check live urls using httpx
cat all_urls_$HOST.txt | $URO | $HTTPX -mc 200 -silent | tee live_urls_$HOST.txt

# Get endpoints that have parameters
cat live_urls_$HOST.txt | grep '?' | tee params_endpoints_urls_$HOST.txt

# Get php endpoints
cat live_urls_$HOST.txt | grep ".php" | cut -f1 -d"?" | sed 's:/*$::' | sort -u > php_endpoints_urls_$HOST.txt

# Save in a folder possibile hidden params to check for sql injections later
# GET
for URL in $(<php_endpoints_urls_$HOST.txt); do ($FFUF -u "${URL}?FUZZ=1" -w $PARAMS -mc 200 -ac -sa -t 20 -or -od ffuf_hidden_params_$HOST); done
# POST
for URL in $(<php_endpoints_urls_$HOST.txt); do ($FFUF -X POST -u "${URL}" -w PARAMS -mc 200 -ac -sa -t 20 -or -od ffuf_hidden_params_$HOST -d "FUZZ=1"); done

# Extracts js urls
cat live_urls_$HOST.txt | $SUBJS | tee javascript_urls_$HOST.txt

# Remove duplicates
cat javascript_urls_$HOST.txt | $QSREPLACE -a | tee javascript_urls_temp_$HOST.txt
rm javascript_urls_$HOST.txt
mv javascript_urls_temp_$HOST.txt javascript_urls_$HOST.txt

# Remove third-part domains from js file urls
awk "/${HOST}/" javascript_urls_$HOST.txt > javascript_urls_temp_$HOST.txt
rm javascript_urls_$HOST.txt
mv javascript_urls_temp_$HOST.txt javascript_urls_$HOST.txt

# Discover endpoints in javascript urls
if [ ! -z "$LINKFINDER" ]
then
    while IFS='' read -r URL || [ -n "${URL}" ]; do
        echo -e "[URL] -> ${URL}" >> linkfinder_results_$HOST.txt
        python3 $LINKFINDER -i $URL -o cli | tee -a linkfinder_results_$HOST.txt
        echo -e "\n\n\n" >> linkfinder_results_$HOST.txt
    done < javascript_urls_$HOST.txt
fi

# Run ppmap tool (Prototype Pollution)
cat live_subdomains_$HOST.txt | $PPMAP | tee ppmap_results_$HOST.txt

# Run Nuclei
$NUCLEI -list live_subdomains_$HOST.txt -o nuclei_results_$HOST.txt -c 2

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
        sleep 45
    done < cloudflare_hosts_$HOST.txt
fi

# Extract urls with possible XSS params
cat params_endpoints_urls_$HOST.txt | $GF xss > xss_urls_$HOST.txt

# Extract urls with possible SQLi params
cat params_endpoints_urls_$HOST.txt | $GF sqli > sqli_urls_$HOST.txt

# Extract urls with possible LFI params
cat params_endpoints_urls_$HOST.txt | $GF lfi > lfi_urls_$HOST.txt

# Extract urls with possible SSRF params
cat params_endpoints_urls_$HOST.txt | $GF ssrf > ssrf_urls_$HOST.txt

# Extract urls with possible OPEN REDIRECT params
cat params_endpoints_urls_$HOST.txt | $GF redirect > redirect_urls_$HOST.txt

# Run Oralyzer
if [ ! -z "$ORALYZER" ]
then
    python3 $ORALYZER -l redirect_urls_$HOST.txt -p $ORALYZER_PAYLOADS > oralyzer_results_$HOST.txt
fi

# Running Dalfox
$DALFOX file xss_urls_$HOST.txt -b $XSSHUNTER -S -o dalfox_PoC_$HOST.txt --skip-mining-all --skip-headless

# Running sqlmap
$SQLMAP -m sqli_urls_$HOST.txt --smart --batch --random-agent --output-dir=sqlmap_$HOST

# Save finish execution time
end=`date +%s`
echo ''
echo "********* COMPLETED ! *********"
echo ''
echo "Fork it on https://github.com/CalfCrusher/RobinHood and make the world a better place"
echo ''
echo Execution time was `expr $end - $start` seconds
