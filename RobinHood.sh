#!/usr/bin/env bash

## Run with: nohup ./RobinHood.sh DOMAIN 2>&1 & ##

# Save starting execution time
start=`date +%s`

# Save locations of tools
SUBFINDER=$(which subfinder)
AMASS=$(which amass)
SUBLIST3R=$(which sublist3r)
WAYBACKURLS=$(which waybackurls)
HTTPX=$(which httpx)
GXSS=$(which Gxss)
GF=$(which gf)
DALFOX=$(which dalfox)
GOSPIDER=$(which gospider)
SUBJACK=$(which subjack)

# Get Domain as first argument
HOST=$1

# Get Fingerprints for subjack tool
FINGERPRINTS=$(find ~/go/pkg/ -name fingerprints.json)

echo ''
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~~~~~SUBDOMAINS ENUMERATION~~~~~~~~" 
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo ''

# Search for subdomains
$SUBLIST3R -d $HOST -o subdomains_$HOST.txt
$SUBFINDER -d $HOST -silent | awk -F[ ' {print $1}' | tee -a subdomains_$HOST.txt
$AMASS enum -passive -d $HOST -timeout 10 | tee -a subdomains_$HOST.txt

echo ''
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~~CHECKING SUBDOMAINS WITH HTTPX~~~~" 
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo ''

# Output live sites (Redirects are followed)
cat subdomains_$HOST.txt | sort -u | $HTTPX -silent | tee live_sites_$HOST.txt

echo ''
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~~~~~~~CHECKING WAYBACKURLS~~~~~~~~" 
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo ''

# Saves waybackurls in a file
cat live_sites_$HOST.txt | $WAYBACKURLS | tee waybackurls_$HOST.txt

# Remove empty lines
sed -i '/^$/d' waybackurls_$HOST.txt

echo ''
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~~~~~~~SUBDOMAINS TAKEOVER~~~~~~~~~" 
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo ''

# Search for Subdomains TakeOver
$SUBJACK -w subdomains_$HOST.txt -t 30 -o subdomains_takeover_$HOST.txt -ssl -c $FINGERPRINTS -v -a

echo ''
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~~~~SEARCH XSS ON WAYBACK URLS~~~~~" 
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo ''

# SEARCH FOR XSS THROUGH WAYBACKURLS
cat waybackurls_$HOST.txt | $GF xss | tee wayback_gf_$HOST.txt
cat wayback_gf_$HOST.txt | $GXSS -p Xss -u "Google Bot" -o wayback_Gxss_$HOST.txt
sort -u wayback_Gxss_$HOST.txt | grep . | tee wayback_Gxss_$HOST.txt
cat wayback_Gxss_$HOST.txt | $DALFOX pipe -S -o wayback_dalfox_POCs_$HOST.txt

echo ''
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo "~~~~~~SEARCH XSS USING GOSPIDER~~~~~~" 
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo ''

# SEARCH FOR XSS MANUAL SPIDERING
$GOSPIDER -S live_sites_$HOST.txt -c 10 -m 5 -d 5 -o gospider_$HOST --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e "code-200" | awk '{print $5}' | $GF xss | tee gospider_gf_$HOST.txt
cat gospider_gf_$HOST.txt | $GXSS -p Xss -u "Google Bot" -o gospider_Gxss_$HOST.txt
sort -u gospider_Gxss_$HOST.txt | grep . | tee gospider_Gxss_$HOST.txt
cat gospider_Gxss_$HOST.txt | $DALFOX pipe -S -o gospider_dalfox_POCs_$HOST.txt

# Save finish execution time
end=`date +%s`
echo ''
echo "********* COMPLETED *********"
echo Execution time was `expr $end - $start` seconds.
