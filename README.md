# RobinHood
## Bug Hunting Recon Automation Script

This script performs automated recon on a target domain (large scope) by running the best set of tools to perform scanning and massive reconnaissance. 

![](https://github.com/CalfCrusher/RobinHood/blob/main/RobinHood.jpg)

### Required Tools (you need to install those by yourself)

- SUBFINDER (https://github.com/projectdiscovery/subfinder)

- AMASS (https://github.com/OWASP/Amass)

- SUBLIST3R (https://github.com/aboul3la/Sublist3r)

- HTTPX (https://github.com/projectdiscovery/httpx)

- GF (https://github.com/1ndianl33t/Gf-Patterns)

- GAU (https://github.com/lc/gau)

- QSREPLACE (https://github.com/tomnomnom/qsreplace)

- ANEW (https://github.com/tomnomnom/anew)

- URO (https://github.com/s0md3v/uro)

- SUBJACK (https://github.com/haccer/subjack)

- GOWITNESS (https://github.com/sensepost/gowitness)

- SQLMAP (https://github.com/sqlmapproject/sqlmap)

- JSUBFINDER (https://github.com/ThreatUnkown/jsubfinder)

- ORALYZER (https://github.com/r0075h3ll/Oralyzer)

- NUCLEI (https://github.com/projectdiscovery/nuclei)

- NMAP (https://github.com/nmap/nmap)

- CRLFUZZ (https://github.com/dwisiswant0/crlfuzz)

- CLOUDFLAIR (https://github.com/christophetd/CloudFlair)

- SCIPAG VULSCAN NSE (https://github.com/scipag/vulscan)

- SUBJS (https://github.com/lc/subjs)

- LINKFINDER (https://github.com/GerbenJavado/LinkFinder)

- VHOSTS SIEVE (https://github.com/dariusztytko/vhosts-sieve)

- CLOUD ENUM (https://github.com/initstring/cloud_enum)

- DALFOX (https://github.com/hahwul/dalfox)

- ALTDNS (https://github.com/infosec-au/altdns)

- DNSREAPER (https://github.com/punk-security/dnsReaper)

- PPMAP (https://github.com/kleiton0x00/ppmap)

- FFUF (https://github.com/ffuf/ffuf)

### EXAMPLES OF API AND TOOLS LOCATIONS
*If you don't set those variables the related tools will not run!*

`FINGERPRINTS="" # Subjack fingerprints location`

`CLOUDFLAIR="" # CloudFlair tool location`

`CENSYS_API_ID="" # Censys api id for CloudFlair`

`CENSYS_API_SECRET="" # Censys api secret for CloudFlair`

`VULSCAN_NMAP_NSE="" # Vulscan NSE script for Nmap`

`JSUBFINDER_SIGN="" # Signature location for jsubfinder tool`

`LINKFINDER="" # Path for LinkFinder tool`

`VHOSTS_SIEVE="" # Path for VHosts Sieve tool`

`CLOUD_ENUM="" # Path for cloud_enum, Multi-cloud OSINT`

`SUBLIST3R="" # Path for sublist3r tool`

`ALTDNS_WORDS="" # Path to altdns words permutations file`

`DNSREAPER="" # Path to dnsrepaer tool`

`XSSHUNTER="" # XSS Hunter url for Dalfox (blind xss)`

`ORALYZER="/root/Oralyzer/oralyzer.py" # Oralyzer path url tool (EDIT THIS)`

`ORALYZER_PAYLOADS="/root/Oralyzer/payloads.txt" # Oralyzer payloads file`

`SMUGGLER="/root/smuggler/smuggler.py" # Smuggler tool`

`PARAMS="/root/params.txt" # List of params for bruteforcing GET/POST hidden params`

`SQLMAP="/snap/bin/sqlmap"`

### Features

* Searching for subdomains
* Search for subdomains takeover (subjack, dnsreaper)
* Search for live urls using gau
* Get screenshots of subdomains
* Powered by GF-Patterns
* Search for secrets, token and APIs
* Search hidden endpoints in JS urls
* Scan live hosts with Nmap and Vulscan NSE Script
* Run Nuclei on all live subdomains
* Search for XSS with Dalfox
* Search for SQL injections with sqlmap
* Search for virtual hosts
* Search for public resources in AWS, Azure, and Google Cloud
* Try to get origin of IPs using CloudFlair
* Get interesting URLs for XSS, SSRF, SQLi, LFI, OPEN REDIRECT
* Extend searching subdomains with words permutations using altdns
* Scan for Open Redirect with Oralyzer
* Fuzzing for CRLF
* Client-side Prototype Pollution to XSS
* Search for hidden params on php endpoints

### Usage

`$ git clone https://github.com/CalfCrusher/RobinHood/`

`$ cd RobinHood && chmod +x RobinHood.sh`

Run in background:

`$ nohup ./RobinHood.sh LARGE_SCOPE_DOMAIN 2>&1 &`

You can also give the out-of-scope domains list separated by commas:

`$ nohup ./RobinHood.sh example.com vpn.example.com,test.example.com 2>&1 &`

To see progress output

`$ tail -f nohup.out`

### Disclaimer

Be free to edit the various settings of tools related to your VPS power/bandwith. You can run this script also on your Raspberry or your DigitalOcean droplet or just where you want.
It takes very long time also in base of which domain you run against to.
