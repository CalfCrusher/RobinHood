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

- JSUBFINDER (https://github.com/ThreatUnkown/jsubfinder)

- DIRSEARCH (https://github.com/maurosoria/dirsearch)

- SQLMAP (https://github.com/sqlmapproject/sqlmap)

- ORALYZER (https://github.com/r0075h3ll/Oralyzer)

- NUCLEI (https://github.com/projectdiscovery/nuclei)

- NMAP (https://github.com/nmap/nmap)

- SMUGGLER (https://github.com/defparam/smuggler)

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

- FFUF (https://github.com/ffuf/ffuf)

- PARAMSPIDER (https://github.com/devanshbatham/ParamSpider)

- ARJUN (https://github.com/s0md3v/Arjun)

- KATANA (https://github.com/projectdiscovery/katana)

- LOG4J SCAN (https://github.com/fullhunt/log4j-scan)

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

`ORALYZER="" # Oralyzer path url tool`

`ORALYZER_PAYLOADS="" # Oralyzer payloads file`

`SMUGGLER="" # Smuggler tool`

`PARAMS="" # List of params for bruteforcing GET/POST hidden params`

`LFI_PAYLOADS="" # List of payloads for LFI `

`PARAMSPIDER="" # Path to paramspider tool `

`DIRSEARCH="" # Path to dirsearch tool`

`DIRSEARCH_WORDLIST="" # Path to dirsearch wordlist `

`LOG4JSCAN="" # Path do log4jscan tool`

`HEADERS_LOG4J="" # Path to log4j headers`

### Features

* Search for subdomains
* Search for subdomains takeover (dnsreaper)
* Search for live urls using gau
* Spider live urls using Katana
* Get screenshots of subdomains
* Powered by GF-Patterns
* Search for secrets, token and APIs
* Search hidden endpoints in JS urls
* Discovery dirs and files with Dirsearch
* Scan live hosts with Nmap and Vulscan NSE Script
* Run Nuclei on all live subdomains
* Search for XSS with Dalfox
* Search for SQL Injections
* Search for virtual hosts
* Search for LFI on ParamSpider results using FFUF
* Search for public resources in AWS, Azure, and Google Cloud
* Try to get origin of IPs using CloudFlair
* Get interesting URLs for XSS, SQLi, LFI, OPEN REDIRECT
* Extend searching subdomains with words permutations using altdns
* Scan for Open Redirect with Oralyzer
* Fuzzing for CRLF
* Client-side Prototype Pollution to XSS
* Search for hidden params on php/aspx endpoints with FFUF
* Search for hidden params on endpoints with Arjun
* Search for log4j vulnerability
* Search directories and file using Dirsearch

and much more !

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
