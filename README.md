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

- NUCLEI (https://github.com/projectdiscovery/nuclei)

- NUCLEI TEMPLATES (https://github.com/projectdiscovery/nuclei-templates)

- NMAP (https://github.com/nmap/nmap)

- CLOUDFLAIR (https://github.com/christophetd/CloudFlair)

- SCIPAG VULSCAN NSE (https://github.com/scipag/vulscan)

- SUBJS (https://github.com/lc/subjs)

- LINKFINDER (https://github.com/GerbenJavado/LinkFinder)

- SECRETFINDER (https://github.com/m4ll0k/SecretFinder)

- VHOSTS SIEVE (https://github.com/dariusztytko/vhosts-sieve)

- CLOUD ENUM (https://github.com/initstring/cloud_enum)

- DALFOX (https://github.com/hahwul/dalfox)

- ALTDNS (https://github.com/infosec-au/altdns)

- S3SCANNER (https://github.com/sa7mon/S3Scanner)

- PARAMSPIDER (https://github.com/devanshbatham/ParamSpider)

- DNSREAPER (https://github.com/punk-security/dnsReaper)

### API AND TOOLS LOCATIONS
*If you don't set those variables the related tools will not run!*

`FINGERPRINTS="" # Subjack fingerprints location`

`CLOUDFLAIR="" # CloudFlair tool location`

`CENSYS_API_ID="" # Censys api id for CloudFlair`

`CENSYS_API_SECRET="" # Censys api secret for CloudFlair`

`VULSCAN_NMAP_NSE="" # Vulscan NSE script for Nmap`

`JSUBFINDER_SIGN="" # Signature location for jsubfinder tool`

`NUCLEI_TEMPLATES="" # Path template for Nuclei`

`LINKFINDER="" # Path for LinkFinder tool`

`VHOSTS_SIEVE="" # Path for VHosts Sieve tool`

`CLOUD_ENUM="" # Path for cloud_enum, Multi-cloud OSINT`

`SUBLIST3R="" # Path for sublist3r tool`

`ALTDNS_WORDS="" # Path to altdns words permutations file`

`PARAMSPIDER="" # Path to paramspider tool`

`DNSREAPER="" # Path to dnsrepaer tool`

`XSSHUNTER="" # XSS Hunter url for Dalfox (blind xss)`

### Features

* Search for subdomains (subjack, dnsreaper)
* Search for live urls using gau
* Get screenshots of subdomains
* Powered by GF-Patterns
* Search for secrets, token and APIs
* Search hidden endpoints in JS urls
* Scan live hosts with Nmap and Vulscan NSE Script
* Run Nuclei on all subdomains
* Search for XSS with Dalfox
* Search for SQL injections with sqlmap
* Search for virtual hosts
* Search for public resources in AWS, Azure, and Google Cloud
* Try to get origin of IPs using CloudFlair
* Get interesting URLs for XSS, SSRF, SQLi, LFI, OPEN REDIRECT
* Search for subdomains takeover with subjack and DNS Reaper
* Extend searching subdomains with words permutations using altdns
* Get all params using ParamSpider
* Scan S3 Buckets found with S3Scanner

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
It takes very long time also in base of which program you run against to !
