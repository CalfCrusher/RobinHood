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

- SUBJACK (https://github.com/haccer/subjack)

- GOWITNESS (https://github.com/sensepost/gowitness)

- JSUBFINDER (https://github.com/ThreatUnkown/jsubfinder)

- NUCLEI (https://github.com/projectdiscovery/nuclei)

- NUCLEI TEMPLATES (https://github.com/projectdiscovery/nuclei-templates)

- NMAP (https://github.com/nmap/nmap)

- CLOUDFLAIR (https://github.com/christophetd/CloudFlair)

- SCIPAG VULSCAN NSE (https://github.com/scipag/vulscan)

- SUBJS (https://github.com/lc/subjs)

- LINKFINDER (https://github.com/GerbenJavado/LinkFinder)

- VHOSTS SIEVE (https://github.com/dariusztytko/vhosts-sieve)

- CLOUD ENUM (https://github.com/initstring/cloud_enum)

### API AND TOOLS LOCATIONS
*If you don't set those variables the related tools will not run!*

`BURP_COLLAB_URL="" # Burp Collaborator`

`FINGERPRINTS="" # Subjack fingerprints location`

`CLOUDFLAIR="" # CloudFlair tool location`

`CENSYS_API_ID="" # Censys api id for CloudFlair`

`CENSYS_API_SECRET="" # Censys api secret for CloudFlair`

`VULSCAN_NMAP_NSE="" # Vulscan NSE script for Nmap`

`JSUBFINDER_SIGN="" # Signature location for jsubfinder tool`

`NUCLEI_TEMPLATES="" # Directory template for Nuclei`

`LINKFINDER="" # Directory for LinkFinder tool`

`VHOSTS_SIEVE="" # Directory for VHosts Sieve tool`

`CLOUD_ENUM="" # Directory for cloud_enum, Multi-cloud OSINT`

### Features

* Search for subdomains
* Search for live urls using gau
* Get screenshot of subdomains
* Search for secrets, token and APIs
* Search hidden endpoints in JS urls
* Scan live hosts with Nmap and Vulscan NSE Script
* Run Nuclei on all live urls
* Search virtual hosts
* Search for public resources in AWS, Azure, and Google Cloud
* Try to get origin of IPs using CloudFlair
* Get interesting URLs for XSS, SSRF, SQLi, LFI, OPEN REDIRECT
* Test for basic SSRF using Burp Collaborator
* Search for subdomains takeover

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

Be free to edit the various settings of tools related to your VPS power/bandwith. Settings for Nuclei, for example, are really "low" because i haven’t so much bandwith for my connection. You can run this script also on your Raspberry like me or your DigitalOcean droplet or just where you want. It takes very long time also in base of which program you run against to !
