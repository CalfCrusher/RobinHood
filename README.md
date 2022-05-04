# RobinHood
A Bash Script for Bug Hunting Recon and Exploit Automation

![](https://github.com/CalfCrusher/RobinHood/blob/main/RobinHood.jpg)

### Required Tools (you need to install those by yourself)

- SUBFINDER
- AMASS
- SUBLIST3R
- WAYBACKURLS
- HTTPX
- GXSS
- GF PATTERN
- DALFOX
- GOSPIDER
- SUBJACK

### Usage

`$ git clone https://github.com/CalfCrusher/RobinHood/`

`$ cd RobinHood && chmod +x RobinHood.sh`

Run in background

`$ nohup ./RobinHood.sh DOMAIN 2>&1 &`

`$ tail -f nohup.out` to see progress output

### Note
This is basic script for searching "low hanging fruits" (XSS mainly) especially for VDP Bug Bounties Programs.
