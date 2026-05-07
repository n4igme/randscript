---
name: recon-active
description: Active reconnaissance and enumeration — directly probe targets to identify services and vulnerabilities.
version: 2.1.0
metadata:
  category: enumeration
  phase: 2
  scope_types: [web, network, cloud, mobile, mixed]
---

# Skill: Active Reconnaissance & Enumeration

## When to Use
- After passive recon is complete (Gateway 1 PASSED).
- When you need to identify live services, versions, and potential attack vectors.

## Techniques & Tools

### 1. Port Scanning
Identify open ports and services.
```bash
# TCP full scan
nmap -sV -sC -p- -oA ./ptest-output/recon-active/nmap-tcp target.com

# UDP top 1000
nmap -sU --top-ports 1000 -oA ./ptest-output/recon-active/nmap-udp target.com

# Fast initial scan
nmap -sV --top-ports 100 -T4 target.com

# Masscan for speed on large ranges
masscan -p1-65535 --rate=1000 -oL ./ptest-output/recon-active/masscan.txt 10.0.0.0/24
```

### 2. Service Enumeration
Banner grabbing and version detection.
```bash
# Detailed service probing
nmap -sV --version-intensity 5 -p 22,80,443,8080 target.com

# Netcat banner grab
nc -nv target.com 80 <<< "HEAD / HTTP/1.0\r\n\r\n"

# SMB enumeration
enum4linux -a target.com
smbclient -L //target.com -N

# SNMP
snmpwalk -v2c -c public target.com
```

### 3. Web Enumeration
Directory brute-forcing, vhost discovery, API mapping.
```bash
# Directory brute-force
gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt -o ./ptest-output/recon-active/gobuster.txt

# feroxbuster (recursive)
feroxbuster -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -o ./ptest-output/recon-active/ferox.txt

# Virtual host discovery
gobuster vhost -u https://target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# API endpoint discovery
ffuf -u https://target.com/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 200,301,302,403

# Parameter discovery
arjun -u https://target.com/endpoint
```

### 4. Vulnerability Scanning
Automated scanning for known CVEs.
```bash
# Nuclei
nuclei -u https://target.com -o ./ptest-output/recon-active/nuclei.txt

# Nikto (web server scanner)
nikto -h https://target.com -o ./ptest-output/recon-active/nikto.txt

# Nmap NSE vulnerability scripts
nmap --script vuln -p 80,443 target.com
```

### 5. Authentication Probing
Default credentials and auth mechanism analysis.
```bash
# Check for default creds on common services
hydra -L users.txt -P /usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt target.com ssh -t 4

# Web login page discovery
curl -sI https://target.com/admin
curl -sI https://target.com/login
curl -sI https://target.com/wp-admin

# Auth mechanism fingerprinting
curl -v https://target.com/api/auth 2>&1 | grep -i "www-authenticate\|set-cookie\|x-auth"
```

### 6. SSL/TLS Analysis
Certificate and cipher evaluation.
```bash
# testssl.sh
testssl.sh --html https://target.com

# sslscan
sslscan target.com

# Nmap SSL scripts
nmap --script ssl-enum-ciphers -p 443 target.com

# Certificate details
openssl s_client -connect target.com:443 </dev/null 2>/dev/null | openssl x509 -text -noout
```

## Scope Type Adjustments

- **web/API only:** Focus on techniques 3, 4, 5, 6. Skip deep network scanning.
- **network:** Focus on techniques 1, 2, 4, 5. Expand port scanning to full ranges.
- **cloud:** Add cloud-specific enumeration (S3 buckets, Azure blobs, GCP storage).
- **mobile:** Focus on API endpoints the app communicates with, certificate pinning checks.

## Output

Document findings in `./ptest-output/recon-active/`:
- `summary.md` — consolidated enumeration results
- `ports-services.md` — open ports and services per host
- `versions.md` — software versions identified
- `web-enum.md` — web application enumeration results
- `vectors.md` — potential vulnerability vectors, prioritized
- `auth-mechanisms.md` — authentication mechanisms found
- `misconfigurations.md` — misconfigurations detected

Write `./ptest-output/recon-active/checklist.md`:

```markdown
# Active Recon Checklist

| # | Technique | Status | Notes |
|---|-----------|--------|-------|
| 1 | Port Scanning | PENDING | |
| 2 | Service Enumeration | PENDING | |
| 3 | Web Enumeration | PENDING | |
| 4 | Vulnerability Scanning | PENDING | |
| 5 | Authentication Probing | PENDING | |
| 6 | SSL/TLS Analysis | PENDING | |
```

## Exit Criteria
- [ ] All in-scope hosts port-scanned.
- [ ] Service versions fingerprinted.
- [ ] Web applications enumerated (directories, endpoints).
- [ ] Potential attack vectors prioritized.
- [ ] Checklist shows all applicable techniques executed.
