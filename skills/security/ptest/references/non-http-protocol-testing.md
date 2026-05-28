# Non-HTTP Protocol Testing Reference

## Decision Tree: Port Found → Identify → Test

```
Port scan result
├── 25/465/587 → SMTP → See SMTP Checklist
├── 22/2222 → SSH/SFTP → See SSH/SFTP Checklist
├── 943/1194 → OpenVPN-AS → See OpenVPN Checklist
├── 53 → DNS → See DNS Checklist
└── Unknown → Banner grab → nmap -sV -p<port> <target>
```

General approach for any non-HTTP service:
1. Banner grab: `nc -vz <host> <port>` or `nmap -sV -p<port> <host>`
2. Identify service and version
3. Check for default credentials
4. Check for known CVEs against version
5. Test authentication mechanisms
6. Test encryption (TLS/SSL) configuration
7. Check for information disclosure

---

## SMTP Testing

### Quick Reference Commands

```bash
# Banner grab
nc -vn <host> 25
openssl s_client -connect <host>:465        # SMTPS
openssl s_client -starttls smtp -connect <host>:587  # STARTTLS

# VRFY - enumerate users
nc <host> 25
HELO test.com
VRFY root
VRFY admin
VRFY postmaster

# EXPN - expand mailing lists
EXPN all-staff
EXPN admin

# Open relay test
nc <host> 25
HELO test.com
MAIL FROM:<attacker@evil.com>
RCPT TO:<victim@external.com>
DATA
Subject: Relay Test
Test
.
QUIT

# AUTH methods enumeration
EHLO test.com
# Look for 250-AUTH line in response

# Nmap scripts
nmap -p25 --script smtp-commands,smtp-enum-users,smtp-open-relay,smtp-vuln-cve2010-4344 <host>
nmap -p25 --script smtp-ntlm-info <host>
```

### SMTP Test Checklist

| Test | Risk | Command |
|------|------|---------|
| VRFY enabled | Info disclosure | `VRFY <username>` - 252 = exists |
| EXPN enabled | Info disclosure | `EXPN <list>` |
| Open relay | Critical | MAIL FROM external, RCPT TO external |
| AUTH bruteforce | Account compromise | hydra/medusa against AUTH |
| No STARTTLS | Credential sniffing | Check EHLO response for STARTTLS |
| Weak TLS | Downgrade | `openssl s_client -starttls smtp` |

### Bank Jago Context: SMTP

**Hetzner MX (direct)**
- VRFY enabled: `postmaster` confirmed (252 response)
- Test additional usernames: root, admin, abuse, security, info
- Check if EXPN also enabled

**Brevo/Sendinblue Relay (mail01-04)**
- Hosts: mail01.bankjago.co.id through mail04.bankjago.co.id
- Third-party relay service - limited direct attack surface
- Test: SPF/DKIM/DMARC alignment issues
- Test: Can we send as bankjago.co.id from unauthorized source?
- Check if relay accepts mail from non-authenticated sources

```bash
# Test Hetzner VRFY
nc <hetzner-mx> 25
EHLO probe.test
VRFY postmaster
VRFY root
VRFY admin
VRFY it
VRFY security

# Test Brevo relay auth
openssl s_client -starttls smtp -connect mail01.bankjago.co.id:587
EHLO probe.test
# Check AUTH mechanisms offered
```

---

## SSH / SFTP Testing

### Quick Reference Commands

```bash
# Banner grab
nc -vn <host> 22
ssh -v <host> 2>&1 | grep "remote software version"

# Auth methods enumeration
ssh -o PreferredAuthentications=none -o BatchMode=yes user@<host> 2>&1
# Shows: Permission denied (publickey,password,keyboard-interactive)

# Username enumeration (timing-based, CVE-2018-15473 for OpenSSH < 7.7)
# Using auxiliary/scanner/ssh/ssh_enumusers in Metasploit
# Or: python3 ssh-enum.py <host> <wordlist>

# Key-based attacks
ssh-keyscan <host>                    # Get host public keys
ssh -o HostKeyAlgorithms=ssh-rsa <host>  # Force weak algo

# SFTP specific
sftp -v <user>@<host>
# Check: anonymous access, default creds, directory traversal

# Nmap scripts
nmap -p22 --script ssh2-enum-algos,ssh-hostkey,ssh-auth-methods <host>
nmap -p22 --script ssh-brute --script-args userdb=users.txt,passdb=pass.txt <host>
```

### SSH/SFTP Test Checklist

- Banner information disclosure (OS, version)
- Supported authentication methods
- Username enumeration (timing or error-based)
- Weak key exchange algorithms (diffie-hellman-group1-sha1)
- Weak ciphers (arcfour, 3des-cbc)
- Weak MACs (hmac-md5)
- Password authentication enabled (bruteforce possible)
- Key reuse across hosts
- Authorized_keys file exposure
- SFTP chroot escape

### Bank Jago Context: AWS Transfer Family SFTP

**Targets:** AWS Transfer Family endpoints
**Banner:** `SSH-2.0-AWS_SFTP_1.2`
**Auth:** publickey-only (no password bruteforce possible)

```bash
# Confirm auth method
ssh -o PreferredAuthentications=none -o BatchMode=yes testuser@<aws-sftp-endpoint> 2>&1
# Expected: Permission denied (publickey)

# Enumerate supported algorithms
nmap -p22 --script ssh2-enum-algos <aws-sftp-endpoint>

# Check for weak host keys
ssh-keyscan <aws-sftp-endpoint>

# Test if service leaks valid usernames via timing
# (AWS Transfer Family typically does NOT - returns generic error)
```

**Attack surface notes:**
- Publickey-only = no credential bruteforce
- AWS managed = patching handled by AWS, fewer CVEs applicable
- Focus on: key management issues, overly permissive IAM, exposed S3 buckets backing the SFTP
- Check if any associated S3 bucket is publicly accessible

---

## OpenVPN Access Server (OpenVPN-AS)

### Quick Reference

```bash
# Web admin interface (HTTPS on port 943)
curl -kv https://<host>:943/admin
curl -kv https://<host>:943/

# Default credentials
# Username: openvpn
# Password: openvpn
# ALWAYS test these first

# Client portal
curl -kv https://<host>:943/__session_start__/
curl -kv https://<host>:943/downloads/

# Version detection
curl -sk https://<host>:943/ | grep -i "openvpn"
curl -sk https://<host>:943/admin | grep -i version

# OpenVPN UDP service
nmap -sU -p1194 <host>
```

### OpenVPN-AS CVEs

| CVE | Version | Impact |
|-----|---------|--------|
| CVE-2024-27459 | < 2.6.9 | Local privilege escalation |
| CVE-2023-46850 | 2.6.0-2.6.6 | Remote code execution (use-after-free) |
| CVE-2023-46849 | 2.6.0-2.6.6 | DoS via division by zero |
| CVE-2022-0547 | < 2.5.6 | Auth bypass with external plugins |
| CVE-2020-15077 | < 2.8.8 (AS) | Auth bypass when using deferred auth |
| CVE-2020-11810 | < 2.4.9 | DoS via float/peer-id |
| CVE-2017-12166 | < 2.4.4 | Buffer overflow in key-method 1 |

### OpenVPN-AS Test Checklist

1. Default credentials: openvpn/openvpn on /admin
2. Version disclosure on login page
3. Client portal accessible without auth (/downloads/)
4. XML-RPC interface exposed
5. User enumeration via login error messages
6. Session management weaknesses
7. TLS configuration (weak ciphers, old TLS versions)
8. VPN configuration file download without auth
9. Admin panel bruteforce (no lockout)

### Bank Jago Context: OpenVPN-AS

**Targets:**
- nonprod-vpn: `35.219.70.19:943` (non-production)
- prod-vpn: `35.219.58.25:943` (production)

```bash
# Test default creds on both
curl -sk -X POST https://35.219.70.19:943/admin \
  -d "username=openvpn&password=openvpn"

curl -sk -X POST https://35.219.58.25:943/admin \
  -d "username=openvpn&password=openvpn"

# Version fingerprint
curl -sk https://35.219.70.19:943/ | grep -iE "(openvpn|version)"
curl -sk https://35.219.58.25:943/ | grep -iE "(openvpn|version)"

# Check client portal
curl -sk https://35.219.70.19:943/__session_start__/
curl -sk https://35.219.58.25:943/__session_start__/

# Check for config download
curl -sk https://35.219.70.19:943/rest/GetUserlogin
curl -sk https://35.219.70.19:943/rest/GetAutologin

# TLS check
openssl s_client -connect 35.219.70.19:943 </dev/null 2>/dev/null | grep -E "(Protocol|Cipher)"
```

**Priority:** nonprod-vpn first (lower risk of disruption), then prod-vpn with confirmed safe tests only.

---

## DNS Testing

### Quick Reference Commands

```bash
# Zone transfer (AXFR)
dig @<dns-server> <domain> AXFR
host -t axfr <domain> <dns-server>
nmap -p53 --script dns-zone-transfer --script-args dns-zone-transfer.domain=<domain> <dns-server>

# Reverse DNS sweep
dnsrecon -r <CIDR> -n <dns-server>

# DNS enumeration
dig @<dns-server> <domain> ANY
dig @<dns-server> <domain> NS
dig @<dns-server> <domain> MX
dig @<dns-server> <domain> TXT
dig @<dns-server> <domain> SOA

# Cache poisoning indicators
# Check for source port randomization
dig +short porttest.dns-oarc.net TXT @<dns-server>
# Check DNSSEC
dig @<dns-server> <domain> DNSKEY
dig @<dns-server> <domain> DS

# DNS recursion test (should be disabled on authoritative)
dig @<dns-server> google.com A
# If resolves = recursion enabled

# Subdomain brute
gobuster dns -d <domain> -w /usr/share/wordlists/dns.txt -r <dns-server>
```

### DNS Test Checklist

- Zone transfer (AXFR) allowed
- Recursion enabled on authoritative server
- DNSSEC not implemented
- DNS amplification possible (open resolver)
- Version disclosure: `dig @<server> version.bind chaos txt`
- Cache snooping: `dig @<server> <domain> A +norecurse`
- Subdomain enumeration
- Wildcard DNS detection

### Cache Poisoning Indicators

Signs a DNS server may be vulnerable:
- Non-randomized source ports (predictable)
- No DNSSEC validation
- Long TTL values (cached responses persist)
- Recursive resolver accepting queries from anywhere

```bash
# Test source port randomness
dig +short porttest.dns-oarc.net TXT @<target-dns>
# "GREAT" = randomized, "POOR" = predictable

# Check if DNSSEC is validated
dig +dnssec <domain> @<target-dns>
# Look for 'ad' flag in response (Authenticated Data)
```

---

## General Non-HTTP Service Approach

### Phase 1: Discovery

```bash
# Full port scan
nmap -sS -sU -p- --min-rate 1000 <target> -oA full-scan

# Service version detection on open ports
nmap -sV -sC -p<open-ports> <target> -oA service-scan

# Quick banner grab on all open TCP ports
for port in $(cat open-ports.txt); do
  echo "=== Port $port ===" 
  echo "" | nc -vn -w3 <target> $port 2>&1
done
```

### Phase 2: Per-Service Testing

For each identified service:
1. Google: `<service> <version> exploit`
2. SearchSploit: `searchsploit <service> <version>`
3. Check default credentials (if applicable)
4. Run relevant nmap NSE scripts: `ls /usr/share/nmap/scripts/ | grep <service>`
5. Test authentication mechanisms
6. Check encryption/TLS configuration
7. Look for information disclosure

### Phase 3: Common Non-HTTP Services Quick Reference

| Port | Service | First Test |
|------|---------|-----------|
| 21 | FTP | Anonymous login, bounce attack |
| 22 | SSH | Auth methods, banner, key algos |
| 23 | Telnet | Cleartext creds, banner |
| 25 | SMTP | VRFY, open relay |
| 53 | DNS | Zone transfer, recursion |
| 110 | POP3 | Banner, cleartext auth |
| 143 | IMAP | Banner, cleartext auth |
| 389 | LDAP | Anonymous bind, null base search |
| 443 | HTTPS | (HTTP testing applies) |
| 445 | SMB | Null session, shares enum |
| 993 | IMAPS | TLS config |
| 1194 | OpenVPN | UDP probe |
| 1433 | MSSQL | Default sa creds |
| 3306 | MySQL | Remote root, version |
| 3389 | RDP | NLA, BlueKeep |
| 5432 | PostgreSQL | Default creds, trust auth |
| 5900 | VNC | No-auth, weak password |
| 6379 | Redis | No-auth, INFO command |
| 8080 | HTTP-alt | Web testing |
| 27017 | MongoDB | No-auth, db enum |

### Reporting Priority

- **Critical:** Open relay, default creds on VPN/admin, zone transfer exposing internal hosts
- **High:** VRFY/EXPN enabled, weak SSH algorithms, unpatched CVEs
- **Medium:** Banner disclosure, missing STARTTLS, DNS recursion
- **Low:** Informational version disclosure, non-exploitable config issues
