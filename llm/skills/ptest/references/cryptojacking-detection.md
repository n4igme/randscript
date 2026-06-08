# Cryptojacking Detection & Hunting Reference

Use during Phase 5-6 when testing infrastructure targets, cloud environments, or investigating compromised hosts.

## Browser-Based Cryptojacking (Client-Side)

### Injection Vectors
- JavaScript injection in web pages (inline or loaded from external domains)
- Compromised CDN/third-party scripts
- Malicious browser extensions
- Malvertising campaigns loading miner scripts

### Indicators
- WebSocket connections to mining pools (ports: 3333, 5555, 7777, 14444)
- High CPU usage from browser tabs / WebWorkers
- Known domains: coinhive.com, coin-hive.com, authedmine.com, crypto-loot.com, minero.cc, jsecoin.com (many dead, clones exist)
- WebAssembly (WASM) modules performing hash computations
- Obfuscated JS with CryptoNight/RandomX algorithm implementations

### Detection
- CSP violation reports indicating unauthorized script sources
- Performance API anomalies (sustained high CPU in web workers)
- Network: WebSocket upgrades to unknown endpoints with mining pool protocol

## Server-Side Cryptojacking

### Common Processes
- xmrig, ccminer, cpuminer, minerd, kdevtmpfsi, kinsing
- Renamed as legitimate services: kworker, [kthreadd], syslogd, systemd-udevd
- Hidden in /tmp, /dev/shm, /var/tmp, dot-prefixed directories

### Persistence Mechanisms
- Cron jobs (user + system level) dropping/updating miners
- Systemd services with obfuscated names
- Docker containers running miners (often from compromised registries)
- SSH authorized_keys backdoor + miner combo
- LD_PRELOAD rootkits hiding miner processes

### Entry Vectors (for pentest exploitation phase)
- Exposed Docker API (2375/2376)
- Redis unauthenticated (6379) → cron injection
- Kubernetes dashboard/kubelet unauthenticated
- Jenkins/CI unauthenticated RCE
- Exposed Jupyter notebooks
- Log4Shell, Spring4Shell → miner payload
- Compromised npm/PyPI packages in CI pipelines

## Network IOCs

### Mining Pool Communication
- Stratum protocol: `stratum+tcp://`, `stratum+ssl://`
- JSON-RPC methods: "mining.authorize", "mining.subscribe", "mining.submit"
- Common pool ports: 3333, 4444, 5555, 8888, 14433, 14444

### Known Pool Domains (sample)
- pool.minexmr.com, xmr.pool.minergate.com
- xmr-*.*.nanopool.org, pool.supportxmr.com
- moneroocean.stream, gulf.moneroocean.stream
- herominers.com, hashvault.pro

### DNS Indicators
- DGA-like domains resolving to mining proxies
- DNS-over-HTTPS to bypass corporate DNS monitoring
- Tor hidden service connections (.onion via SOCKS)

## Detection Rules (Defensive Hunting)

### Process-Based
- CPU usage anomalies per host/container (sustained >80% single core)
- Process name vs binary hash mismatch
- Processes with deleted binary (ls -la /proc/PID/exe → "(deleted)")
- Unexpected WASM compilation in browser processes

### File-Based
- New executables in /tmp, /dev/shm, /var/tmp
- Crontab modifications on servers (inotify/auditd)
- Modified system binaries (tripwire/AIDE alerts)
- Config files: config.json with "algo": "rx/0" or "cn/r"

### Network-Based
- Sustained outbound connections on mining ports
- JSON-RPC traffic patterns (small request, no large response)
- TLS connections to IPs without valid certificates on non-standard ports
- Unusual outbound traffic volume from containers/serverless

## YARA Rule Indicators (key strings)
```
strings:
  $s1 = "stratum+tcp://"
  $s2 = "mining.authorize"
  $s3 = "mining.subscribe"
  $s4 = "\"algo\"" ascii
  $s5 = "randomx" nocase
  $s6 = "cryptonight" nocase
  $s7 = "xmrig" nocase
  $s8 = "hashrate" ascii
  $s9 = "pool_address" ascii
  $s10 = "coin-hive.com" ascii
```

## Sigma Rule Indicators
- Process creation with known miner binary names
- Network connection to known pool IPs/domains
- Cron modification events followed by high CPU
- Container image pull from untrusted registry + immediate CPU spike

## Relevance to Pentest Findings

When discovering cryptojacking during an engagement:
- Severity: High (unauthorized resource consumption + indicates prior compromise)
- Evidence needed: process listing, network connections, cron entries, binary sample hash
- Impact: resource theft, potential lateral movement (same entry vector), compliance violation
- Check: was the miner planted via a vulnerability in scope? If yes → chain the finding (vuln + impact = cryptojacking)
