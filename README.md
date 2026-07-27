# C2 Tracker

Network-based Command & Control (C2) server tracker. Monitors live network connections, enriches IPs via Shodan and Censys, and detects known C2 frameworks.

## Features

- **Live network monitoring** via `psutil` — tracks all inbound/outbound connections
- **Shodan enrichment** — banners, open ports, vulnerabilities, OS, org info
- **Censys enrichment** — services, protocols, autonomous system data
- **Known malicious IP database** — 1200+ IPs linked to Cobalt Strike, Metasploit, Sliver, TrickBot, Emotet, Conti, LockBit, REvil, and more
- **C2 framework detection** — Cobalt Strike, Metasploit, Sliver, Havoc, Covenant, Mythic, Empire, PoshC2, Brute Ratel, Decaf, and more
- **Threat scoring** — weighted scoring based on framework detection, port indicators, vulnerabilities, and banner analysis
- **Continuous monitoring** mode with configurable intervals
- **Private IP filtering** to focus on external connections
- **C2 Hunting** — passive Shodan queries to find C2 infrastructure across the internet

## Quick Start

### 1. Clone the repo

```bash
git clone https://github.com/0xvuln0/C2-Tracker.git
cd C2-Tracker
```

### 2. Set up API keys (optional)

```bash
cp .env.example .env
```

Edit `.env` and add your API keys:

```
SHODAN_API_KEY=your_key_here
CENSYS_API_ID=your_id_here
CENSYS_API_SECRET=your_secret_here
```

Get free API keys:
- Shodan: https://account.shodan.io
- Censys: https://search.censys.io/register

> You can use the tool without API keys — it will use the built-in malware IP database and local network analysis.

## Usage

### Scan network connections

```bash
# Basic scan (requires sudo for live connection data)
sudo python3 cli.py scan

# Show all connections with verbose output
sudo python3 cli.py scan -s -v

# Continuous monitoring (check every 10 seconds)
sudo python3 cli.py scan -m -i 10

# Filter out private/internal IPs
sudo python3 cli.py scan -f

# Local-only scan (no Shodan/Censys lookups, just malware DB + network)
sudo python3 cli.py scan --no-api
```

### Hunt C2 infrastructure via Shodan

```bash
# Hunt all tracked C2 families (requires Shodan API key)
python3 cli.py hunt

# Hunt specific products only
python3 cli.py hunt "Cobalt Strike" "Sliver" "AsyncRAT"

# Verbose output showing each query
python3 cli.py hunt -v

# Custom output directory
python3 cli.py hunt -o /tmp/c2data
```

### Scan files for malware

```bash
# Scan a single file
python3 cli.py scan-file suspicious.exe

# Scan multiple files with verbose output
python3 cli.py scan-file -v sample1.exe sample2.dll sample3.ps1

# Scan all files in a directory
python3 cli.py scan-file /path/to/samples/*
```

The file scanner detects:
- Known malware signatures (Cobalt Strike, Metasploit, AsyncRAT, njRAT, Remcos, etc.)
- Suspicious behaviors (encoded PowerShell, credential dumping, persistence mechanisms)
- Embedded IOCs (IPs, domains, URLs)
- PE file information (architecture, sections, timestamps)
- File entropy (packing/encryption detection)
- Risk scoring with MALICIOUS/SUSPICIOUS/LOW RISK/CLEAN labels
- **Malware family identification** with reasons for detection
- **Binary shellcode analysis** (syscalls, XOR patterns, NOP sleds)
- **ELF anomaly detection** (tiny binaries, no section headers)
- **Self-learning** - improves detection with each scan

### Learning database

```bash
# View learning stats
python3 cli.py learning

# Reset learning database
python3 cli.py learning --reset
```

### Check IPs against the threat database

```bash
# Check one or more IPs
python3 cli.py check 45.77.65.114
python3 cli.py check 45.77.65.114 185.56.83.83 192.168.1.1
```

### Search the threat database

```bash
# Search by malware family
python3 cli.py family "cobalt strike"
python3 cli.py family trickbot

# Search by threat actor
python3 cli.py actor "Evil Corp"
python3 cli.py actor "Conti Group"

# Show database summary
python3 cli.py db --families --actors
```

## C2 Frameworks Detected

| Framework | Indicators |
|-----------|-----------|
| Cobalt Strike | Beacon artifacts, malleable C2 profiles, port 50050 |
| Metasploit | Meterpreter payloads, reverse_tcp/shells |
| Sliver | Sliver-specific ports and service names |
| Covenant | Grunt implants |
| Brute Ratel | Badger payloads |
| Havoc | Demon implants |
| Mythic | Athena/apfell agents |
| Empire | PowerShell Empire artifacts |
| PoshC2 | PoshC2-specific markers |
| Decaf | Decaf C2 markers |
| AsyncRAT | AsyncRAT-specific C2 channels |
| njRAT | njRAT C2 ports |
| Remcos | Remcos C2 infrastructure |
| Agent Tesla | Agent Tesla exfil servers |
| TrickBot | TrickBot C2 panels |
| Emotet | Emotet Epoch 4 C2 |
| Conti | Conti ransomware C2 |
| LockBit | LockBit ransomware C2 |
| REvil | REvil/Sodinokibi C2 |
| QakBot | QakBot C2 servers |
| RedLine | RedLine stealer C2 |
| Lumma | Lumma stealer C2 |
| Pikabot | Pikabot C2 |

## Requirements

- Python 3.9+
- Root/sudo access (for live network monitoring via `scan`)
- (Optional) Shodan API key — free tier available (required for `hunt`)
- (Optional) Censys API key — free tier available

## License

MIT
