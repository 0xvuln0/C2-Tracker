# C2 Tracker

[![Python 3.9+](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CI](https://github.com/0xvuln0/C2-Tracker/actions/workflows/ci.yml/badge.svg)](https://github.com/0xvuln0/C2-Tracker/actions)
[![PyPI](https://img.shields.io/pypi/v/c2tracker.svg)](https://pypi.org/project/c2tracker/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue?logo=docker)](Dockerfile)
[![YARA](https://img.shields.io/badge/YARA-Supported-orange)](yara_scanner.py)
[![Platforms](https://img.shields.io/badge/Platforms-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)]()

Network-based Command & Control (C2) server tracker. Monitors live network connections, enriches IPs via Shodan and Censys, scans files for malware, and detects known C2 frameworks.

**Works on Linux, macOS, and Windows.**

> Inspired by [montysecurity/C2-Tracker](https://github.com/montysecurity/C2-Tracker) for passive Shodan-based C2 hunting approach.

## Features

| Feature | Description |
|---------|-------------|
| **Live network monitoring** | Track all inbound/outbound connections via `psutil` |
| **Shodan enrichment** | Banners, open ports, vulnerabilities, OS, org info (cached) |
| **Censys enrichment** | Services, protocols, autonomous system data (cached) |
| **Malware IP database** | 950+ static IPs + auto-updating online IOCs from ThreatFox/URLhaus |
| **File scanning** | Detect malware signatures, shellcode, reverse shells |
| **YARA rules** | Built-in rules + custom rule support |
| **MITRE ATT&CK** | Map detections to 30+ ATT&CK techniques |
| **Binary analysis** | Detect raw shellcode, anti-debug, anti-VM, packing |
| **Self-learning** | Scanner improves with each scan |
| **C2 Hunting** | Passive Shodan queries to find C2 infrastructure |
| **Export** | JSON, CSV, and IOC export formats |
| **Docker** | Ready-to-use Docker support |
| **Threat scoring** | Configurable weighted scoring (edit `scoring.yaml`) |
| **Auto-update** | Pull latest IOCs from ThreatFox and URLhaus |
| **Parallel scanning** | Multi-threaded bulk file scanning (`-j`) |
| **Directory watch** | Auto-scan new/modified files in a directory |

## Quick Start

### 1. Install

**From PyPI:**
```bash
pip install c2tracker
```

> On Parrot/Debian, if you get `externally-managed-environment`, use `--break-system-packages` or install in a venv:
> ```bash
> pip install c2tracker --break-system-packages
> # or
> python3 -m venv ~/venv && source ~/venv/bin/activate && pip install c2tracker
> ```
>
> On **macOS**: works out of the box. On **Windows**: run as Administrator for `scan` (network monitoring) to see all connections.

**From source (for development):**
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

### Upgrade

```bash
pip install c2tracker --upgrade --break-system-packages
```

Or if using a venv:
```bash
source ~/venv/bin/activate && pip install c2tracker --upgrade
```

### Platform Notes

| Platform | `scan-file` | `scan` (network) | Notes |
|----------|-------------|-------------------|-------|
| **Linux** | Works | Requires `sudo` | Full connection + process visibility |
| **macOS** | Works | Requires `sudo` | Some process names may differ |
| **Windows** | Works | Run as Administrator | Use `c2tracker scan` in an elevated terminal |
| **Docker** | Works | Use `--network host --pid host` | See docker-compose.yml for examples |

### Docker

```bash
# Build
docker build -t c2tracker .

# Scan files
docker run -v ./samples:/samples c2tracker scan-file /samples/*

# Scan network (needs host access)
docker run --network host --pid host --privileged c2tracker scan --no-api
```

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

# Local-only scan (no API lookups)
sudo python3 cli.py scan --no-api
```

### Scan files for malware

```bash
# Scan a single file
python3 cli.py scan-file suspicious.exe

# Scan multiple files with verbose output
python3 cli.py scan-file -v sample1.exe sample2.dll

# Scan a directory (recursive)
python3 cli.py scan-file ./samples/

# Output as JSON (pipe to jq, etc.)
python3 cli.py scan-file -f json suspicious.exe | jq '.[].risk_label'

# Output as CSV
python3 cli.py scan-file -f csv *.exe

# Output IOCs only (hashes, IPs, domains)
python3 cli.py scan-file -f ioc suspicious.exe

# Summary table (compact overview)
python3 cli.py scan-file -f summary ./samples/

# Parallel scanning with 4 workers
python3 cli.py scan-file -j 4 ./samples/ -f summary
```

The file scanner detects:

- **Malware families** — Cobalt Strike, Metasploit, Sliver, AsyncRAT, njRAT, Remcos, 40+ more
- **Reverse shells** — bash, python, perl, php, ruby, netcat, socat
- **Shellcode** — NOP sleds, XOR patterns, syscalls, encoded IPs
- **Web shells** — PHP, ASP, ASPX, JSP
- **Anti-analysis** — anti-debug, anti-VM, anti-sandbox, packing
- **Suspicious behaviors** — encoded PowerShell, credential dumping, persistence
- **MITRE ATT&CK** — maps every detection to technique IDs
- **YARA rules** — scans against built-in and custom rules

### YARA scanning

```bash
# Scan with built-in YARA rules
python3 cli.py scan-file --yara suspicious.exe

# Scan with custom rules directory
python3 cli.py scan-file --yara-rules /path/to/rules suspicious.exe
```

### Update IOC database

```bash
# Auto-update from ThreatFox + URLhaus (runs if >24h since last update)
python3 cli.py update

# Force update
python3 cli.py update --force
```

### Watch directory for new malware

```bash
# Watch a directory, scan new/modified files every 10 seconds
python3 cli.py watch ./incoming/

# Custom interval (5 seconds) with verbose output
python3 cli.py watch -i 5 -v ./downloads/
```

### Hunt C2 infrastructure via Shodan

```bash
# Hunt all tracked C2 families (requires Shodan API key)
python3 cli.py hunt

# Hunt specific products only
python3 cli.py hunt "Cobalt Strike" "Sliver" "AsyncRAT"

# Verbose output
python3 cli.py hunt -v

# Custom output directory
python3 cli.py hunt -o /tmp/c2data
```

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
python3 cli.py check 45.77.65.114 185.56.83.83
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

## MITRE ATT&CK Mapping

Every detection is mapped to MITRE ATT&CK techniques:

| Technique | Description |
|-----------|-------------|
| T1059 | Command and Scripting Interpreter |
| T1055 | Process Injection |
| T1053 | Scheduled Task/Job |
| T1003 | OS Credential Dumping |
| T1486 | Data Encrypted for Impact (Ransomware) |
| T1027 | Obfuscated Files or Information |
| T1572 | Protocol Tunneling |
| T1497 | Virtualization/Sandbox Evasion |
| T1562 | Impair Defenses |
| T1071 | Application Layer Protocol (C2) |
| ... | 20+ more techniques |

See [`mitre_attack.py`](mitre_attack.py) for the full mapping.

## Configurable Scoring

Edit `scoring.yaml` to customize risk score weights:

```yaml
scoring:
  # More behaviors = higher score
  behavior_tiers:
    15: 40    # 15+ behaviors → 40 pts
    10: 30    # 10-14 → 30 pts
     7: 22    # 7-9 → 22 pts

  # Per-indicator bonuses
  shellcode_per_hit: 2
  anti_analysis_per_hit: 3

  # Family matches
  family_log_scale: 15
  family_max: 20

thresholds:
  malicious: 70
  suspicious: 40
  low_risk: 20
```

Requires `pyyaml`: `pip install c2tracker[config]`

## YARA Rules

Built-in rules in `rules/`:

| File | Description |
|------|-------------|
| `malware.yar` | Ransomware, packed executables, cryptominers |
| `webshells.yar` | PHP, ASPX, JSP web shells |
| `shells.yar` | Bash, Python, Perl, Ruby reverse shells |

Add your own `.yar` files to `rules/` and they'll be loaded automatically.

## Architecture

```
c2tracker/
  cli.py              # CLI entry point
  network.py          # Network connection monitoring
  analyzer.py         # Threat scoring engine
  malware_db.py       # 1226 malicious IPs
  shodan_lookup.py    # Shodan API integration
  censys_lookup.py    # Censys API integration
  hunter.py           # Passive C2 hunting via Shodan
  file_scanner.py     # File-based malware analysis
  yara_scanner.py     # YARA rule scanning
  mitre_attack.py     # MITRE ATT&CK mapping
  export.py           # JSON/CSV/IOC export
  config.py           # Configuration management
  models.py           # Data models
  rules/              # YARA rules directory
  test_samples/       # Sample malware for testing
```

## C2 Frameworks Detected

| Framework | Indicators |
|-----------|-----------|
| Cobalt Strike | Beacon artifacts, malleable C2 profiles, port 50050 |
| Metasploit | Meterpreter payloads, reverse_tcp/shells |
| Sliver | Sliver-specific ports and service names |
| Havoc | Demon implants |
| Brute Ratel | Badger payloads |
| Mythic | Athena/apfell agents |
| Covenant | Grunt implants |
| Empire | PowerShell Empire artifacts |
| PoshC2 | PoshC2-specific markers |
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
- (Optional) `yara-python` for YARA rule scanning

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a PR.

## License

MIT — see [LICENSE](LICENSE) for details.
