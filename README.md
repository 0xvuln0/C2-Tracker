# C2 Tracker

[![Python 3.9+](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CI](https://github.com/0xvuln0/C2-Tracker/actions/workflows/ci.yml/badge.svg)](https://github.com/0xvuln0/C2-Tracker/actions)
[![PyPI](https://img.shields.io/pypi/v/c2tracker.svg)](https://pypi.org/project/c2tracker/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue?logo=docker)](Dockerfile)
[![Platforms](https://img.shields.io/badge/Platforms-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)]()

Network-based Command & Control (C2) server tracker. Monitors live network connections, enriches IPs via Shodan and Censys, scans files for malware, and detects known C2 frameworks.

> Inspired by [montysecurity/C2-Tracker](https://github.com/montysecurity/C2-Tracker) for passive Shodan-based C2 hunting approach.

## Features

| Feature | Description |
|---------|-------------|
| **Live network monitoring** | Track all inbound/outbound connections via `psutil` |
| **Shodan/Censys enrichment** | Banners, ports, vulns, OS, org, ASN (locally cached) |
| **Malware IP database** | 950+ static IPs + auto-updating IOCs from ThreatFox/URLhaus |
| **File scanning** | Malware signatures, shellcode, reverse shells, 40+ families |
| **YARA rules** | Built-in rules + custom rule support |
| **MITRE ATT&CK** | Map detections to 30+ ATT&CK techniques |
| **Binary analysis** | Raw shellcode, anti-debug, anti-VM, packing detection |
| **Self-learning** | Scanner improves with each scan |
| **C2 Hunting** | Passive Shodan queries to find C2 infrastructure |
| **Export** | JSON, CSV, IOC output formats |
| **Auto-update** | Pull latest IOCs from ThreatFox and URLhaus |
| **Parallel scanning** | Multi-threaded bulk file scanning (`-j`) |
| **Directory watch** | Auto-scan new/modified files |
| **Configurable scoring** | Edit `scoring.yaml` to tune risk weights |
| **Docker** | Ready-to-use Docker support |

---

## Installation

### Linux / macOS

```bash
pip install c2tracker
```

On Parrot/Debian with `externally-managed-environment`:
```bash
pip install c2tracker --break-system-packages
# or use a venv
python3 -m venv ~/venv && source ~/venv/bin/activate && pip install c2tracker
```

### Windows

```powershell
# 1. Install Python from python.org (3.9+), check "Add Python to PATH"
# 2. Open PowerShell and install
pip install c2tracker
# 3. Verify
c2tracker --version
```

> **Windows note:** `scan` (network monitoring) requires running PowerShell as Administrator.

### From source (development)

```bash
git clone https://github.com/0xvuln0/C2-Tracker.git
cd C2-Tracker
```

### Upgrade

```bash
pip install c2tracker --upgrade
```

---

## Quick Start

```bash
# Scan a file
c2tracker scan-file suspicious.exe

# Scan with JSON output
c2tracker scan-file -f json suspicious.exe

# Check an IP against the threat database
c2tracker check 45.77.65.114

# Update IOC database from online feeds
c2tracker update
```

---

## Commands

### `scan-file` — Scan files for malware

```bash
# Single file
c2tracker scan-file suspicious.exe

# Multiple files
c2tracker scan-file -v sample1.exe sample2.dll

# Scan directory recursively
c2tracker scan-file ./samples/

# JSON output (for piping to jq, SIEM, etc.)
c2tracker scan-file -f json suspicious.exe

# CSV output
c2tracker scan-file -f csv *.exe

# IOC output (hashes, IPs, domains only)
c2tracker scan-file -f ioc suspicious.exe

# Summary table
c2tracker scan-file -f summary ./samples/

# Parallel scanning (4 workers)
c2tracker scan-file -j 4 ./samples/ -f summary
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

### `scan` — Monitor live network connections

```bash
# Basic scan (requires sudo on Linux/macOS, Administrator on Windows)
sudo c2tracker scan

# Show all connections with verbose output
sudo c2tracker scan -s -v

# Continuous monitoring (every 10 seconds)
sudo c2tracker scan -m -i 10

# Filter out private/internal IPs
sudo c2tracker scan -f

# Local-only scan (no API lookups)
sudo c2tracker scan --no-api
```

### `update` — Update IOC database

```bash
# Auto-update from ThreatFox + URLhaus (runs if >24h since last)
c2tracker update

# Force update
c2tracker update --force
```

### `watch` — Watch directory for new malware

```bash
# Watch directory, scan new/modified files every 10 seconds
c2tracker watch ./incoming/

# Custom interval (5 seconds) with verbose output
c2tracker watch -i 5 -v ./downloads/
```

### `check` — Check IPs against threat database

```bash
c2tracker check 45.77.65.114
c2tracker check 45.77.65.114 185.56.83.83
```

### `family` / `actor` — Search threat database

```bash
c2tracker family "cobalt strike"
c2tracker actor "Evil Corp"
```

### `db` — Show database summary

```bash
c2tracker db
c2tracker db --families --actors
```

### `hunt` — Hunt C2 infrastructure via Shodan

```bash
c2tracker hunt
c2tracker hunt "Cobalt Strike" "Sliver" -v
```

### `learning` — Learning database stats

```bash
c2tracker learning
c2tracker learning --reset
```

---

## Configuration

### API keys (optional)

```bash
cp .env.example .env
```

Edit `.env`:
```
SHODAN_API_KEY=your_key_here
CENSYS_API_ID=your_id_here
CENSYS_API_SECRET=your_secret_here
```

Get free API keys:
- Shodan: https://account.shodan.io
- Censys: https://search.censys.io/register

### Configurable scoring

Edit `scoring.yaml` to customize risk score weights:

```yaml
scoring:
  behavior_tiers:
    15: 40    # 15+ behaviors → 40 pts
    10: 30    # 10-14 → 30 pts
     7: 22    # 7-9 → 22 pts
  shellcode_per_hit: 2
  anti_analysis_per_hit: 3
  family_log_scale: 15
  family_max: 20

thresholds:
  malicious: 70
  suspicious: 40
  low_risk: 20
```

Requires `pyyaml`: `pip install c2tracker[config]`

### Platform Notes

| Platform | `scan-file` | `scan` (network) | Notes |
|----------|-------------|-------------------|-------|
| **Linux** | Works | Requires `sudo` | Full connection + process visibility |
| **macOS** | Works | Requires `sudo` | Some process names may differ |
| **Windows** | Works | Run as Admin | Use elevated PowerShell for `scan` |
| **Docker** | Works | Use `--network host` | See docker-compose.yml |

---

## Docker

```bash
# Build
docker build -t c2tracker .

# Scan files
docker run -v ./samples:/samples c2tracker scan-file /samples/*

# Scan network (needs host access)
docker run --network host --pid host --privileged c2tracker scan --no-api
```

---

## Repository Structure

```
C2-Tracker/
├── cli.py              # CLI entry point (all commands)
├── network.py          # Live connection monitoring (psutil)
├── analyzer.py         # Threat scoring for network IPs
├── file_scanner.py     # File malware analysis (signatures, shellcode, behavior)
├── malware_db.py       # 950+ known malicious IPs
├── db_updater.py       # Auto-update IOCs from ThreatFox/URLhaus
├── api_cache.py        # Local cache for Shodan/Censys results
├── shodan_lookup.py    # Shodan API enrichment
├── censys_lookup.py    # Censys API enrichment
├── hunter.py           # Passive C2 hunting via Shodan queries
├── yara_scanner.py     # YARA rule scanning engine
├── mitre_attack.py     # MITRE ATT&CK technique mapping
├── export.py           # JSON/CSV/IOC export
├── config.py           # .env configuration loader
├── models.py           # Data models (ShodanResult, CensysResult)
├── scoring.yaml        # Configurable risk score weights
├── rules/              # Built-in YARA rules
│   ├── malware.yar
│   ├── webshells.yar
│   └── shells.yar
├── tests/              # Unit tests
├── test_samples/       # Sample files for testing
├── pyproject.toml      # Package config + dependencies
├── requirements.txt    # pip install -r fallback
├── Dockerfile          # Multi-stage Docker build
├── docker-compose.yml  # Docker Compose services
├── .env.example        # API key template
├── .github/workflows/  # CI pipeline
├── CHANGELOG.md        # Version history
├── LICENSE             # MIT License
└── README.md           # This file
```

---

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

## YARA Rules

Built-in rules in `rules/`:

| File | Description |
|------|-------------|
| `malware.yar` | Ransomware, packed executables, cryptominers |
| `webshells.yar` | PHP, ASPX, JSP web shells |
| `shells.yar` | Bash, Python, Perl, Ruby reverse shells |

Add your own `.yar` files to `rules/` and they'll be loaded automatically.

## C2 Frameworks Detected

Cobalt Strike, Metasploit, Sliver, Havoc, Brute Ratel, Mythic, Covenant, Empire, PoshC2, AsyncRAT, njRAT, Remcos, Agent Tesla, TrickBot, Emotet, Conti, LockBit, REvil, QakBot, RedLine, Lumma, Pikabot, and more.

## Requirements

- Python 3.9+
- Root/sudo access (Linux/macOS) or Administrator (Windows) for `scan`
- (Optional) Shodan API key — free tier available
- (Optional) Censys API key — free tier available
- (Optional) `yara-python` for YARA rule scanning (`pip install c2tracker[yara]`)
- (Optional) `pyyaml` for configurable scoring (`pip install c2tracker[config]`)

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a PR.

## License

MIT — see [LICENSE](LICENSE) for details.
