# C2 Tracker

Network-based Command & Control (C2) server tracker. Monitors live network connections, enriches IPs via Shodan and Censys, and detects known C2 frameworks.

## Features

- **Live network monitoring** via `psutil` — tracks all inbound/outbound connections
- **Shodan enrichment** — banners, open ports, vulnerabilities, OS, org info
- **Censys enrichment** — services, protocols, autonomous system data
- **Known malicious IP database** — 120+ IPs linked to Cobalt Strike, Metasploit, Sliver, TrickBot, Emotet, Conti, LockBit, REvil, and more
- **C2 framework detection** — Cobalt Strike, Metasploit, Sliver, Havoc, Covenant, Mythic, Empire, PoshC2, Brute Ratel, Decaf, and more
- **Threat scoring** — weighted scoring based on framework detection, port indicators, vulnerabilities, and banner analysis
- **Continuous monitoring** mode with configurable intervals
- **Private IP filtering** to focus on external connections

## Quick Start

### 1. Clone the repo

```bash
git clone https://github.com/0xvuln0/C2-Tracker.git
cd C2-Tracker
```

### 2. Create a virtual environment (recommended)

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Set up API keys (optional, for Shodan/Censys lookups)

```bash
cp .env.example .env
```

Edit `.env` and fill in your API keys:

```
SHODAN_API_KEY=your_key_here
CENSYS_API_ID=your_id_here
CENSYS_API_SECRET=your_secret_here
```

Get free API keys:
- Shodan: https://account.shodio.io
- Censys: https://search.censys.io/register

> You can still use the tool without API keys — it will use the built-in malware IP database and local network analysis.

## Usage

All scan commands require `sudo` because they read live network connections.

There are two ways to run the tool:

**Option A — Run directly with Python (no install needed):**

```bash
sudo python3 c2tracker/cli.py scan
```

**Option B — Install it first, then use the `c2tracker` command:**

```bash
pip install .
sudo c2tracker scan
```

### Scan network connections

```bash
# Basic scan
sudo python3 c2tracker/cli.py scan

# Show all connections with verbose output
sudo python3 c2tracker/cli.py scan -s -v

# Continuous monitoring (check every 10 seconds)
sudo python3 c2tracker/cli.py scan -m -i 10

# Filter out private/internal IPs
sudo python3 c2tracker/cli.py scan -f

# Local-only scan (no Shodan/Censys lookups, just malware DB + network)
sudo python3 c2tracker/cli.py scan --no-api
```

### Check IPs against the threat database

```bash
# Check one or more IPs
python3 c2tracker/cli.py check 45.77.65.114
python3 c2tracker/cli.py check 45.77.65.114 185.56.83.83 192.168.1.1
```

### Search the threat database

```bash
# Search by malware family
python3 c2tracker/cli.py family "cobalt strike"
python3 c2tracker/cli.py family trickbot

# Search by threat actor
python3 c2tracker/cli.py actor "Evil Corp"
python3 c2tracker/cli.py actor "Conti Group"

# Show database summary
python3 c2tracker/cli.py db --families --actors
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
- Root/sudo access (for live network monitoring)
- (Optional) Shodan API key — free tier available
- (Optional) Censys API key — free tier available

## License

MIT
