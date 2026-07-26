# C2 Tracker

Network-based Command & Control (C2) server tracker. Monitors live network connections, enriches IPs via Shodan and Censys, and detects known C2 frameworks.

## Features

- **Live network monitoring** via `psutil` — tracks all inbound/outbound connections
- **Shodan enrichment** — banners, open ports, vulnerabilities, OS, org info
- **Censys enrichment** — services, protocols, autonomous system data
- **C2 framework detection** — Cobalt Strike, Metasploit, Sliver, Havoc, Covenant, Mythic, Empire, PoshC2, Brute Ratel, Decaf, and more
- **Threat scoring** — weighted scoring based on framework detection, port indicators, vulnerabilities, and banner analysis
- **Continuous monitoring** mode with configurable intervals
- **Private IP filtering** to focus on external connections

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/c2-tracker.git
cd c2-tracker
pip install -e .
```

Or install dependencies directly:

```bash
pip install -r requirements.txt
```

## Configuration

Copy `.env.example` to `.env` and add your API keys:

```bash
cp .env.example .env
```

```
SHODAN_API_KEY=your_key_here
CENSYS_API_ID=your_id_here
CENSYS_API_SECRET=your_secret_here
```

Get API keys:
- Shodan: https://account.shodan.io
- Censys: https://search.censys.io/register

## Usage

```bash
# Basic scan (requires root for live monitoring)
sudo python -m c2tracker.cli

# Show all connections and verbose output
sudo c2tracker -s -v

# Continuous monitoring with 10s interval
sudo c2tracker -m -i 10

# Filter out private IPs, only show threats
sudo c2tracker -f

# Local-only scan (no API lookups)
sudo c2tracker --no-api -s

# Use only Shodan
sudo c2tracker --shodan-only

# Use only Censys
sudo c2tracker --censys-only
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

## Requirements

- Python 3.9+
- Root/sudo access (for live network monitoring)
- Shodan API key (free tier available)
- Censys API key (free tier available)

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

## License

MIT
