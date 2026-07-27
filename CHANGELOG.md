# Changelog

All notable changes to C2 Tracker will be documented in this file.

## [0.2.0] - 2025-07-27

### Added
- **YARA rule scanning** with built-in rules for malware, webshells, and reverse shells
- **MITRE ATT&CK mapping** - every detection maps to technique IDs (30+ techniques)
- **JSON/CSV export** - export scan results and IOCs to standard formats
- **Docker support** - Dockerfile + docker-compose for easy deployment
- **GitHub Actions CI** - automated testing on Python 3.9-3.12
- **Learning database** - scanner improves with each scan
- **Malware family identification** - detects which family and why
- **Binary shellcode analysis** - detects raw shellcode patterns
- **Anti-analysis detection** - anti-debug, anti-VM, anti-sandbox
- **Behavioral analysis** - unusual file properties, double extensions
- **Rules directory** - community YARA rules for malware detection

### Changed
- Expanded malware database to 1226 IPs (114 families, 22 actors)
- Improved risk scoring with behavioral indicators
- Deduplicated suspicious string output

### Fixed
- Fixed psutil `raddr` tuple handling in network.py
- Fixed `--no-api` flag to properly gate imports
- Fixed README to use flattened project structure

## [0.1.0] - 2025-07-26

### Added
- Initial release
- Network connection monitoring via psutil
- Shodan and Censys enrichment
- Known malicious IP database (716 IPs)
- Threat scoring engine
- Continuous monitoring mode
- Shodan C2 hunting queries
- File scanning with malware signatures
- CLI with rich output formatting
