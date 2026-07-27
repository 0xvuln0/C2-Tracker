"""File-based malware signature and behavior scanner.

Scans files for known malware signatures, embedded IOCs,
suspicious strings, and behavioral indicators.
"""

from __future__ import annotations

import hashlib
import ipaddress
import math
import os
import re
import struct
from dataclasses import dataclass, field


@dataclass
class FileScanResult:
    """Result of scanning a single file."""
    path: str
    file_size: int = 0
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    file_type: str = ""
    entropy: float = 0.0
    risk_score: int = 0
    risk_label: str = "CLEAN"
    detected_signatures: list[str] = field(default_factory=list)
    detected_families: list[str] = field(default_factory=list)
    embedded_ips: list[str] = field(default_factory=list)
    embedded_domains: list[str] = field(default_factory=list)
    suspicious_strings: list[str] = field(default_factory=list)
    pe_info: dict = field(default_factory=dict)
    indicators: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# Known malware string signatures (case-insensitive patterns)
MALWARE_SIGNATURES: dict[str, list[str]] = {
    "Cobalt Strike": [
        r"beacon\.dll",
        r"cobaltstrike",
        r"malleable\s*c2",
        r"jquery-3\.3\.1\.min\.js",
        r"default\.html",
        r"pipe\\msagent_",
        r"pipe\\msSECEH_",
        r"PostError",
        r"GetUser",
        r"GetComputerNameW",
    ],
    "Metasploit": [
        r"meterpreter",
        r"reverse_tcp",
        r"reverse_http",
        r"metsvc",
        r"windows\/meterpreter",
        r"stageless",
        r"staged",
        r"msfconsole",
        r"exploit\/multi",
    ],
    "Sliver": [
        r"sliver",
        r"mtls",
        r"wireguard",
        r"http-c2",
        r"dns-c2",
        r"named.?pipe",
        r"SliverAsset",
        r"sliver\.exe",
    ],
    "AsyncRAT": [
        r"asyncrat",
        r"AsyncRAT",
        r"AsyncClient",
        r"\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00",
    ],
    "njRAT": [
        r"njrat",
        r"njRAT",
        r"nj_rat",
        r"HAVEX",
        r"njw0rm",
    ],
    "Remcos": [
        r"remcos",
        r"Remcos",
        r"remcos\.exe",
        r"remcos_client",
    ],
    "Agent Tesla": [
        r"agent.?tesla",
        r"AgentTesla",
        r"agent_tesla",
        r"smtp\. gmail\.com",
        r"KeysBase64",
    ],
    "QuasarRAT": [
        r"quasar",
        r"Quasar",
        r"quasar\.rat",
        r"Quasar\.RAT",
    ],
    "DarkComet": [
        r"darkcomet",
        r"DarkComet",
        r"DCRat",
        r"SkyRAT",
    ],
    "NanoCore": [
        r"nanocore",
        r"NanoCore",
        r"nanocore\.client",
    ],
    "Gh0st RAT": [
        r"gh0st",
        r"ghost.*rat",
        r"Gh0st",
    ],
    "Formbook": [
        r"formbook",
        r"Formbook",
        r"XLoader",
    ],
    "TrickBot": [
        r"trickbot",
        r"TrickBot",
        r"trick_",
    ],
    "Emotet": [
        r"emotet",
        r"Emotet",
        r"epoch[_\s]?4",
    ],
    "Conti": [
        r"conti",
        r"Conti",
        r"ryuk",
        r"Ryuk",
    ],
    "LockBit": [
        r"lockbit",
        r"LockBit",
        r"lockbit\.",
    ],
    "REvil": [
        r"revil",
        r"REvil",
        r"sodinokibi",
        r"Sodinokibi",
    ],
    "BlackCat": [
        r"blackcat",
        r"BlackCat",
        r"ALPHV",
        r"alphv",
    ],
    "CobaltStrike Malleable C2": [
        r"set\s*hostname",
        r"set\s*uri",
        r"set\s*user-agent",
        r"set\s*headers",
        r"set\s*metadata",
        r"set\s*tcp_frame_header",
    ],
    "PowerShell Empire": [
        r"empire",
        r"Empire",
        r"Invoke-Empire",
        r"powershell.*-enc",
    ],
    "PoshC2": [
        r"poshc2",
        r"PoshC2",
        r"posh.*c2",
    ],
    "Brute Ratel": [
        r"brute.?ratel",
        r"BruteRatel",
        r"badger\.dll",
    ],
    "Havoc": [
        r"havoc",
        r"Havoc",
        r"demon\.dll",
        r"demon\.sys",
    ],
    "Covenant": [
        r"covenant",
        r"Covenant",
        r"grunt",
    ],
    "Mythic": [
        r"mythic",
        r"Mythic",
        r"apfell",
        r"Athena",
    ],
    "Pikabot": [
        r"pikabot",
        r"PikaBot",
    ],
    "QakBot": [
        r"qakbot",
        r"QakBot",
        r"qbot",
        r"QBot",
    ],
    "IcedID": [
        r"icedid",
        r"IcedID",
        r"bokbot",
        r"BokBot",
    ],
    "BazarLoader": [
        r"bazarloader",
        r"BazarLoader",
        r"bazar",
    ],
    "GuLoader": [
        r"guloader",
        r"GuLoader",
        r"cloudkey",
    ],
    "RedLine Stealer": [
        r"redline",
        r"RedLine",
        r"redline.*stealer",
    ],
    "Lumma Stealer": [
        r"lumma",
        r"Lumma",
        r"lumma.*stealer",
    ],
    "Vidar Stealer": [
        r"vidar",
        r"Vidar",
    ],
    "Raccoon Stealer": [
        r"raccoon",
        r"Raccoon",
    ],
    "Mystic Stealer": [
        r"mystic.*stealer",
        r"MysticStealer",
    ],
    "XMRig Miner": [
        r"xmrig",
        r"XMRig",
        r"stratum\+tcp",
        r"stratum\+ssl",
        r"mining\.pool",
    ],
    "Mirai Botnet": [
        r"mirai",
        r"Mirai",
        r"botnet",
        r"/bin/sh",
        r"/bin/busybox",
        r"echo.*>.*\/proc",
    ],
    "Mozi Botnet": [
        r"mozi",
        r"Mozi",
        r"mozi\.a",
        r"mozi\.m",
    ],
}

# Known malicious domains
MALICIOUS_DOMAINS: list[str] = [
    "pastebin.com/raw",
    "hastebin.com/raw",
    "rentry.co/raw",
    "paste.ee/raw",
    "ghbot.com",
    "ngrok.io",
    "serveo.net",
    "localtunnel.com",
    "trycloudflare.com",
    "duckdns.org",
    "freedns.afraid.org",
    "no-ip.com",
    "dynu.com",
    "zapto.org",
    "hopto.org",
    "sytes.net",
    "myftp.biz",
    "redirectme.net",
    "portmap.io",
    "tcpshield.com",
]

# Suspicious string patterns
SUSPICIOUS_PATTERNS: list[tuple[str, str]] = [
    (r"powershell.*-enc\s+[A-Za-z0-9+/=]{20,}", "Encoded PowerShell command"),
    (r"powershell.*-w\s+hidden", "Hidden PowerShell window"),
    (r"cmd\.exe\s+/c.*&&", "Chained CMD commands"),
    (r"certutil.*-urlcache", "CertUtil download"),
    (r"bitsadmin.*\/transfer", "BITSAdmin transfer"),
    (r"reg\s+add.*\\Run", "Registry autorun entry"),
    (r"schtasks.*\/create", "Scheduled task creation"),
    (r"net\s+user\s+.*\/add", "User account creation"),
    (r"wmic\s+process\s+call\s+create", "WMIC process creation"),
    (r"mshta.*vbscript", "MSHTA VBScript execution"),
    (r"regsvr32.*\/s.*\/i.*scrobj", "RegSvr32 scriptlet"),
    (r"rundll32.*javascript:", "Rundll32 JavaScript"),
    (r"mimikatz", "Mimikatz credential tool"),
    (r"sekurlsa::logonpasswords", "Mimikatz logon dump"),
    (r"kerberos::golden", "Golden Ticket attack"),
    (r"Invoke-Mimikatz", "PowerShell Mimikatz"),
    (r"Invoke-TokenManipulation", "Token manipulation"),
    (r"Get-GPPPassword", "GPP password extraction"),
    (r"Invoke-Kerberoast", "Kerberoasting"),
    (r"Invoke-DCShadow", "DCShadow attack"),
    (r"Invoke-PowerShellTcp", "Nishang reverse shell"),
    (r"Invoke-PowerShellIcmp", "Nishang ICMP shell"),
    (r"Invoke-CredentialInjection", "Credential injection"),
    (r"Invoke-PSRemoting", "PS Remoting exploitation"),
    (r"New-Object.*Net\.Sockets\.TCPClient", "TCP reverse shell"),
    (r"New-Object.*Net\.Sockets\.UDPClient", "UDP reverse shell"),
    (r"\[System\.Net\.Sockets\]", "Raw .NET socket usage"),
    (r"DownloadString.*http", "Remote code download"),
    (r"DownloadFile.*http", "Remote file download"),
    (r"Invoke-WebRequest.*-OutFile", "Web file download"),
    (r"Start-BitsTransfer.*-Source", "BITS file transfer"),
    (r"Add-MpPreference.*-ExclusionPath", "Windows Defender exclusion"),
    (r"Set-MpPreference.*-DisableRealtimeMonitoring", "Disabling Windows Defender"),
    (r"sc\s+stop\s+WinDefend", "Stopping Windows Defender"),
    (r"bcdedit.*set.*recoveryenabled\s+no", "Disabling recovery"),
    (r"bcdedit.*set.*bootstatuspolicy.*ignoreallfailures", "Ignoring boot failures"),
    (r"vssadmin\s+delete\s+shadows", "Shadow copy deletion"),
    (r"wmic\s+shadowcopy\s+delete", "Shadow copy deletion via WMI"),
    (r"cipher\s+/w", "Wiping free space"),
    (r"wevtutil\s+cl", "Event log clearing"),
]

# Known malicious IPs (subset of database for quick lookup)
# These are the most critical indicators
KNOWN_MALICIOUS_IP_PATTERNS: list[str] = [
    r"185\.56\.83\.\d+",
    r"185\.220\.101\.\d+",
    r"91\.215\.85\.\d+",
    r"185\.174\.136\.\d+",
    r"194\.87\.\d+\.\d+",
    r"185\.215\.113\.\d+",
]


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data (0.0 = uniform, 8.0 = random)."""
    if not data:
        return 0.0
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in byte_counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def calculate_hashes(file_path: str) -> tuple[str, str, str]:
    """Calculate MD5, SHA1, and SHA256 hashes of a file."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()


def detect_file_type(data: bytes) -> str:
    """Detect file type from magic bytes."""
    if data[:2] == b"MZ":
        return "PE (Windows executable)"
    if data[:4] == b"\x7fELF":
        return "ELF (Linux executable)"
    if data[:4] == b"\xfe\xed\xfa\xce" or data[:4] == b"\xfe\xed\xfa\xcf":
        return "Mach-O (macOS executable)"
    if data[:4] == b"PK\x03\x04":
        return "ZIP archive"
    if data[:3] == b"Rar":
        return "RAR archive"
    if data[:4] == b"\x1f\x8b\x08":
        return "GZIP archive"
    if data[:5] == b"%PDF-":
        return "PDF document"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "PNG image"
    if data[:3] == b"\xff\xd8\xff":
        return "JPEG image"
    if data[:4] == b"GIF8":
        return "GIF image"
    if data[:4] == b"OggS":
        return "OGG audio"
    if data[:4] == b"ID3":
        return "MP3 audio"
    if data[:4] == b"\x00\x00\x00\x1c" or data[:4] == b"\x00\x00\x00\x18":
        return "MP4 video"
    if b"#!/bin/sh" in data[:100] or b"#!/bin/bash" in data[:100]:
        return "Shell script"
    if b"#!/usr/bin/env python" in data[:100] or b"#!/usr/bin/python" in data[:100]:
        return "Python script"
    return "Unknown"


def extract_strings(data: bytes, min_length: int = 4) -> list[str]:
    """Extract ASCII strings from binary data."""
    strings = []
    current = []
    for byte in data:
        if 32 <= byte <= 126:
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                strings.append("".join(current))
            current = []
    if len(current) >= min_length:
        strings.append("".join(current))
    return strings


def extract_ips_from_strings(strings: list[str]) -> list[str]:
    """Extract IP addresses from string data."""
    ip_pattern = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
    found_ips = set()
    for s in strings:
        for match in ip_pattern.finditer(s):
            ip = match.group(1)
            try:
                addr = ipaddress.ip_address(ip)
                if not addr.is_private and not addr.is_loopback:
                    found_ips.add(ip)
            except ValueError:
                continue
    return sorted(found_ips)


def extract_domains_from_strings(strings: list[str]) -> list[str]:
    """Extract domains from string data."""
    domain_pattern = re.compile(r"\b([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,})\b")
    found_domains = set()
    for s in strings:
        for match in domain_pattern.finditer(s):
            domain = match.group(1).lower()
            if len(domain) > 5 and not domain.endswith((".exe", ".dll", ".sys", ".ocx", ".txt", ".log", ".tmp")):
                found_domains.add(domain)
    return sorted(found_domains)


def check_pe_info(data: bytes) -> dict:
    """Extract basic PE file information."""
    info = {}
    if len(data) < 64:
        return info
    if data[:2] != b"MZ":
        return info

    try:
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset + 4 >= len(data):
            return info
        if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
            return info

        machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
        machines = {0x14c: "x86", 0x8664: "x86_64", 0xAA64: "ARM64"}
        info["machine"] = machines.get(machine, f"0x{machine:x}")

        num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
        info["sections"] = num_sections

        timestamp = struct.unpack_from("<I", data, pe_offset + 8)[0]
        if timestamp > 0:
            from datetime import datetime
            try:
                info["timestamp"] = datetime.utcfromtimestamp(timestamp).isoformat()
            except (OSError, OverflowError):
                pass

        opt_header_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
        opt_start = pe_offset + 24
        magic = struct.unpack_from("<H", data, opt_start)[0]
        if magic == 0x20b:
            info["format"] = "PE32+"
        else:
            info["format"] = "PE32"

    except (struct.error, IndexError):
        pass

    return info


def scan_file(file_path: str) -> FileScanResult:
    """Scan a file for malware signatures and suspicious behavior.

    Args:
        file_path: Path to the file to scan.

    Returns:
        FileScanResult with all findings.
    """
    result = FileScanResult(path=file_path)

    if not os.path.exists(file_path):
        result.errors.append(f"File not found: {file_path}")
        return result

    try:
        result.file_size = os.path.getsize(file_path)
    except OSError as e:
        result.errors.append(f"Cannot stat file: {e}")
        return result

    if result.file_size == 0:
        result.indicators.append("Empty file (0 bytes)")
        return result

    if result.file_size > 100 * 1024 * 1024:
        result.errors.append(f"File too large ({result.file_size} bytes), skipping deep analysis")
        return result

    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except OSError as e:
        result.errors.append(f"Cannot read file: {e}")
        return result

    # Hashes
    result.md5 = hashlib.md5(data).hexdigest()
    result.sha1 = hashlib.sha1(data).hexdigest()
    result.sha256 = hashlib.sha256(data).hexdigest()

    # File type
    result.file_type = detect_file_type(data)

    # Entropy
    result.entropy = round(calculate_entropy(data), 2)
    if result.entropy > 7.0:
        result.indicators.append(f"High entropy ({result.entropy}) - possible packing/encryption")
    if result.entropy > 7.5:
        result.indicators.append("Very high entropy - likely packed or encrypted")

    # PE info
    if data[:2] == b"MZ":
        result.pe_info = check_pe_info(data)

    # Extract strings
    strings = extract_strings(data)

    # Check malware signatures
    text_blob = " ".join(strings).lower()
    for family, patterns in MALWARE_SIGNATURES.items():
        for pattern in patterns:
            if re.search(pattern, text_blob, re.IGNORECASE):
                if family not in result.detected_families:
                    result.detected_families.append(family)
                sig_match = f"Signature match: {family} ({pattern})"
                if sig_match not in result.detected_signatures:
                    result.detected_signatures.append(sig_match)
                break

    # Extract and check embedded IPs
    result.embedded_ips = extract_ips_from_strings(strings)

    # Extract and check domains
    result.embedded_domains = extract_domains_from_strings(strings)
    for domain in result.embedded_domains:
        for mal_domain in MALICIOUS_DOMAINS:
            if mal_domain in domain:
                result.suspicious_strings.append(f"Malicious domain: {domain}")
                break

    # Check suspicious patterns
    text_full = " ".join(strings)
    for pattern, description in SUSPICIOUS_PATTERNS:
        if re.search(pattern, text_full, re.IGNORECASE):
            if description not in result.suspicious_strings:
                result.suspicious_strings.append(description)

    # Calculate risk score
    score = 0
    score += len(result.detected_families) * 25
    score += len(result.detected_signatures) * 10
    score += len(result.suspicious_strings) * 15
    if result.entropy > 7.0:
        score += 10
    if result.entropy > 7.5:
        score += 10
    if result.file_type == "PE (Windows executable)":
        score += 5
    if result.embedded_ips:
        score += min(len(result.embedded_ips) * 2, 10)
    if any(p in text_full.lower() for p in ["mimikatz", "sekurlsa", "kerberos::golden"]):
        score += 30

    result.risk_score = min(score, 100)

    if result.risk_score >= 70:
        result.risk_label = "MALICIOUS"
    elif result.risk_score >= 40:
        result.risk_label = "SUSPICIOUS"
    elif result.risk_score >= 20:
        result.risk_label = "LOW RISK"
    else:
        result.risk_label = "CLEAN"

    # Build final indicators list
    if result.detected_families:
        result.indicators.insert(0, f"Detected families: {', '.join(result.detected_families)}")
    if result.detected_signatures:
        result.indicators.append(f"{len(result.detected_signatures)} signature match(es)")
    if result.suspicious_strings:
        result.indicators.append(f"{len(result.suspicious_strings)} suspicious behavior(s)")
    if result.embedded_ips:
        result.indicators.append(f"{len(result.embedded_ips)} embedded IP(s)")
    if result.embedded_domains:
        result.indicators.append(f"{len(result.embedded_domains)} embedded domain(s)")

    return result
