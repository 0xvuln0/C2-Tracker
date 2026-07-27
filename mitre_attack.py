"""MITRE ATT&CK technique mapping for detected behaviors.

Maps suspicious strings and malware behaviors to MITRE ATT&CK
technique IDs, tactics, and descriptions.
"""

from __future__ import annotations

import re

# MITRE ATT&CK Techniques database
# Format: technique_id -> {name, description, tactics, patterns}
TECHNIQUES: dict[str, dict] = {
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
        "tactics": ["TA0002"],
        "patterns": [
            r"cmd\.exe", r"powershell", r"pwsh", r"/bin/sh", r"/bin/bash",
            r"python.*-c", r"perl.*-e", r"ruby.*-e", r"php.*-r",
            r"mshta", r"wscript", r"cscript", r"regsvr32", r"rundll32",
        ],
    },
    "T1059.001": {
        "name": "PowerShell",
        "description": "Adversaries may abuse PowerShell commands and scripts for execution.",
        "tactics": ["TA0002"],
        "patterns": [r"powershell", r"pwsh", r"IEX", r"Invoke-", r"-enc ", r"-EncodedCommand"],
    },
    "T1059.003": {
        "name": "Windows Command Shell",
        "description": "Adversaries may abuse cmd.exe commands and scripts for execution.",
        "tactics": ["TA0002"],
        "patterns": [r"cmd\.exe", r"cmd /c", r"cmd.exe /c"],
    },
    "T1059.004": {
        "name": "Unix Shell",
        "description": "Adversaries may abuse Unix shell commands and scripts for execution.",
        "tactics": ["TA0002"],
        "patterns": [r"/bin/sh", r"/bin/bash", r"/bin/dash", r"bash -i", r"sh -i"],
    },
    "T1059.006": {
        "name": "Python",
        "description": "Adversaries may abuse Python commands and scripts for execution.",
        "tactics": ["TA0002"],
        "patterns": [r"python.*socket", r"python.*subprocess", r"python.*exec", r"python.*os\.system"],
    },
    "T1059.007": {
        "name": "JavaScript",
        "description": "Adversaries may abuse JavaScript commands and scripts for execution.",
        "tactics": ["TA0002"],
        "patterns": [r"javascript:", r"jscript", r"vbscript", r"eval\s*\("],
    },
    "T1055": {
        "name": "Process Injection",
        "description": "Adversaries may inject code into processes in order to evade process-based defenses.",
        "tactics": ["TA0005"],
        "patterns": [
            r"WriteProcessMemory", r"CreateRemoteThread", r"VirtualAllocEx",
            r"VirtualProtectEx", r"NtCreateThreadEx", r"QueueUserAPC",
            r"RtlCreateUserThread", r"SetThreadContext", r"ptrace",
            r"process_vm_writev", r"/proc/.*/mem",
        ],
    },
    "T1053": {
        "name": "Scheduled Task/Job",
        "description": "Adversaries may abuse task scheduling functionality to facilitate execution.",
        "tactics": ["TA0003", "TA0002"],
        "patterns": [r"schtasks", r"crontab", r"/etc/cron", r"at\s+\d+", r"New-ScheduledTask"],
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "description": "Adversaries may communicate using application layer protocols to avoid detection.",
        "tactics": ["TA0011"],
        "patterns": [
            r"http://", r"https://", r"ftp://", r"smtp://", r"dns://",
            r"C2", r"command.and.control",
        ],
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "description": "Adversaries may transfer tools or other files into an infected environment.",
        "tactics": ["TA0011"],
        "patterns": [
            r"wget.*http", r"curl.*http", r"certutil.*-urlcache",
            r"bitsadmin.*\/transfer", r"Invoke-WebRequest",
            r"DownloadString", r"DownloadFile", r"Net\.WebClient",
        ],
    },
    "T1078": {
        "name": "Valid Accounts",
        "description": "Adversaries may obtain and abuse credentials of existing accounts.",
        "tactics": ["TA0001", "TA0005"],
        "patterns": [r"net\s+user", r"net\s+localgroup", r"New-LocalUser", r"Add-LocalGroupMember"],
    },
    "T1110": {
        "name": "Brute Force",
        "description": "Adversaries may use brute force techniques to gain access to accounts.",
        "tactics": ["TA0006"],
        "patterns": [r"password\s*=\s*", r"brute", r"hydra", r"medusa", r"ncrack"],
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "description": "Adversaries may attempt to dump credentials to obtain account login and credential material.",
        "tactics": ["TA0006"],
        "patterns": [
            r"mimikatz", r"sekurlsa", r"lsass", r"procdump.*lsass",
            r"comsvcs.*MiniDump", r"pypykatz", r"crackmapexec",
            r"hashdump", r"sam\.db", r"ntds\.dit",
        ],
    },
    "T1003.001": {
        "name": "LSASS Memory",
        "description": "Adversaries may attempt to access credential material stored in LSASS memory.",
        "tactics": ["TA0006"],
        "patterns": [r"lsass", r"sekurlsa", r"mimikatz", r"procdump.*lsass", r"comsvcs"],
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "description": "Adversaries may encrypt data on target systems to interrupt availability.",
        "tactics": ["TA0040"],
        "patterns": [
            r"encrypt", r"ransom", r"bitcoin", r"wallet", r"decrypt",
            r"\.locked", r"\.encrypted", r"\.crypto", r"restore_files",
        ],
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "description": "Adversaries may attempt to make an executable or file difficult to discover or analyze.",
        "tactics": ["TA0005"],
        "patterns": [
            r"base64", r"encode", r"decode", r"obfuscat", r"packed",
            r"\\x[0-9a-f]{2}", r"chr\(\d+\)", r"fromCharCode",
        ],
    },
    "T1219": {
        "name": "Remote Access Software",
        "description": "An adversary may use legitimate remote access tools to establish C2.",
        "tactics": ["TA0011"],
        "patterns": [
            r"teamviewer", r"anydesk", r"todesk", r"rustdesk",
            r"splashtop", r"beyond\s*control", r"screenconnect",
        ],
    },
    "T1572": {
        "name": "Protocol Tunneling",
        "description": "Adversaries may tunnel network communications to avoid detection.",
        "tactics": ["TA0011"],
        "patterns": [
            r"tunnel", r"ngrok", r"serveo", r"localtunnel",
            r"ssh.*-L", r"ssh.*-R", r"dns.*tunnel", r"iodine",
        ],
    },
    "T1562": {
        "name": "Impair Defenses",
        "description": "Adversaries may maliciously modify components of a victim environment.",
        "tactics": ["TA0005"],
        "patterns": [
            r"disable.*defender", r"stop.*windefend", r"Set-MpPreference",
            r"sc\s+stop", r"sc\s+delete", r"bcdedit.*recoveryenabled\s+no",
        ],
    },
    "T1070": {
        "name": "Indicator Removal",
        "description": "Adversaries may delete or modify artifacts generated within systems.",
        "tactics": ["TA0010", "TA0005"],
        "patterns": [
            r"wevtutil\s+cl", r"Clear-EventLog", r"vssadmin\s+delete",
            r"cipher\s+/w", r"timestomp", r"del.*\/f.*\/q",
        ],
    },
    "T1134": {
        "name": "Access Token Manipulation",
        "description": "Adversaries may modify access tokens to bypass access controls.",
        "tactics": ["TA0005"],
        "patterns": [r"Invoke-TokenManipulation", r"token.*impersonat", r"DuplicateTokenEx", r"SetThreadToken"],
    },
    "T1087": {
        "name": "Account Discovery",
        "description": "Adversaries may attempt to get a listing of accounts on a system.",
        "tactics": ["TA0007"],
        "patterns": [r"net\s+user", r"net\s+group", r"enum\s+users", r"Get-LocalUser"],
    },
    "T1082": {
        "name": "System Information Discovery",
        "description": "Adversaries may attempt to get detailed information about the system.",
        "tactics": ["TA0007"],
        "patterns": [r"systeminfo", r"uname\s+-a", r"Get-WmiObject.*Win32_OperatingSystem", r"hostname"],
    },
    "T1049": {
        "name": "System Network Connections Discovery",
        "description": "Adversaries may attempt to get a listing of network connections.",
        "tactics": ["TA0007"],
        "patterns": [r"netstat", r"ss\s+-", r"Get-NetTCPConnection", r"lsof.*-i"],
    },
    "T1018": {
        "name": "Remote System Discovery",
        "description": "Adversaries may attempt to get a listing of other systems by IP address.",
        "tactics": ["TA0007"],
        "patterns": [r"nmap", r"masscan", r"arp\s+-a", r"Get-ADComputer"],
    },
    "T1046": {
        "name": "Network Service Scanning",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts.",
        "tactics": ["TA0007"],
        "patterns": [r"nmap", r"masscan", r"zmap", r"nbtscan"],
    },
    "T1057": {
        "name": "Process Discovery",
        "description": "Adversaries may attempt to get information about running processes.",
        "tactics": ["TA0007"],
        "patterns": [r"tasklist", r"ps\s+aux", r"Get-Process", r"/proc/.*/cmdline"],
    },
    "T1083": {
        "name": "File and Directory Discovery",
        "description": "Adversaries may enumerate files and directories to find specific information.",
        "tactics": ["TA0007"],
        "patterns": [r"dir\s+\/s", r"find\s+/", r"ls\s+-la", r"Get-ChildItem", r"tree\s+/f"],
    },
    "T1119": {
        "name": "Automated Collection",
        "description": "Once established within a system or network, an adversary may use automated techniques.",
        "tactics": ["TA0009"],
        "patterns": [r"enum.*files", r"collect.*data", r"harvest", r"grab.*password"],
    },
    "T1005": {
        "name": "Data from Local System",
        "description": "Adversaries may search local system sources to find files of interest.",
        "tactics": ["TA0009"],
        "patterns": [r"\.doc", r"\.pdf", r"\.key", r"\.pem", r"\.kdbx", r"passwords?\.(txt|csv|xlsx)"],
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "description": "Adversaries may steal data by exfiltrating it over an existing command and control channel.",
        "tactics": ["TA0010"],
        "patterns": [r"exfil", r"upload.*data", r"send.*file", r"post.*data"],
    },
    "T1567": {
        "name": "Exfiltration Over Web Service",
        "description": "Adversaries may use an existing, legitimate external Web service to exfiltrate data.",
        "tactics": ["TA0010"],
        "patterns": [
            r"pastebin", r"hastebin", r"github\.com.*raw", r"dropbox",
            r"gofile", r"transfer\.sh", r"0x0\.st",
        ],
    },
    "T1571": {
        "name": "Non-Standard Port",
        "description": "Adversaries may communicate using a non-standard port instead of the usual port.",
        "tactics": ["TA0011"],
        "patterns": [
            r"port\s*[:=]\s*\d+", r"connect.*:\d+", r"listen.*:\d+",
            r"4444", r"4443", r"8443", r"1337", r"31337",
        ],
    },
    "T1095": {
        "name": "Non-Application Layer Protocol",
        "description": "Adversaries may communicate using a custom protocol instead of encapsulating commands.",
        "tactics": ["TA0011"],
        "patterns": [r"raw.*socket", r"SOCK_RAW", r"ICMP", r"DNS.*tunnel"],
    },
    "T1132": {
        "name": "Data Encoding",
        "description": "Adversaries may encode data to make command and control traffic harder to detect.",
        "tactics": ["TA0011"],
        "patterns": [r"base64.*encode", r"\\x[0-9a-f]{2}\\x", r"chr\(\d+\)\s*\+", r"rot13"],
    },
    "T1090": {
        "name": "Proxy",
        "description": "Adversaries may use a connection proxy to direct network traffic.",
        "tactics": ["TA0011"],
        "patterns": [r"proxy", r"socks", r"SOCKS5", r"forward.*proxy", r"reverse.*proxy"],
    },
    "T1573": {
        "name": "Encrypted Channel",
        "description": "Adversaries may employ a known encryption algorithm to conceal C2 traffic.",
        "tactics": ["TA0011"],
        "patterns": [r"TLS", r"SSL", r"encrypt.*channel", r"AES", r"RSA"],
    },
    "T1098": {
        "name": "Account Manipulation",
        "description": "Adversaries may manipulate accounts to maintain and/or elevate access.",
        "tactics": ["TA0003", "TA0004"],
        "patterns": [
            r"net\s+user.*\/add", r"net\s+localgroup.*\/add",
            r"New-LocalUser", r"Add-LocalGroupMember",
            r"net\s+user.*\/active.*yes",
        ],
    },
    "T1547": {
        "name": "Boot or Logon Autostart Execution",
        "description": "Adversaries may configure system settings to automatically execute a program during boot.",
        "tactics": ["TA0003"],
        "patterns": [
            r"reg\s+add.*\\Run", r"reg\s+add.*\\RunOnce",
            r"HKLM.*\\Run", r"HKCU.*\\Run",
            r"StartupFolder", r"New-Service",
        ],
    },
    "T1543": {
        "name": "Create or Modify System Process",
        "description": "Adversaries may create or modify system-level processes to repeatedly execute malicious payloads.",
        "tactics": ["TA0003", "TA0002"],
        "patterns": [r"sc\s+create", r"New-Service", r"systemctl.*enable", r"/etc/init\.d/"],
    },
    "T1036": {
        "name": "Masquerading",
        "description": "Adversaries may attempt to manipulate features of files to make them appear legitimate.",
        "tactics": ["TA0005"],
        "patterns": [
            r"\.pdf\.exe", r"\.doc\.exe", r"\.jpg\.exe",
            r"double.*ext", r"masquerad",
        ],
    },
    "T1082": {
        "name": "System Information Discovery",
        "description": "Adversaries may attempt to get detailed information about the operating system.",
        "tactics": ["TA0007"],
        "patterns": [r"systeminfo", r"uname", r"Get-WmiObject", r"/etc/os-release"],
    },
    "T1497": {
        "name": "Virtualization/Sandbox Evasion",
        "description": "Adversaries may employ means to detect and avoid virtualization and analysis environments.",
        "tactics": ["TA0007", "TA0005"],
        "patterns": [
            r"VMware", r"VirtualBox", r"VBox", r"QEMU", r"Xen",
            r"Sandboxie", r"sbiedll", r"sample\.exe", r"malware",
        ],
    },
    "T1622": {
        "name": "Debugger Evasion",
        "description": "Adversaries may employ debugging string checks to detect a debugger.",
        "tactics": ["TA0005", "TA0007"],
        "patterns": [
            r"IsDebuggerPresent", r"CheckRemoteDebuggerPresent",
            r"NtQueryInformationProcess", r"OutputDebugString",
            r"FindWindow.*OllyDbg", r"INT3", r"\\xcc",
        ],
    },
    "T1027.002": {
        "name": "Software Packing",
        "description": "Adversaries may perform software packing to conceal their code.",
        "tactics": ["TA0005"],
        "patterns": [
            r"UPX", r"ASPack", r"PECompact", r"Themida", r"VMProtect",
            r"Enigma", r"MPRESS", r"petite", r"packed",
        ],
    },
}


def map_to_mitre(suspicious_strings: list[str]) -> list[dict]:
    """Map suspicious strings to MITRE ATT&CK techniques.

    Args:
        suspicious_strings: List of suspicious behavior descriptions.

    Returns:
        List of matched techniques with id, name, description, tactics.
    """
    if not suspicious_strings:
        return []

    matched = []
    seen_ids = set()

    text = " ".join(suspicious_strings).lower()

    for tech_id, tech in TECHNIQUES.items():
        if tech_id in seen_ids:
            continue

        for pattern in tech["patterns"]:
            if re.search(pattern, text, re.IGNORECASE):
                matched.append({
                    "id": tech_id,
                    "name": tech["name"],
                    "description": tech["description"],
                    "tactics": tech["tactics"],
                })
                seen_ids.add(tech_id)
                break

    return matched


def get_technique(technique_id: str) -> dict | None:
    """Look up a single MITRE ATT&CK technique by ID.

    Args:
        technique_id: Technique ID (e.g., "T1059").

    Returns:
        Technique dict or None if not found.
    """
    return TECHNIQUES.get(technique_id)


def get_all_techniques() -> dict[str, dict]:
    """Return all loaded techniques."""
    return TECHNIQUES.copy()
