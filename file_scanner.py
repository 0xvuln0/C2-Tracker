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
    # --- Reverse Shells ---
    (r"bash\s+-i\s+>&\s+/dev/tcp/", "Bash reverse shell"),
    (r"/dev/tcp/\d+\.\d+\.\d+\.\d+/", "Bash /dev/tcp connection"),
    (r"nc\s+-e\s+/bin/(ba)?sh", "Netcat reverse shell"),
    (r"ncat\s+-e\s+/bin/(ba)?sh", "Ncat reverse shell"),
    (r"python.*socket.*connect", "Python reverse shell"),
    (r"python.*SOCK_STREAM", "Python socket connection"),
    (r"python.*subprocess", "Python subprocess execution"),
    (r"perl.*socket.*INET", "Perl reverse shell"),
    (r"perl.*exec\s*\(", "Perl exec call"),
    (r"ruby.*TCPSocket", "Ruby reverse shell"),
    (r"ruby.*exec\s*\(", "Ruby exec call"),
    (r"php.*fsockopen", "PHP reverse shell"),
    (r"php.*proc_open", "PHP proc_open"),
    (r"php.*shell_exec", "PHP shell_exec"),
    (r"php.*system\s*\(", "PHP system call"),
    (r"php.*passthru", "PHP passthru"),
    (r"php.*exec\s*\(", "PHP exec call"),
    (r"lua.*socket", "Lua reverse shell"),
    (r"lua.*os.execute", "Lua os.execute"),
    (r"mkfifo.*nc\s", "FIFO named pipe shell"),
    (r"nc\s+-l\s+-p\s+\d+", "Netcat listener"),
    (r"socat\s+tcp:", "Socat reverse shell"),
    (r"mknod.*b.*666", "Device node creation (FUDGI)"),

    # --- Metasploit / msfvenom ---
    (r"windows/meterpreter", "Meterpreter payload"),
    (r"windows/shell", "Windows shell payload"),
    (r"windows/bind_shell", "Windows bind shell"),
    (r"linux/x86/meterpreter", "Linux Meterpreter"),
    (r"linux/x64/meterpreter", "Linux x64 Meterpreter"),
    (r"linux/x86/shell", "Linux shell payload"),
    (r"linux/x64/shell", "Linux x64 shell payload"),
    (r"reverse_tcp", "Reverse TCP shellcode"),
    (r"reverse_http", "Reverse HTTP payload"),
    (r"reverse_https", "Reverse HTTPS payload"),
    (r"bind_tcp", "Bind TCP shellcode"),
    (r"stageless", "Stageless payload"),
    (r"staged", "Staged payload"),
    (r"msfvenom", "msfvenom artifact"),
    (r"msfconsole", "Metasploit console artifact"),
    (r"exploit/multi", "Metasploit exploit module"),
    (r"exploit/windows", "Metasploit Windows exploit"),
    (r"exploit/linux", "Metasploit Linux exploit"),
    (r"payload/linux", "Metasploit Linux payload"),
    (r"payload/windows", "Metasploit Windows payload"),
    (r"metsvc", "Meterpreter service"),
    (r"meterpreter\.dll", "Meterpreter DLL"),
    (r"meterpreter\.exe", "Meterpreter executable"),
    (r"meterpreter\.py", "Python Meterpreter"),
    (r"meterpreter\.rb", "Ruby Meterpreter"),
    (r"reverse_tcp_handler", "Metasploit handler"),
    (r"LPORT=", "LPORT parameter (Metasploit)"),
    (r"LHOST=", "LHOST parameter (Metasploit)"),
    (r"AutoRunScript", "Metasploit AutoRunScript"),
    (r"SESSION=", "Metasploit session reference"),

    # --- Shellcode / Assembly ---
    (r"\\x90\\x90\\x90\\x90", "NOP sled (NOP x4)"),
    (r"\x90\x90\x90\x90", "NOP sled (binary)"),
    (r"\\x31\\xc0", "XOR EAX,EAX shellcode"),
    (r"\\x31\\xdb", "XOR EBX,EBX shellcode"),
    (r"\\x31\\xc9", "XOR ECX,ECX shellcode"),
    (r"\\x31\\xd2", "XOR EDX,EDX shellcode"),
    (r"\\x50\\x56", "PUSH EAX; PUSH ESI (shellcode)"),
    (r"\\x68\\x01\\x01", "PUSH 0x0101 (shellcode)"),
    (r"\\xcd\\x80", "INT 0x80 syscall (x86 Linux)"),
    (r"\\x0f\\x05", "SYSCALL instruction (x64)"),
    (r"\\xcc", "INT3 breakpoint"),

    # --- PowerShell ---
    (r"powershell.*-enc\s+[A-Za-z0-9+/=]{20,}", "Encoded PowerShell command"),
    (r"powershell.*-w\s+hidden", "Hidden PowerShell window"),
    (r"powershell.*-nop", "No-profile PowerShell"),
    (r"powershell.*-ExecutionPolicy\s+Bypass", "ExecutionPolicy bypass"),
    (r"powershell.*IEX\s*\(", "PowerShell IEX (Invoke-Expression)"),
    (r"powershell.*Invoke-Expression", "PowerShell Invoke-Expression"),
    (r"powershell.*DownloadString", "PowerShell DownloadString"),
    (r"powershell.*DownloadFile", "PowerShell DownloadFile"),
    (r"powershell.*Net\.WebClient", "PowerShell WebClient download"),
    (r"powershell.*Start-BitsTransfer", "PowerShell BITS transfer"),
    (r"powershell.*-c\s+", "PowerShell inline command"),
    (r"powershell.*-command\s+", "PowerShell -command execution"),
    (r"pwsh.*-enc\s+[A-Za-z0-9+/=]{20,}", "Encoded pwsh command"),
    (r"Invoke-WebRequest.*-OutFile", "Web file download"),
    (r"Start-BitsTransfer.*-Source", "BITS file transfer"),
    (r"Invoke-PowerShellTcp", "Nishang reverse shell"),
    (r"Invoke-PowerShellIcmp", "Nishang ICMP shell"),
    (r"Invoke-CredentialInjection", "Credential injection"),
    (r"Invoke-PSRemoting", "PS Remoting exploitation"),

    # --- Credential Access ---
    (r"mimikatz", "Mimikatz credential tool"),
    (r"sekurlsa::logonpasswords", "Mimikatz logon dump"),
    (r"sekurlsa::wdigest", "Mimikatz wdigest dump"),
    (r"sekurlsa::kerberos", "Mimikatz kerberos dump"),
    (r"kerberos::golden", "Golden Ticket attack"),
    (r"kerberos::ptt", "Pass-the-Ticket"),
    (r"Invoke-Mimikatz", "PowerShell Mimikatz"),
    (r"Invoke-TokenManipulation", "Token manipulation"),
    (r"Get-GPPPassword", "GPP password extraction"),
    (r"Invoke-Kerberoast", "Kerberoasting"),
    (r"Invoke-DCShadow", "DCShadow attack"),
    (r"lsass\.dmp", "LSASS memory dump"),
    (r"procdump.*lsass", "LSASS dump via procdump"),
    (r"comsvcs\.dll.*MiniDump", "LSASS dump via comsvcs"),
    (r"rundll32.*comsvcs", "LSASS dump via rundll32"),
    (r"pypykatz", "Python mimikatz"),
    (r"crackmapexec", "CrackMapExec"),

    # --- Execution ---
    (r"cmd\.exe\s+/c.*&&", "Chained CMD commands"),
    (r"cmd\.exe\s+/c.*\|", "CMD pipe execution"),
    (r"cmd\.exe\s+/c.*>", "CMD output redirect"),
    (r"certutil.*-urlcache", "CertUtil download"),
    (r"certutil.*-decode", "CertUtil decode"),
    (r"bitsadmin.*\/transfer", "BITSAdmin transfer"),
    (r"wmic\s+process\s+call\s+create", "WMIC process creation"),
    (r"wmic\s+process\s+call\s+create.*powershell", "WMIC PowerShell spawn"),
    (r"mshta.*vbscript", "MSHTA VBScript execution"),
    (r"mshta.*http", "MSHTA remote execution"),
    (r"regsvr32.*\/s.*\/i.*scrobj", "RegSvr32 scriptlet"),
    (r"regsvr32.*\/s.*\/n.*\/u.*javascript:", "RegSvr32 JavaScript"),
    (r"rundll32.*javascript:", "Rundll32 JavaScript"),
    (r"rundll32.*url\.dll", "Rundll32 URL DLL"),
    (r"rundll32.*comres\.dll", "Rundll32 COMres"),
    (r"forfiles.*\/c.*cmd", "Forfiles CMD execution"),
    (r"cmstp.*\/s", "CMSTP bypass"),
    (r"installutil.*\/logfile", "InstallUtil execution"),
    (r"msbuild.*\/t:", "MSBuild code execution"),
    (r"regasm.*\/logfile", "RegAsm execution"),
    (r"regsvcs.*\/logfile", "RegSvcs execution"),

    # --- Persistence ---
    (r"reg\s+add.*\\Run", "Registry autorun entry"),
    (r"reg\s+add.*\\RunOnce", "Registry RunOnce entry"),
    (r"reg\s+add.*\\CurrentVersion\\Run", "Registry Run key"),
    (r"schtasks.*\/create", "Scheduled task creation"),
    (r"at\s+\d+:\d+", "AT scheduled task"),
    (r"sc\s+create", "Service creation"),
    (r"New-Service", "PowerShell service creation"),
    (r"StartupFolder", "Startup folder persistence"),
    (r"\\\\Startup\\\\", "Startup folder path"),
    (r"HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run", "HKLM Run key"),
    (r"HKCU\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run", "HKCU Run key"),

    # --- Privilege Escalation ---
    (r"sudo\s+chmod\s+[47]", "SUID/SGID binary creation"),
    (r"chmod\s+[47]\d{2}\s+/bin/", "SUID shell"),
    (r"chmod\s+u\+s", "Setuid bit"),
    (r"net\s+localgroup\s+administrators", "Admin group modification"),
    (r"net\s+user\s+.*\/add", "User account creation"),
    (r"net\s+localgroup.*\/add", "Group membership change"),
    (r"Set-ItemProperty.*RunAs", "RunAs persistence"),
    (r"New-LocalUser", "Local user creation"),
    (r"Add-LocalGroupMember", "Group member addition"),

    # --- Defense Evasion ---
    (r"Add-MpPreference.*-ExclusionPath", "Windows Defender exclusion"),
    (r"Set-MpPreference.*-DisableRealtimeMonitoring", "Disabling Windows Defender"),
    (r"Set-MpPreference.*-DisableBehaviorMonitoring", "Disabling behavior monitoring"),
    (r"Set-MpPreference.*-DisableIOAVProtection", "Disabling IOAV protection"),
    (r"sc\s+stop\s+WinDefend", "Stopping Windows Defender"),
    (r"sc\s+delete\s+WinDefend", "Deleting Windows Defender"),
    (r"bcdedit.*set.*recoveryenabled\s+no", "Disabling recovery"),
    (r"bcdedit.*set.*bootstatuspolicy.*ignoreallfailures", "Ignoring boot failures"),
    (r"vssadmin\s+delete\s+shadows", "Shadow copy deletion"),
    (r"wmic\s+shadowcopy\s+delete", "Shadow copy deletion via WMI"),
    (r"cipher\s+/w", "Wiping free space"),
    (r"wevtutil\s+cl", "Event log clearing"),
    (r"Clear-EventLog", "PowerShell event log clear"),
    (r"Remove-EventLog", "PowerShell event log removal"),
    (r"timestomp", "Timestomping"),
    (r"Set-MpPreference.*-ExclusionProcess", "Process exclusion"),
    (r"unhook.*ntdll", "Unhooking ntdll"),
    (r"EatHook", "EAT hooking"),
    (r"IatHook", "IAT hooking"),

    # --- Lateral Movement ---
    (r"Invoke-WMIMethod.*Win32_Process.*Create", "WMI remote execution"),
    (r"Invoke-Command.*-ComputerName", "PowerShell remoting"),
    (r"psexec.*\\\\", "PsExec remote execution"),
    (r"wmic.*\/node:.*process", "WMI remote process"),
    (r"Enter-PSSession", "PowerShell remote session"),

    # --- Data Exfiltration ---
    (r"ftp.*-s:", "FTP staging"),
    (r"tftp.*-i", "TFTP transfer"),
    (r"curl.*-T\s+", "CURL upload"),
    (r"wget.*--post", "WGET POST"),
    (r"Invoke-RestMethod.*-Method\s+Post", "PowerShell HTTP POST"),
    (r"Invoke-RestMethod.*-Uri.*\/api", "PowerShell API call"),
    (r"Invoke-WebRequest.*-Method\s+Post", "PowerShell web POST"),

    # --- C2 / RAT Indicators ---
    (r"New-Object.*Net\.Sockets\.TCPClient", "TCP reverse shell"),
    (r"New-Object.*Net\.Sockets\.UDPClient", "UDP reverse shell"),
    (r"\[System\.Net\.Sockets\]", "Raw .NET socket usage"),
    (r"System\.Net\.Sockets\.TcpClient", "TCP client creation"),
    (r"System\.Net\.Sockets\.UdpClient", "UDP client creation"),
    (r"System\.Net\.Sockets\.NetworkStream", "Network stream creation"),
    (r"System\.IO\.StreamReader.*NetworkStream", "Reading from network stream"),
    (r"System\.IO\.StreamWriter.*NetworkStream", "Writing to network stream"),
    (r"Start-Process.*-WindowStyle\s+Hidden", "Hidden process launch"),
    (r"Start-Process.*-NoNewWindow", "NoNewWindow process launch"),
    (r"Add-Type.*-TypeDefinition.*DllImport", "P/Invoke DllImport"),
    (r"VirtualAlloc", "VirtualAlloc (memory allocation)"),
    (r"VirtualProtect", "VirtualProtect (memory protection change)"),
    (r"CreateThread", "CreateThread (thread creation)"),
    (r"RtlMoveMemory", "RtlMoveMemory (memory copy)"),
    (r"WriteProcessMemory", "WriteProcessMemory (process injection)"),
    (r"NtCreateThreadEx", "NtCreateThreadEx"),
    (r"CreateRemoteThread", "CreateRemoteThread (process injection)"),
    (r"QueueUserAPC", "QueueUserAPC (process injection)"),
    (r"SetWindowsHookEx", "SetWindowsHookEx (keylogger)"),
    (r"GetAsyncKeyState", "GetAsyncKeyState (keylogger)"),
    (r"GetKeyState", "GetKeyState (keylogger)"),
    (r"RegisterHotKey", "RegisterHotKey (hotkey capture)"),
    (r"EnumWindows", "EnumWindows (window enumeration)"),
    (r"GetForegroundWindow", "GetForegroundWindow (active window)"),
    (r"GetWindowText", "GetWindowText (window text)"),
    (r"CapCreateCaptureWindow", "Screen capture window"),
    (r"BitBlt", "BitBlt (screen capture)"),
    (r"CreateCompatibleBitmap", "Compatible bitmap creation"),
    (r"GetDC", "GetDC (device context)"),
    (r"OpenDesktop", "OpenDesktop (desktop access)"),
    (r"EnumProcesses", "EnumProcesses"),
    (r"OpenProcess", "OpenProcess"),
    (r"ReadProcessMemory", "ReadProcessMemory"),
    (r"IsDebuggerPresent", "Anti-debug check"),
    (r"CheckRemoteDebuggerPresent", "Anti-debug check"),
    (r"NtQueryInformationProcess", "Anti-debug check"),
    (r"OutputDebugString", "Anti-debug check"),
    (r"SleepEx", "Anti-sandbox SleepEx"),
    (r"NtDelayExecution", "NtDelayExecution"),

    # --- Linux specific ---
    (r"\/bin\/sh\s+-c", "Shell execution"),
    (r"\/bin\/bash\s+-c", "Bash execution"),
    (r"\/bin\/dash\s+-c", "Dash execution"),
    (r"\/tmp\/\.", "Hidden file in /tmp"),
    (r"\/dev\/shm\/", "Shared memory abuse"),
    (r"cron.*\*.*\*.*\/bin\/sh", "Cron persistence"),
    (r"crontab.*-e", "Crontab editing"),
    (r"\/etc\/crontab", "System crontab"),
    (r"\/var\/spool\/cron", "User cron"),
    (r"chmod\s+777", "World-writable permissions"),
    (r"curl.*\|.*sh", "Pipe to shell (curl)"),
    (r"curl.*\|.*bash", "Pipe to bash (curl)"),
    (r"wget.*\|.*sh", "Pipe to shell (wget)"),
    (r"wget.*\|.*bash", "Pipe to bash (wget)"),
    (r"python.*-c.*socket", "Python socket execution"),
    (r"python3.*-c.*socket", "Python3 socket execution"),
    (r"perl.*-e.*socket", "Perl socket execution"),
    (r"ruby.*-e.*socket", "Ruby socket execution"),

    # --- Web shells ---
    (r"eval\s*\(\$_(GET|POST|REQUEST|COOKIE)", "PHP web shell eval"),
    (r"assert\s*\(\$_(GET|POST|REQUEST|COOKIE)", "PHP web shell assert"),
    (r"base64_decode\s*\(\$_(GET|POST|REQUEST)", "PHP web shell base64"),
    (r"shell_exec\s*\(\$_(GET|POST|REQUEST)", "PHP web shell exec"),
    (r"passthru\s*\(\$_(GET|POST|REQUEST)", "PHP web shell passthru"),
    (r"system\s*\(\$_(GET|POST|REQUEST)", "PHP web shell system"),
    (r"proc_open\s*\(\$_(GET|POST|REQUEST)", "PHP web shell proc_open"),
    (r"\$_(GET|POST|REQUEST)\[.*\]\s*\(\$_(GET|POST|REQUEST)", "PHP web shell function call"),
    (r"JEE7NS4xMjM0", "Base64 web shell marker"),
    (r"PD9waHA", "Base64 PHP open tag"),
    (r"PD9wdXNo", "Base64 push tag"),
    (r"<\?php.*eval.*base64_decode", "PHP webshell pattern"),
    (r"aspx一句话", "ASPX webshell"),
    (r"<%eval request", "ASP webshell"),
    (r"<%@ Page Language", "ASPX page"),
    (r"Runtime\.getRuntime\(\)\.exec", "Java runtime exec"),
    (r"ProcessBuilder.*start", "Java ProcessBuilder"),
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


def check_elf_info(data: bytes) -> dict:
    """Extract basic ELF file information and detect anomalies."""
    info = {}
    if len(data) < 64:
        return info
    if data[:4] != b"\x7fELF":
        return info

    try:
        ei_class = data[4]  # 1 = 32-bit, 2 = 64-bit
        ei_data = data[5]   # 1 = little-endian, 2 = big-endian

        if ei_class == 2 and ei_data == 1:  # 64-bit little-endian
            e_type = struct.unpack_from("<H", data, 16)[0]
            e_machine = struct.unpack_from("<H", data, 18)[0]
            e_entry = struct.unpack_from("<Q", data, 24)[0]
            e_phoff = struct.unpack_from("<Q", data, 28)[0]
            e_shoff = struct.unpack_from("<Q", data, 40)[0]
            e_flags = struct.unpack_from("<I", data, 48)[0]
            e_ehsize = struct.unpack_from("<H", data, 52)[0]
            e_phnum = struct.unpack_from("<H", data, 56)[0]
            e_shnum = struct.unpack_from("<H", data, 60)[0]

            type_names = {1: "REL (relocatable)", 2: "EXEC (executable)",
                         3: "DYN (shared object)", 4: "CORE"}
            info["type"] = type_names.get(e_type, f"0x{e_type:x}")
            info["entry"] = f"0x{e_entry:x}"
            info["sections"] = e_shnum
            info["segments"] = e_phnum

            # Detect anomalies
            if e_type == 2:  # EXEC
                info["executable"] = True
            if e_shnum == 0:
                info["no_section_headers"] = True
            if e_entry == 0:
                info["no_entry_point"] = True

        elif ei_class == 1 and ei_data == 1:  # 32-bit little-endian
            e_type = struct.unpack_from("<H", data, 16)[0]
            e_entry = struct.unpack_from("<I", data, 24)[0]
            e_shoff = struct.unpack_from("<I", data, 32)[0]
            e_shnum = struct.unpack_from("<H", data, 48)[0]

            type_names = {1: "REL (relocatable)", 2: "EXEC (executable)",
                         3: "DYN (shared object)", 4: "CORE"}
            info["type"] = type_names.get(e_type, f"0x{e_type:x}")
            info["entry"] = f"0x{e_entry:x}"
            info["sections"] = e_shnum

            if e_type == 2:
                info["executable"] = True
            if e_shnum == 0:
                info["no_section_headers"] = True

    except (struct.error, IndexError):
        pass

    return info


def detect_binary_patterns(data: bytes) -> list[str]:
    """Detect shellcode and malicious binary patterns in raw bytes."""
    patterns = []

    # --- Linux x86-64 syscall sequences ---
    # SYSCALL (0x0f 0x05) is the primary indicator
    syscall_count = data.count(b"\x0f\x05")
    if syscall_count >= 2:
        patterns.append(f"Linux x86-64 syscall sequences ({syscall_count} occurrences)")

    # INT 0x80 (0xcd 0x80) - 32-bit Linux syscalls
    int80_count = data.count(b"\xcd\x80")
    if int80_count >= 2:
        patterns.append(f"Linux x86 INT 0x80 syscalls ({int80_count} occurrences)")

    # --- Common shellcode byte patterns ---

    # XOR EAX,EAX (0x31 0xc0) - zeroing registers
    xor_eax = data.count(b"\x31\xc0")
    if xor_eax >= 1:
        patterns.append(f"XOR EAX,EAX (register zeroing: {xor_eax}x)")

    # XOR EBX,EBX (0x31 0xdb)
    xor_ebx = data.count(b"\x31\xdb")
    if xor_ebx >= 1:
        patterns.append(f"XOR EBX,EBX ({xor_ebx}x)")

    # XOR ECX,ECX (0x31 0xc9)
    xor_ecx = data.count(b"\x31\xc9")
    if xor_ecx >= 1:
        patterns.append(f"XOR ECX,ECX ({xor_ecx}x)")

    # XOR EDX,EDX (0x31 0xd2)
    xor_edx = data.count(b"\x31\xd2")
    if xor_edx >= 1:
        patterns.append(f"XOR EDX,EDX ({xor_edx}x)")

    # PUSH rbp / MOV rbp, rsp (function prologue)
    if b"\x55\x48\x89\xe5" in data or b"\x55\x48\x8b\xec" in data:
        patterns.append("Function prologue (PUSH rbp; MOV rbp,rsp)")

    # PUSH rax; POP rdi (common shellcode pattern)
    push_pop_count = 0
    for i in range(len(data) - 2):
        if data[i] == 0x50 and data[i + 2] == 0x5f:  # push rax; ... pop rdi
            push_pop_count += 1
    if push_pop_count >= 2:
        patterns.append(f"PUSH/POP register sequence ({push_pop_count}x)")

    # PUSH 0x2a; POP rax (socket syscall = 42)
    if b"\x6a\x2a\x58" in data:
        patterns.append("Socket syscall (PUSH 0x2a; POP rax = SYS_socket)")

    # PUSH 0x29; POP rax (connect syscall = 41)
    if b"\x6a\x29\x58" in data:
        patterns.append("Connect syscall (PUSH 0x29; POP rax = SYS_connect)")

    # PUSH 0x01; POP rdi (fd = 1, stdout)
    if b"\x6a\x01\x5f" in data:
        patterns.append("File descriptor setup (PUSH 1; POP rdi)")

    # PUSH 0x02; POP rdi (socket type SOCK_STREAM)
    if b"\x6a\x02\x5f" in data:
        patterns.append("Socket type setup (PUSH 2; POP rdi = SOCK_STREAM)")

    # JMP/CALL/POP pattern (string decoding in shellcode)
    if b"\xeb" in data and b"\x5e" in data:  # JMP short + POP rsi
        patterns.append("JMP/POP pattern (shellcode string decoding)")

    # --- NOP sled detection ---
    nop_sleds = [b"\x90" * 4, b"\x90" * 8, b"\x90" * 16]
    for sled in nop_sleds:
        if sled in data:
            patterns.append(f"NOP sled ({len(sled)} bytes)")
            break

    # --- Encoded IP/port detection ---
    # Look for common port patterns (little-endian 2 bytes after PUSH)
    common_ports = {
        b"\x5c\x11": 4444,    # port 4444
        b"\xbb\x01": 443,     # port 443
        b"\x50\x00": 80,      # port 80
        b"\x1f\x90": 34567,   # port 34567
        b"\x39\x05": 1337,    # port 1337
        b"\x0d\xbb": 44444,   # port 44444
        b"\x15\x53": 21298,   # port 21298
    }
    for pattern, port in common_ports.items():
        if pattern in data:
            patterns.append(f"Encoded port {port} (0x{pattern.hex()})")
            break

    # Detect IP addresses in network byte order (big-endian)
    ip_pattern = re.compile(
        rb"\x02\x00([\x00-\xff]{2})([\x00-\xff]{2})\x51"
    )
    match = ip_pattern.search(data)
    if match:
        ip_bytes = data[match.start() + 2:match.start() + 6]
        ip_int = struct.unpack("!I", ip_bytes)[0]
        ip_str = f"{(ip_int >> 24) & 0xff}.{(ip_int >> 16) & 0xff}.{(ip_int >> 8) & 0xff}.{ip_int & 0xff}"
        patterns.append(f"Encoded IP address: {ip_str}")

    # Also try to find IPs as 4 consecutive bytes that look like private/public IPs
    for i in range(len(data) - 3):
        if data[i] == 0xc0 and data[i + 1] == 0xa8:  # 192.168.x.x
            patterns.append(f"Private IP 192.168.{data[i+2]}.{data[i+3]} detected")
            break

    return patterns


def detect_elf_anomalies(data: bytes) -> list[str]:
    """Detect suspicious ELF characteristics."""
    anomalies = []

    if data[:4] != b"\x7fELF":
        return anomalies

    elf_info = check_elf_info(data)

    # Very small ELF with no section headers = likely shellcode
    if len(data) < 500 and elf_info.get("no_section_headers"):
        anomalies.append("Tiny ELF with no section headers (shellcode loader)")

    # Statically linked (no dynamic section)
    if b"\x00dynamic\x00" not in data and b"\x00.dynstr\x00" not in data:
        if len(data) < 2000:
            anomalies.append("Statically linked (no dynamic section)")

    # Entry point in code segment (typical for shellcode)
    if elf_info.get("executable") and elf_info.get("no_section_headers"):
        anomalies.append("Executable ELF without section headers")

    # Detect common shellcode in entry point
    entry_str = ""
    try:
        if elf_info.get("entry"):
            entry_addr = int(elf_info["entry"], 16)
            if entry_addr < len(data) - 10:
                entry_bytes = data[entry_addr:entry_addr + 16]
                entry_str = entry_bytes.hex()
    except (ValueError, IndexError):
        pass

    if entry_str:
        if "4831ff" in entry_str:  # XOR RDI,RDI
            anomalies.append("Entry point: XOR RDI,RDI (shellcode)")
        if "6a0958" in entry_str:  # PUSH 9; POP RAX (setuid)
            anomalies.append("Entry point: PUSH 9; POP RAX (setuid syscall)")
        if "6a3c58" in entry_str:  # PUSH 0x3c; POP RAX (exit)
            anomalies.append("Entry point: PUSH 0x3c; POP RAX (exit syscall)")

    return anomalies


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

    # ELF info
    if data[:4] == b"\x7fELF":
        result.pe_info = check_elf_info(data)

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

    # --- Binary pattern detection (for shellcode, ELF malware, etc.) ---
    bin_patterns = detect_binary_patterns(data)
    for bp in bin_patterns:
        result.suspicious_strings.append(bp)

    # --- ELF anomaly detection ---
    if data[:4] == b"\x7fELF":
        elf_anomalies = detect_elf_anomalies(data)
        for ea in elf_anomalies:
            result.suspicious_strings.append(ea)

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
    score += len(result.suspicious_strings) * 5
    if result.entropy > 7.0:
        score += 10
    if result.entropy > 7.5:
        score += 10
    if result.file_type == "PE (Windows executable)":
        score += 5
    if result.embedded_ips:
        score += min(len(result.embedded_ips) * 2, 10)

    # Heavily weight certain high-confidence indicators
    text_lower = " ".join(strings).lower()
    if any(p in text_lower for p in ["mimikatz", "sekurlsa", "kerberos::golden"]):
        score += 30
    if any(p in text_lower for p in ["reverse_tcp", "meterpreter", "bind_tcp"]):
        score += 30
    if any(p in text_lower for p in ["/dev/tcp/", "bash -i", "nc -e /bin/sh", "nc -e /bin/bash"]):
        score += 25
    if any(p in text_lower for p in ["virtualalloc", "virtualprotect", "writemem"]):
        score += 20
    if any(p in text_lower for p in ["schtasks.*create", "reg add.*\\\\run"]):
        score += 15
    if any(p in text_lower for p in ["disablerealtime", "stop windefend", "delete shadows"]):
        score += 20
    if any(p in text_lower for p in ["webshell", "webshell", "shell_exec($_", "eval($_"]):
        score += 25

    # Bonus for ELF/Linux malware indicators
    if result.file_type == "ELF (Linux executable)":
        elf_indicators = ["/bin/sh", "/bin/bash", "busybox", "mirai", "botnet", "wget.*sh", "curl.*sh"]
        if any(ind in text_lower for ind in elf_indicators):
            score += 20
        if result.entropy > 6.5:
            score += 5

    # Bonus for shellcode indicators
    shellcode_indicators = [
        "Linux x86-64 syscall", "INT 0x80", "XOR EAX,EAX",
        "Socket syscall", "Connect syscall", "NOP sled",
        "Encoded port", "Encoded IP", "JMP/POP pattern",
        "shellcode loader", "Executable ELF without section",
    ]
    shellcode_hits = sum(1 for si in shellcode_indicators
                         if any(si in s for s in result.suspicious_strings))
    if shellcode_hits >= 3:
        score += 30
    elif shellcode_hits >= 1:
        score += 20

    # Extra penalty for small ELF with shellcode characteristics
    if data[:4] == b"\x7fELF" and len(data) < 500:
        score += 25

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
