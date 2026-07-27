"""YARA rule scanning capability for malware detection.

Provides a YaraScanner class that compiles and loads YARA rules from
a directory of .yar files and includes built-in rules for common
malware patterns. Falls back gracefully if yara-python is not installed.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    yara = None  # type: ignore[assignment]
    YARA_AVAILABLE = False


# ---------------------------------------------------------------------------
# Built-in YARA rules (stored as Python strings)
# ---------------------------------------------------------------------------

BUILTIN_RULES: dict[str, str] = {
    "reverse_shells": r"""
rule BashReverseShell {
    meta:
        description = "Detects bash reverse shell patterns"
        severity = "high"
        category = "reverse_shell"
    strings:
        $bash1 = "bash -i >& /dev/tcp/"
        $bash2 = "/dev/tcp/"
        $bash3 = "0<&196;exec 196<>/dev/tcp/"
        $nc1 = "nc -e /bin/sh"
        $nc2 = "ncat -e /bin/sh"
        $nc3 = "nc -e /bin/bash"
    condition:
        any of them
}

rule PythonReverseShell {
    meta:
        description = "Detects Python reverse shell patterns"
        severity = "high"
        category = "reverse_shell"
    strings:
        $py1 = "import socket" ascii
        $py2 = "socket.socket" ascii
        $py3 = "SOCK_STREAM" ascii
        $py4 = "connect((" ascii
        $py5 = "subprocess.Popen" ascii
        $py6 = "os.dup2" ascii
        $py7 = "os.system" ascii
        $py9 = "__import__('os')" ascii
        $cmd1 = "subprocess.call" ascii
        $cmd2 = "subprocess.run" ascii
    condition:
        ($py1 and $py2 and $py3 and $py4) or
        ($py5 and $py6 and $py7) or
        ($py9 and $py5) or
        ($py1 and $cmd1 and $py6) or
        ($py1 and $cmd2 and $py6)
}

rule PerlReverseShell {
    meta:
        description = "Detects Perl reverse shell patterns"
        severity = "high"
        category = "reverse_shell"
    strings:
        $perl1 = "use Socket" ascii
        $perl2 = "INET" ascii
        $perl3 = "socket(S," ascii
        $perl4 = "connect(S," ascii
        $perl5 = "exec {'/bin/sh'}" ascii
        $perl6 = "open(STDIN," ascii
        $perl7 = "open(STDOUT," ascii
    condition:
        ($perl1 and $perl2 and $perl3 and $perl4) or
        ($perl5 and $perl6 and $perl7)
}
""",

    "cobalt_strike": r"""
rule CobaltStrikeBeacon {
    meta:
        description = "Detects Cobalt Strike beacon indicators"
        severity = "critical"
        category = "c2"
    strings:
        $cs1 = "beacon.dll" ascii nocase
        $cs2 = "cobaltstrike" ascii nocase
        $cs3 = "malleable c2" ascii nocase
        $cs4 = "jquery-3.3.1.min.js" ascii
        $cs5 = "pipe\\msagent_" ascii
        $cs6 = "pipe\\msSECEH_" ascii
        $cs7 = "PostError" ascii
        $cs8 = "default.html" ascii
        $cs9 = "GetUser" ascii
        $cs10 = "GetComputerNameW" ascii
        $cfg1 = "set hostname" ascii nocase
        $cfg2 = "set uri" ascii nocase
        $cfg3 = "set user-agent" ascii nocase
        $cfg4 = "set headers" ascii nocase
        $cfg5 = "set metadata" ascii nocase
        $cfg6 = "set tcp_frame_header" ascii nocase
    condition:
        3 of ($cs*) or
        4 of ($cfg*)
}

rule CobaltStrikeShellcode {
    meta:
        description = "Detects Cobalt Strike beacon shellcode patterns"
        severity = "critical"
        category = "c2"
    strings:
        $x64 = { 48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 }
        $x86 = { 55 8B EC 83 EC 0C 53 56 57 }
        $jmp = { FC E8 }
    condition:
        $x64 at 0 or
        $x86 at 0 or
        ($jmp and $x64) or
        ($jmp and $x86)
}
""",

    "metasploit": r"""
rule MetasploitPayload {
    meta:
        description = "Detects Metasploit payload indicators"
        severity = "critical"
        category = "exploit_framework"
    strings:
        $msf1 = "meterpreter" ascii nocase
        $msf2 = "reverse_tcp" ascii
        $msf3 = "reverse_http" ascii
        $msf4 = "metsvc" ascii
        $msf5 = "windows/meterpreter" ascii
        $msf6 = "msfconsole" ascii
        $msf7 = "exploit/multi" ascii
        $msf8 = "msfvenom" ascii
        $msf9 = "stageless" ascii
        $msf10 = "staged" ascii
        $msf11 = "LPORT=" ascii
        $msf12 = "LHOST=" ascii
        $msf13 = "AutoRunScript" ascii
    condition:
        3 of them
}

rule MetasploitShellcode {
    meta:
        description = "Detects Metasploit-generated shellcode patterns"
        severity = "critical"
        category = "exploit_framework"
    strings:
        $win_x64 = { FC E8 82 00 00 00 60 89 E5 31 D2 }
        $win_x86 = { FC E8 89 00 00 00 60 89 E5 31 D2 }
        $meterpreter = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 }
        $linux_x64 = { 48 31 C0 48 31 FF 48 31 F6 48 31 D2 }
    condition:
        any of them
}
""",

    "webshells": r"""
rule PHPWebShell {
    meta:
        description = "Detects common PHP web shell patterns"
        severity = "critical"
        category = "webshell"
    strings:
        $php1 = "eval($_GET" ascii
        $php2 = "eval($_POST" ascii
        $php3 = "eval($_REQUEST" ascii
        $php4 = "assert($_GET" ascii
        $php5 = "assert($_POST" ascii
        $php6 = "shell_exec($_GET" ascii
        $php7 = "shell_exec($_POST" ascii
        $php8 = "passthru($_GET" ascii
        $php9 = "passthru($_POST" ascii
        $php10 = "system($_GET" ascii
        $php11 = "system($_POST" ascii
        $php12 = "proc_open($_GET" ascii
        $php13 = "proc_open($_POST" ascii
        $php14 = "base64_decode($_" ascii
        $php15 = "eval(base64_decode" ascii
        $php16 = "PD9waHA" ascii
        $php17 = "JEE7NS4xMjM0" ascii
    condition:
        2 of them
}

rule ASPWebShell {
    meta:
        description = "Detects common ASP/ASPX web shell patterns"
        severity = "critical"
        category = "webshell"
    strings:
        $asp1 = "<%eval request" ascii nocase
        $asp2 = "<%eval(Request" ascii nocase
        $asp3 = "<%@ Page Language" ascii nocase
        $asp4 = "Response.Write" ascii
        $asp5 = "Request.Form" ascii
        $asp6 = "Request.QueryString" ascii
        $asp7 = "CreateObject(\"WScript" ascii nocase
        $asp8 = "cmd.exe /c" ascii
        $aspx1 = "aspx一句话" ascii
        $aspx2 = "<%@ Page" ascii
        $aspx3 = "System.Diagnostics.Process" ascii
    condition:
        ($asp1 and ($asp4 or $asp5 or $asp6)) or
        ($asp2 and ($asp4 or $asp5 or $asp6)) or
        ($asp3 and $asp7) or
        ($aspx1) or
        ($aspx2 and $asp7) or
        ($aspx3 and $asp8)
}

rule JavaWebShell {
    meta:
        description = "Detects Java-based web shell patterns"
        severity = "high"
        category = "webshell"
    strings:
        $java1 = "Runtime.getRuntime().exec" ascii
        $java2 = "ProcessBuilder" ascii
        $java3 = ".start()" ascii
        $java4 = "getParameter(" ascii
        $java5 = "request.getParameter" ascii
    condition:
        ($java1 and $java4) or
        ($java2 and $java3 and $java5)
}
""",

    "credential_dumping": r"""
rule Mimikatz {
    meta:
        description = "Detects Mimikatz credential dumping tool"
        severity = "critical"
        category = "credential_access"
    strings:
        $mimi1 = "mimikatz" ascii nocase
        $mimi2 = "Invoke-Mimikatz" ascii nocase
        $mimi3 = "sekurlsa::logonpasswords" ascii nocase
        $mimi4 = "sekurlsa::wdigest" ascii nocase
        $mimi5 = "sekurlsa::kerberos" ascii nocase
        $mimi6 = "kerberos::golden" ascii nocase
        $mimi7 = "kerberos::ptt" ascii nocase
        $mimi8 = "pypykatz" ascii
    condition:
        2 of them
}

rule LsassDump {
    meta:
        description = "Detects LSASS memory dump techniques"
        severity = "critical"
        category = "credential_access"
    strings:
        $lsass1 = "lsass.dmp" ascii nocase
        $lsass2 = "procdump.*lsass" ascii nocase
        $lsass3 = "comsvcs.dll" ascii
        $lsass4 = "MiniDump" ascii
        $lsass5 = "rundll32.*comsvcs" ascii nocase
        $lsass6 = "Tasklist /m" ascii nocase
        $lsass7 = "procdump" ascii
    condition:
        ($lsass1) or
        ($lsass2) or
        ($lsass3 and $lsass4) or
        ($lsass5) or
        ($lsass6 and $lsass7)
}

rule Kerberoasting {
    meta:
        description = "Detects Kerberoasting and token manipulation tools"
        severity = "high"
        category = "credential_access"
    strings:
        $kerb1 = "Invoke-Kerberoast" ascii nocase
        $kerb2 = "Invoke-TokenManipulation" ascii nocase
        $kerb3 = "Invoke-DCShadow" ascii nocase
        $kerb4 = "Get-GPPPassword" ascii nocase
        $kerb5 = "crackmapexec" ascii nocase
        $kerb6 = "Invoke-DCSync" ascii nocase
    condition:
        2 of them
}
""",
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class YaraMatch:
    """A single YARA rule match."""

    rule_name: str
    namespace: str
    tags: list[str] = field(default_factory=list)
    meta: dict[str, str] = field(default_factory=dict)
    strings: list[tuple[int, str, bytes]] = field(default_factory=list)

    @property
    def severity(self) -> str:
        return self.meta.get("severity", "unknown")

    @property
    def category(self) -> str:
        return self.meta.get("category", "unknown")


@dataclass
class YaraScanResult:
    """Result of scanning a file with YARA rules."""

    path: str
    matches: list[YaraMatch] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    rules_loaded: int = 0

    @property
    def is_malicious(self) -> bool:
        return len(self.matches) > 0

    @property
    def matched_rules(self) -> list[str]:
        return [m.rule_name for m in self.matches]

    @property
    def unique_severities(self) -> list[str]:
        return list({m.severity for m in self.matches})

    @property
    def unique_categories(self) -> list[str]:
        return list({m.category for m in self.matches})


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class YaraScanner:
    """YARA rule scanner that compiles rules from files and built-in sources.

    Args:
        rules_dir: Directory containing .yar / .yara rule files.
            Defaults to ``rules/`` next to this module.
        include_builtin: Whether to include the built-in rules.
    """

    def __init__(
        self,
        rules_dir: str | None = None,
        include_builtin: bool = True,
    ) -> None:
        self.rules_dir = rules_dir or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "rules"
        )
        self.include_builtin = include_builtin
        self._compiled: object | None = None
        self._rule_count = 0

        if YARA_AVAILABLE:
            self._compile_rules()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _collect_rule_files(self) -> list[str]:
        """Return paths to all .yar / .yara files in the rules directory."""
        if not os.path.isdir(self.rules_dir):
            return []
        paths: list[str] = []
        for fname in sorted(os.listdir(self.rules_dir)):
            if fname.endswith((".yar", ".yara")):
                paths.append(os.path.join(self.rules_dir, fname))
        return paths

    def _compile_rules(self) -> None:
        """Compile built-in and file-based YARA rules."""
        if not YARA_AVAILABLE:
            return

        sources: dict[str, str] = {}

        # Built-in rules
        if self.include_builtin:
            for name, rule_text in BUILTIN_RULES.items():
                sources[f"builtin_{name}"] = rule_text

        # File-based rules
        for path in self._collect_rule_files():
            try:
                with open(path, encoding="utf-8") as fh:
                    key = f"file_{os.path.basename(path)}"
                    sources[key] = fh.read()
            except (OSError, UnicodeDecodeError):
                continue

        if not sources:
            return

        try:
            self._compiled = yara.compile(
                sources=sources  # type: ignore[arg-type]
            )
            self._rule_count = len(sources)
        except yara.SyntaxError:
            # Attempt to compile sources individually to isolate bad rules
            self._compiled = None
            self._rule_count = 0

            for key, source in sources.items():
                try:
                    partial = yara.compile(source=source)  # type: ignore[arg-type]
                    if self._compiled is None:
                        self._compiled = partial
                    self._rule_count += 1
                except yara.SyntaxError:
                    continue

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def available(self) -> bool:
        """Whether yara-python is installed and rules were compiled."""
        return YARA_AVAILABLE and self._compiled is not None

    @property
    def rule_count(self) -> int:
        """Number of successfully compiled rule sources."""
        return self._rule_count

    def scan_file(self, file_path: str) -> YaraScanResult:
        """Scan a file against all loaded YARA rules.

        Args:
            file_path: Absolute or relative path to the file to scan.

        Returns:
            YaraScanResult containing all matches and any errors.
        """
        result = YaraScanResult(path=file_path, rules_loaded=self._rule_count)

        if not YARA_AVAILABLE:
            result.errors.append("yara-python is not installed")
            return result

        if self._compiled is None:
            result.errors.append("No YARA rules were compiled successfully")
            return result

        if not os.path.isfile(file_path):
            result.errors.append(f"File not found: {file_path}")
            return result

        try:
            matches = self._compiled.match(file_path)  # type: ignore[union-attr]
        except Exception as exc:
            result.errors.append(f"YARA scan error: {exc}")
            return result

        for match in matches:
            ym = YaraMatch(
                rule_name=match.rule,
                namespace=match.namespace,
                tags=list(match.tags),
                meta=dict(match.meta) if match.meta else {},
                strings=[
                    (inst.offset, s.identifier, inst.matched_data)
                    for s in match.strings
                    for inst in s.instances
                ],
            )
            result.matches.append(ym)

        return result

    def scan_data(self, data: bytes, identifier: str = "<memory>") -> YaraScanResult:
        """Scan raw bytes against all loaded YARA rules.

        Args:
            data: Raw bytes to scan.
            identifier: Label used in the result to identify this scan.

        Returns:
            YaraScanResult containing all matches and any errors.
        """
        result = YaraScanResult(path=identifier, rules_loaded=self._rule_count)

        if not YARA_AVAILABLE:
            result.errors.append("yara-python is not installed")
            return result

        if self._compiled is None:
            result.errors.append("No YARA rules were compiled successfully")
            return result

        try:
            matches = self._compiled.match(data=data)  # type: ignore[union-attr]
        except Exception as exc:
            result.errors.append(f"YARA scan error: {exc}")
            return result

        for match in matches:
            ym = YaraMatch(
                rule_name=match.rule,
                namespace=match.namespace,
                tags=list(match.tags),
                meta=dict(match.meta) if match.meta else {},
                strings=[
                    (inst.offset, s.identifier, inst.matched_data)
                    for s in match.strings
                    for inst in s.instances
                ],
            )
            result.matches.append(ym)

        return result

    def scan_string(self, text: str, identifier: str = "<string>") -> YaraScanResult:
        """Scan a text string against all loaded YARA rules.

        Convenience wrapper around :meth:`scan_data`.

        Args:
            text: String to scan.
            identifier: Label used in the result.

        Returns:
            YaraScanResult containing all matches and any errors.
        """
        return self.scan_data(data=text.encode("utf-8"), identifier=identifier)

    def list_rules(self) -> list[str]:
        """Return names of all compiled rule files / sources."""
        names: list[str] = []
        if self.include_builtin:
            names.extend(f"builtin_{k}" for k in BUILTIN_RULES)
        for path in self._collect_rule_files():
            names.append(f"file_{os.path.basename(path)}")
        return names
