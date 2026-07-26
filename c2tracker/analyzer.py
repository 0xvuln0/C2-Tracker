from __future__ import annotations

from dataclasses import dataclass, field

from c2tracker.censys_lookup import CensysResult
from c2tracker.network import Connection
from c2tracker.shodan_lookup import ShodanResult

KNOWN_C2_FRAMEWORKS: dict[str, list[str]] = {
    "Cobalt Strike": [
        "cobalt", "cobaltstrike", "beacon", "malleable c2",
        "covert", "default.html", "jquery-3.3.1.min.js",
    ],
    "Metasploit": [
        "metasploit", "meterpreter", "msf", "reverse_tcp",
        "reverse_http", "staged", "stageless",
    ],
    "Sliver": [
        "sliver", "sliver-c2", "mtls", "wireguard",
        "http-c2", "dns-c2", "named pipe",
    ],
    "Covenant": [
        "covenant", "grunt", "covenantframework",
    ],
    "Brute Ratel": [
        "brute ratel", "bruteratel", "badger", "covenant",
    ],
    "Havoc": [
        "havoc", "havoc-c2", "demon",
    ],
    "Mythic": [
        "mythic", "mythic-c2", "athena", "apfell",
    ],
    "Empire": [
        "empire", "empire-c2", "powershell-empire",
    ],
    "PoshC2": [
        "poshc2", "posh", "posh-c2",
    ],
    "Decaf": [
        "decaf", "decaf-c2",
    ],
    "C2Lite": [
        "c2lite", "c2-lite",
    ],
}

C2_PORT_INDICATORS: dict[int, str] = {
    50050: "Cobalt Strike",
    8443: "Common C2 / HTTPS C2",
    443: "Common HTTPS C2",
    80: "Common HTTP C2",
    53: "Possible DNS C2",
    8080: "Common C2",
    4444: "Metasploit (common)",
    5555: "Common C2",
    6568: "Sliver",
    9001: "Sliver / C2",
    8888: "Common C2",
}

SUSPICIOUS_EXTENSIONS = [
    ".exe", ".dll", ".sys", ".bin", ".ps1", ".bat", ".cmd",
    ".vbs", ".js", ".hta", ".scr", ".com", ".pif",
]


@dataclass
class ThreatResult:
    ip: str
    threat_level: str = "low"
    detected_frameworks: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    associated_ports: list[int] = field(default_factory=list)
    shodan_result: ShodanResult | None = None
    censys_result: CensysResult | None = None
    connections: list[Connection] = field(default_factory=list)

    @property
    def score(self) -> int:
        score = 0
        score += len(self.detected_frameworks) * 30
        score += len(self.indicators) * 10
        score += len(self.associated_ports) * 5
        if self.shodan_result and self.shodan_result.vulns:
            score += len(self.shodan_result.vulns) * 3
        if self.shodan_result and self.shodan_result.is_c2_suspect:
            score += 25
        if self.censys_result and self.censys_result.is_c2_suspect:
            score += 25
        return min(score, 100)

    @property
    def threat_label(self) -> str:
        s = self.score
        if s >= 70:
            return "CRITICAL"
        if s >= 50:
            return "HIGH"
        if s >= 25:
            return "MEDIUM"
        return "LOW"


def analyze_shodan_banners(result: ShodanResult) -> list[str]:
    indicators = []
    for banner in result.banners:
        product = (banner.get("product") or "").lower()
        data = (banner.get("data") or "").lower()
        _http_body = (banner.get("http", {}).get("body", "") or "").lower()

        all_text = f"{product} {data} {_http_body}"

        for framework, keywords in KNOWN_C2_FRAMEWORKS.items():
            for kw in keywords:
                if kw in all_text and framework not in indicators:
                    indicators.append(framework)

    return indicators


def analyze_censys_services(result: CensysResult) -> list[str]:
    indicators = []
    for svc in result.services:
        svc_text = " ".join(str(v) for v in svc.values()).lower()
        for framework, keywords in KNOWN_C2_FRAMEWORKS.items():
            for kw in keywords:
                if kw in svc_text and framework not in indicators:
                    indicators.append(framework)
    return indicators


def analyze_connection_ports(connections: list[Connection]) -> list[str]:
    indicators = []
    for conn in connections:
        if conn.remote_port in C2_PORT_INDICATORS:
            framework = C2_PORT_INDICATORS[conn.remote_port]
            if framework not in indicators:
                indicators.append(framework)
    return indicators


def analyze_threat(
    ip: str,
    shodan_result: ShodanResult | None = None,
    censys_result: CensysResult | None = None,
    connections: list[Connection] | None = None,
) -> ThreatResult:
    result = ThreatResult(
        ip=ip,
        shodan_result=shodan_result,
        censys_result=censys_result,
        connections=connections or [],
    )

    if shodan_result and not shodan_result.error:
        shodan_indicators = analyze_shodan_banners(shodan_result)
        result.detected_frameworks.extend(shodan_indicators)

    if censys_result and not censys_result.error:
        censys_indicators = analyze_censys_services(censys_result)
        for fw in censys_indicators:
            if fw not in result.detected_frameworks:
                result.detected_frameworks.append(fw)

    if connections:
        port_indicators = analyze_connection_ports(connections)
        for fw in port_indicators:
            if fw not in result.detected_frameworks:
                result.detected_frameworks.append(fw)
            if fw not in result.indicators:
                result.indicators.append(f"Port {next(c.remote_port for c in connections if C2_PORT_INDICATORS.get(c.remote_port) == fw)} associated with {fw}")

    if shodan_result and not shodan_result.error:
        if shodan_result.vulns:
            result.indicators.append(f"{len(shodan_result.vulns)} known vulnerabilities found")
        result.associated_ports = shodan_result.ports[:10]

    if result.detected_frameworks:
        result.indicators.insert(0, f"C2 frameworks detected: {', '.join(result.detected_frameworks)}")

    return result
