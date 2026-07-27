from __future__ import annotations

from dataclasses import dataclass, field

from malware_db import MalwareIP, check_ip
from models import CensysResult, ShodanResult
from network import Connection

# Scoring weights — each detection source contributes a weighted amount
SCORE_FRAMEWORK_DETECTED = 30
SCORE_INDICATOR = 10
SCORE_PORT_MATCH = 5
SCORE_DB_MATCH_UNIT = 20
SCORE_DB_MATCH_CAP = 40
SCORE_VULN_UNIT = 3
SCORE_SHODAN_SUSPECT = 25
SCORE_CENSYS_SUSPECT = 25
SCORE_MAX = 100

# Threat level thresholds
THRESHOLD_CRITICAL = 70
THRESHOLD_HIGH = 50
THRESHOLD_MEDIUM = 25

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
        "brute ratel", "bruteratel", "badger",
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
        "poshc2", "posh-c2",
    ],
    "Decaf": [
        "decaf", "decaf-c2",
    ],
}

C2_PORT_INDICATORS: dict[int, str] = {
    50050: "Cobalt Strike",
    8443: "Common C2 / HTTPS C2",
    53: "Possible DNS C2",
    8080: "Common C2",
    4444: "Metasploit (common)",
    5555: "Common C2",
    6568: "Sliver",
    9001: "Sliver / C2",
    8888: "Common C2",
    6606: "AsyncRAT",
    4782: "QuasarRAT",
    1177: "njRAT",
    5000: "Remcos / Agent Tesla",
    7443: "Covenant / Mythic",
    65530: "SectopRAT",
}


@dataclass
class ThreatResult:
    """Aggregated threat assessment for a single IP address.

    Combines data from the malware database, Shodan, Censys, and
    live connection analysis into a single scored result.

    Attributes:
        ip: The assessed IP address.
        detected_frameworks: C2 framework names identified from all sources.
        indicators: Human-readable explanation of why this IP was flagged.
        associated_ports: Open ports found via Shodan (capped at 10).
        malware_db_matches: Direct hits from the local threat database.
        shodan_result: Raw Shodan lookup data (if available).
        censys_result: Raw Censys lookup data (if available).
        connections: Active network connections to this IP.
    """

    ip: str
    detected_frameworks: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    associated_ports: list[int] = field(default_factory=list)
    malware_db_matches: list[MalwareIP] = field(default_factory=list)
    shodan_result: ShodanResult | None = None
    censys_result: CensysResult | None = None
    connections: list[Connection] = field(default_factory=list)

    @property
    def score(self) -> int:
        """Compute a 0-100 threat score from all detection signals."""
        score = 0
        score += len(self.detected_frameworks) * SCORE_FRAMEWORK_DETECTED
        score += len(self.indicators) * SCORE_INDICATOR
        score += len(self.associated_ports) * SCORE_PORT_MATCH
        if self.malware_db_matches:
            score += min(len(self.malware_db_matches) * SCORE_DB_MATCH_UNIT, SCORE_DB_MATCH_CAP)
        if self.shodan_result and self.shodan_result.vulns:
            score += len(self.shodan_result.vulns) * SCORE_VULN_UNIT
        if self.shodan_result and self.shodan_result.is_c2_suspect:
            score += SCORE_SHODAN_SUSPECT
        if self.censys_result and self.censys_result.is_c2_suspect:
            score += SCORE_CENSYS_SUSPECT
        return min(score, SCORE_MAX)

    @property
    def threat_label(self) -> str:
        """Map the numeric score to a human-readable threat level."""
        s = self.score
        if s >= THRESHOLD_CRITICAL:
            return "CRITICAL"
        if s >= THRESHOLD_HIGH:
            return "HIGH"
        if s >= THRESHOLD_MEDIUM:
            return "MEDIUM"
        return "LOW"


def analyze_shodan_banners(result: ShodanResult) -> list[str]:
    """Scan Shodan banners for known C2 framework keywords.

    Args:
        result: ShodanResult containing banner data.

    Returns:
        List of detected framework names (e.g. ["Cobalt Strike"]).
    """
    indicators: list[str] = []
    for banner in result.banners:
        product = (banner.get("product") or "").lower()
        data = (banner.get("data") or "").lower()
        http_body = (banner.get("http", {}).get("body", "") or "").lower()

        all_text = f"{product} {data} {http_body}"

        for framework, keywords in KNOWN_C2_FRAMEWORKS.items():
            for kw in keywords:
                if kw in all_text and framework not in indicators:
                    indicators.append(framework)

    return indicators


def analyze_censys_services(result: CensysResult) -> list[str]:
    """Scan Censys service entries for known C2 framework keywords.

    Args:
        result: CensysResult containing service data.

    Returns:
        List of detected framework names (e.g. ["Sliver"]).
    """
    indicators: list[str] = []
    for svc in result.services:
        svc_text = " ".join(str(v) for v in svc.values()).lower()
        for framework, keywords in KNOWN_C2_FRAMEWORKS.items():
            for kw in keywords:
                if kw in svc_text and framework not in indicators:
                    indicators.append(framework)
    return indicators


def analyze_connection_ports(connections: list[Connection]) -> list[str]:
    """Check connection ports against known C2 port indicators.

    Args:
        connections: List of active Connection objects.

    Returns:
        List of framework/indicator names for matching ports.
    """
    indicators: list[str] = []
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
    """Perform a full threat assessment on an IP address.

    Combines the local malware database, Shodan banners, Censys services,
    and active connection ports to produce a scored ThreatResult.

    Args:
        ip: IPv4 address to assess.
        shodan_result: Optional Shodan enrichment data.
        censys_result: Optional Censys enrichment data.
        connections: Optional list of active connections to this IP.

    Returns:
        ThreatResult with score, threat label, and all indicators.
    """
    result = ThreatResult(
        ip=ip,
        shodan_result=shodan_result,
        censys_result=censys_result,
        connections=connections or [],
    )

    # Check local threat database
    db_matches = check_ip(ip)
    if db_matches:
        result.malware_db_matches = db_matches
        families = list({m.malware_family for m in db_matches})
        actors = list({m.threat_actor for m in db_matches if m.threat_actor != "Various"})
        result.indicators.append(
            f"KNOWN MALICIOUS: Matched {len(db_matches)} record(s) in threat database"
        )
        result.indicators.append(f"Malware families: {', '.join(families)}")
        if actors:
            result.indicators.append(f"Threat actors: {', '.join(actors)}")
        for m in db_matches:
            if m.malware_family not in result.detected_frameworks:
                result.detected_frameworks.append(m.malware_family)

    # Shodan banner analysis
    if shodan_result and not shodan_result.error:
        shodan_indicators = analyze_shodan_banners(shodan_result)
        result.detected_frameworks.extend(shodan_indicators)

    # Censys service analysis
    if censys_result and not censys_result.error:
        censys_indicators = analyze_censys_services(censys_result)
        for fw in censys_indicators:
            if fw not in result.detected_frameworks:
                result.detected_frameworks.append(fw)

    # Port-based indicators
    if connections:
        port_indicators = analyze_connection_ports(connections)
        for fw in port_indicators:
            if fw not in result.detected_frameworks:
                result.detected_frameworks.append(fw)
            if fw not in result.indicators:
                matching_port = next(
                    c.remote_port for c in connections
                    if C2_PORT_INDICATORS.get(c.remote_port) == fw
                )
                result.indicators.append(
                    f"Port {matching_port} associated with {fw}"
                )

    # Shodan vulnerability and port enrichment
    if shodan_result and not shodan_result.error:
        if shodan_result.vulns:
            result.indicators.append(
                f"{len(shodan_result.vulns)} known vulnerabilities found"
            )
        result.associated_ports = shodan_result.ports[:10]

    # Prepend framework summary
    if result.detected_frameworks:
        result.indicators.insert(
            0, f"C2 frameworks detected: {', '.join(result.detected_frameworks)}"
        )

    return result
