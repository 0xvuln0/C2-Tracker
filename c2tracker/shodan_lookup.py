from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

import shodan


@dataclass
class ShodanResult:
    """Result of a Shodan IP lookup.

    Attributes:
        ip: The queried IP address.
        ports: Open ports discovered.
        hostnames: DNS hostnames associated with the IP.
        os: Detected operating system.
        org: Organization owning the IP.
        isp: Internet service provider.
        country: Country name.
        city: City name.
        banners: Raw banner data from Shodan services.
        vulns: Known CVE identifiers.
        error: Error message if the lookup failed, None otherwise.
    """

    ip: str
    ports: list[int] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    os: str | None = None
    org: str | None = None
    isp: str | None = None
    country: str | None = None
    city: str | None = None
    banners: list[dict] = field(default_factory=list)
    vulns: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def is_c2_suspect(self) -> bool:
        """Check if banners contain known C2 framework indicators.

        Returns True if any banner matches known C2 tooling signatures.
        """
        c2_indicators = [
            "cobalt", "cobaltstrike", "beacon", "malleable",
            "metasploit", "meterpreter", "covenant", "grunt",
            "sliver", "brute ratel", "bruteratel", "badger",
            "havoc", "demon", "decaf", "mythic", "apfell",
            "empire", "powershell-empire", "poshc2",
        ]
        banner_text = " ".join(str(b) for b in self.banners).lower()
        return any(ind in banner_text for ind in c2_indicators)

    def __str__(self) -> str:
        parts = [f"IP: {self.ip}"]
        if self.os:
            parts.append(f"OS: {self.os}")
        if self.org:
            parts.append(f"Org: {self.org}")
        if self.country:
            parts.append(f"Country: {self.country}")
        if self.ports:
            parts.append(f"Ports: {', '.join(str(p) for p in self.ports)}")
        if self.vulns:
            parts.append(f"Vulns: {len(self.vulns)}")
        return " | ".join(parts)


def lookup_ip(api_key: str, ip: str) -> ShodanResult:
    """Look up an IP address via the Shodan API.

    Args:
        api_key: Shodan API key. If empty, returns an error result.
        ip: IPv4 address to look up.

    Returns:
        ShodanResult with enriched data or an error message.
    """
    result = ShodanResult(ip=ip)

    if not api_key:
        result.error = "Shodan API key not configured"
        return result

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        result.error = f"Invalid IP address: {ip}"
        return result

    try:
        api = shodan.Shodan(api_key)
        host = api.host(ip)

        result.ports = host.get("ports", [])
        result.hostnames = host.get("hostnames", [])
        result.os = host.get("os")
        result.org = host.get("org")
        result.isp = host.get("isp")
        result.country = host.get("country_name")
        result.city = host.get("city")
        result.banners = host.get("data", [])
        vulns = host.get("vulns", {})
        result.vulns = list(vulns.keys()) if isinstance(vulns, dict) else list(vulns)

    except shodan.APIError as e:
        result.error = f"Shodan API error: {e}"
    except Exception as e:
        result.error = f"Shodan lookup failed: {e}"

    return result
