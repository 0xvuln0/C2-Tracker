"""Data models for enrichment results.

These are pure dataclasses with no heavy dependencies (no shodan, censys,
psutil imports) so they can be safely imported by the analyzer and CLI
without requiring API libraries to be installed.
"""

from __future__ import annotations

from dataclasses import dataclass, field


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
        """Check if banners contain known C2 framework indicators."""
        c2_indicators = [
            "cobalt",
            "cobaltstrike",
            "beacon",
            "malleable",
            "metasploit",
            "meterpreter",
            "covenant",
            "grunt",
            "sliver",
            "brute ratel",
            "bruteratel",
            "badger",
            "havoc",
            "demon",
            "decaf",
            "mythic",
            "apfell",
            "empire",
            "powershell-empire",
            "poshc2",
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


@dataclass
class CensysResult:
    """Result of a Censys IP lookup.

    Attributes:
        ip: The queried IP address.
        ports: Open ports discovered.
        protocols: Transport protocols observed.
        services: Raw service data from Censys.
        location_country: Country name.
        location_city: City name.
        autonomous_system_org: ASN organization name.
        operating_system: Detected OS product.
        error: Error message if the lookup failed, None otherwise.
    """

    ip: str
    ports: list[int] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)
    services: list[dict] = field(default_factory=list)
    location_country: str | None = None
    location_city: str | None = None
    autonomous_system_org: str | None = None
    operating_system: str | None = None
    error: str | None = None

    @property
    def is_c2_suspect(self) -> bool:
        """Check if services contain known C2 framework indicators."""
        c2_keywords = [
            "cobalt",
            "cobaltstrike",
            "metasploit",
            "meterpreter",
            "covenant",
            "grunt",
            "sliver",
            "brute ratel",
            "bruteratel",
            "havoc",
            "demon",
            "decaf",
            "mythic",
            "apfell",
            "empire",
            "powershell-empire",
            "poshc2",
        ]
        service_text = " ".join(
            f"{s.get('service_name', '')} {s.get('extended_service_name', '')}" for s in self.services
        ).lower()
        return any(kw in service_text for kw in c2_keywords)

    def __str__(self) -> str:
        parts = [f"IP: {self.ip}"]
        if self.location_country:
            parts.append(f"Country: {self.location_country}")
        if self.autonomous_system_org:
            parts.append(f"ASN: {self.autonomous_system_org}")
        if self.ports:
            parts.append(f"Ports: {', '.join(str(p) for p in self.ports)}")
        if self.services:
            svc_names = [s.get("service_name", "unknown") for s in self.services[:5]]
            parts.append(f"Services: {', '.join(svc_names)}")
        return " | ".join(parts)
