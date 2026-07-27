from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from censys.search import CensysHosts


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
        """Check if services contain known C2 framework indicators.

        Returns True if any service name matches known C2 tooling signatures.
        """
        c2_keywords = [
            "cobalt", "cobaltstrike", "metasploit", "meterpreter",
            "covenant", "grunt", "sliver", "brute ratel", "bruteratel",
            "havoc", "demon", "decaf", "mythic", "apfell",
            "empire", "powershell-empire", "poshc2",
        ]
        service_text = " ".join(
            f"{s.get('service_name', '')} {s.get('extended_service_name', '')}"
            for s in self.services
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


def lookup_ip(api_id: str, api_secret: str, ip: str) -> CensysResult:
    """Look up an IP address via the Censys Search API.

    Args:
        api_id: Censys API ID. If empty, returns an error result.
        api_secret: Censys API secret. If empty, returns an error result.
        ip: IPv4 address to look up.

    Returns:
        CensysResult with enriched data or an error message.
    """
    result = CensysResult(ip=ip)

    if not api_id or not api_secret:
        result.error = "Censys API credentials not configured"
        return result

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        result.error = f"Invalid IP address: {ip}"
        return result

    try:
        hosts = CensysHosts(api_id=api_id, api_secret=api_secret)
        host = hosts.get(ip)

        result.ports = [svc["port"] for svc in host.get("services", []) if "port" in svc]
        result.protocols = list({
            svc.get("transport_protocol", "")
            for svc in host.get("services", [])
            if svc.get("transport_protocol")
        })
        result.services = host.get("services", [])

        loc = host.get("location", {})
        result.location_country = loc.get("country")
        result.location_city = loc.get("city")

        asn = host.get("autonomous_system", {})
        result.autonomous_system_org = asn.get("name")

        os_info = host.get("operating_system", {})
        result.operating_system = os_info.get("product") or os_info.get("uniform_resource_identifier")

    except Exception as e:
        result.error = f"Censys lookup failed: {e}"

    return result
