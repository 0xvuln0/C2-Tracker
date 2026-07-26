from __future__ import annotations

from dataclasses import dataclass, field

import shodan


@dataclass
class ShodanResult:
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
        c2_indicators = [
            "cobalt", "cobaltstrike", "metasploit", "meterpreter",
            "covenant", "sliver", "brute ratel", "havoc", "decaf",
            "mythic", "empire", "poshc2", "dns", "https", "http",
        ]
        banner_text = " ".join(
            str(b) for b in self.banners
        ).lower()
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
    result = ShodanResult(ip=ip)

    if not api_key:
        result.error = "Shodan API key not configured"
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
        result.vulns = list(host.get("vulns", {}).keys()) if isinstance(host.get("vulns"), dict) else list(host.get("vulns", []))

    except shodan.APIError as e:
        result.error = f"Shodan API error: {e}"
    except Exception as e:
        result.error = f"Shodan lookup failed: {e}"

    return result
