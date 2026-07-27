"""Shodan API enrichment for IP lookups."""

from __future__ import annotations

import ipaddress

import shodan

from c2tracker.models import ShodanResult


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
