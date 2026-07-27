"""Censys Search API enrichment for IP lookups."""

from __future__ import annotations

import ipaddress

from censys.search import CensysHosts

from models import CensysResult


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
