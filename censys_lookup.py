"""Censys Search API enrichment for IP lookups."""

from __future__ import annotations

import ipaddress

from censys.search import CensysHosts

from models import CensysResult


def lookup_ip(api_id: str, api_secret: str, ip: str, use_cache: bool = True) -> CensysResult:
    """Look up an IP address via the Censys Search API.

    Args:
        api_id: Censys API ID. If empty, returns an error result.
        api_secret: Censys API secret. If empty, returns an error result.
        ip: IPv4 address to look up.
        use_cache: Whether to use/check the local cache.

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

    # Check cache first
    if use_cache:
        try:
            from api_cache import get_censys, set_censys

            cached = get_censys(ip)
            if cached:
                result.ports = cached.get("ports", [])
                result.protocols = cached.get("protocols", [])
                result.services = cached.get("services", [])
                result.location_country = cached.get("location_country")
                result.location_city = cached.get("location_city")
                result.autonomous_system_org = cached.get("autonomous_system_org")
                result.operating_system = cached.get("operating_system")
                return result
        except ImportError:
            pass

    try:
        hosts = CensysHosts(api_id=api_id, api_secret=api_secret)
        host = hosts.get(ip)

        result.ports = [svc["port"] for svc in host.get("services", []) if "port" in svc]
        result.protocols = list(
            {svc.get("transport_protocol", "") for svc in host.get("services", []) if svc.get("transport_protocol")}
        )
        result.services = host.get("services", [])

        loc = host.get("location", {})
        result.location_country = loc.get("country")
        result.location_city = loc.get("city")

        asn = host.get("autonomous_system", {})
        result.autonomous_system_org = asn.get("name")

        os_info = host.get("operating_system", {})
        result.operating_system = os_info.get("product") or os_info.get("uniform_resource_identifier")

        # Cache the result
        if use_cache:
            try:
                from api_cache import set_censys

                set_censys(
                    ip,
                    {
                        "ports": result.ports,
                        "protocols": result.protocols,
                        "services": result.services,
                        "location_country": result.location_country,
                        "location_city": result.location_city,
                        "autonomous_system_org": result.autonomous_system_org,
                        "operating_system": result.operating_system,
                    },
                )
            except ImportError:
                pass

    except Exception as e:
        result.error = f"Censys lookup failed: {e}"

    return result
