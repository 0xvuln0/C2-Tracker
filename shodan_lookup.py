"""Shodan API enrichment for IP lookups."""

from __future__ import annotations

import ipaddress

import shodan

from models import ShodanResult


def lookup_ip(api_key: str, ip: str, use_cache: bool = True) -> ShodanResult:
    """Look up an IP address via the Shodan API.

    Args:
        api_key: Shodan API key. If empty, returns an error result.
        ip: IPv4 address to look up.
        use_cache: Whether to use/check the local cache.

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

    # Check cache first
    if use_cache:
        try:
            from api_cache import get_shodan, set_shodan
            cached = get_shodan(ip)
            if cached:
                result.ports = cached.get("ports", [])
                result.hostnames = cached.get("hostnames", [])
                result.os = cached.get("os")
                result.org = cached.get("org")
                result.isp = cached.get("isp")
                result.country = cached.get("country")
                result.city = cached.get("city")
                result.banners = cached.get("banners", [])
                result.vulns = cached.get("vulns", [])
                return result
        except ImportError:
            pass

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

        # Cache the result
        if use_cache:
            try:
                from api_cache import set_shodan
                set_shodan(ip, {
                    "ports": result.ports, "hostnames": result.hostnames,
                    "os": result.os, "org": result.org, "isp": result.isp,
                    "country": result.country, "city": result.city,
                    "banners": result.banners, "vulns": result.vulns,
                })
            except ImportError:
                pass

    except shodan.APIError as e:
        result.error = f"Shodan API error: {e}"
    except Exception as e:
        result.error = f"Shodan lookup failed: {e}"

    return result
