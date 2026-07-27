"""Auto-update malware IP database from live threat intelligence feeds.

Pulls IOCs from:
- abuse.ch ThreatFox (https://threatfox.abuse.ch/)
- abuse.ch URLhaus (https://urlhaus.abuse.ch/)
- MalwareBazaar (https://bazaar.abuse.ch/)

Results are merged into .scanner_learn.json so they persist across runs.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

import requests


THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/"
CACHE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".online_iocs.json")
UPDATE_INTERVAL_HOURS = 24


def _load_cache() -> dict[str, Any]:
    """Load cached online IOCs."""
    if os.path.exists(CACHE_PATH):
        try:
            with open(CACHE_PATH) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    return {"last_update": None, "ips": {}, "domains": {}}


def _save_cache(data: dict[str, Any]) -> None:
    """Save online IOCs cache."""
    with open(CACHE_PATH, "w") as f:
        json.dump(data, f, indent=2)


def _needs_update() -> bool:
    """Check if the cache is stale (>24h old)."""
    cache = _load_cache()
    if not cache.get("last_update"):
        return True
    try:
        last = datetime.fromisoformat(cache["last_update"])
        age_hours = (datetime.now(timezone.utc) - last).total_seconds() / 3600
        return age_hours > UPDATE_INTERVAL_HOURS
    except (ValueError, TypeError):
        return True


def fetch_threatfox(days: int = 30, limit: int = 5000) -> list[dict[str, str]]:
    """Fetch recent IOCs from ThreatFox.

    Args:
        days: Look back this many days.
        limit: Max results per query.

    Returns:
        List of {"ip": ..., "family": ..., "port": ..., "protocol": ...} dicts.
    """
    results = []
    try:
        payload = {
            "query": "get_iocs",
            "days": days,
            "limit": limit,
        }
        resp = requests.post(THREATFOX_API, json=payload, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        if data.get("query_status") != "ok":
            return results

        for entry in data.get("data", []):
            ioc = entry.get("ioc", "")
            ioc_type = entry.get("ioc_type", "")
            if ioc_type != "ip:port":
                continue
            parts = ioc.rsplit(":", 1)
            ip = parts[0]
            port = int(parts[1]) if len(parts) > 1 else None

            malware = entry.get("malware_printable", "") or entry.get("malware", "Unknown")
            protocol = entry.get("protocol", "tcp")

            results.append({
                "ip": ip,
                "family": malware,
                "port": port,
                "protocol": protocol,
                "source": "ThreatFox",
                "first_seen": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            })
    except Exception:
        pass
    return results


def fetch_urlhaus(limit: int = 1000) -> list[dict[str, str]]:
    """Fetch recent IOCs from URLhaus (URLs with embedded IPs).

    Args:
        limit: Max results.

    Returns:
        List of {"ip": ..., "family": ..., "url": ...} dicts.
    """
    results = []
    try:
        payload = {"limit": limit}
        resp = requests.post(f"{URLHAUS_API}urls/recent/", data=payload, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        for entry in data.get("urls", []):
            ip = entry.get("host")
            if not ip:
                continue
            results.append({
                "ip": ip,
                "family": entry.get("threat", "Unknown"),
                "port": None,
                "protocol": "https" if "https" in entry.get("url", "") else "http",
                "source": "URLhaus",
                "first_seen": entry.get("date_added", "")[:10],
                "url": entry.get("url", ""),
            })
    except Exception:
        pass
    return results


def merge_iocs(online_iocs: list[dict[str, str]], existing_db_path: str | None = None) -> dict[str, Any]:
    """Merge online IOCs into the local cache.

    Args:
        online_iocs: List of IOC dicts from fetch functions.
        existing_db_path: Optional path to malware_db.py (for dedup).

    Returns:
        Updated cache dict with stats.
    """
    cache = _load_cache()

    existing_ips = set()
    if existing_db_path and os.path.exists(existing_db_path):
        try:
            with open(existing_db_path) as f:
                content = f.read()
            import re
            for m in re.finditer(r'MalwareIP\("(\d+\.\d+\.\d+\.\d+)"', content):
                existing_ips.add(m.group(1))
        except Exception:
            pass

    new_count = 0
    for ioc in online_iocs:
        ip = ioc.get("ip", "")
        if not ip:
            continue

        # Skip invalid IPs
        try:
            parts = ip.split(".")
            if len(parts) != 4 or any(int(p) > 255 for p in parts):
                continue
        except (ValueError, TypeError):
            continue

        # Skip if already in static DB
        if ip in existing_ips:
            continue

        family = ioc.get("family", "Unknown")
        if ip not in cache["ips"]:
            new_count += 1
        cache["ips"][ip] = {
            "family": family,
            "port": ioc.get("port"),
            "protocol": ioc.get("protocol", "tcp"),
            "source": ioc.get("source", "online-feed"),
            "first_seen": ioc.get("first_seen", ""),
            "last_seen": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        }

    cache["last_update"] = datetime.now(timezone.utc).isoformat()
    _save_cache(cache)

    return {
        "new_count": new_count,
        "total_online": len(cache["ips"]),
        "last_update": cache["last_update"],
    }


def update_if_stale() -> dict[str, Any]:
    """Fetch from online feeds if cache is >24h old.

    Returns:
        Stats dict with new_count, total_online, last_update.
        Returns cached stats if no update was needed.
    """
    if not _needs_update():
        cache = _load_cache()
        return {
            "new_count": 0,
            "total_online": len(cache.get("ips", {})),
            "last_update": cache.get("last_update"),
            "skipped": True,
        }

    all_iocs = []
    all_iocs.extend(fetch_threatfox())
    time.sleep(1)  # Be polite to abuse.ch
    all_iocs.extend(fetch_urlhaus())

    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "malware_db.py")
    return merge_iocs(all_iocs, existing_db_path=db_path)


def get_online_ips() -> dict[str, dict]:
    """Get all cached online IOC IPs.

    Returns:
        Dict mapping IP to its IOC info.
    """
    cache = _load_cache()
    return cache.get("ips", {})


def check_online_ip(ip: str) -> dict | None:
    """Check if an IP is in the online IOC cache.

    Returns:
        IOC dict if found, None otherwise.
    """
    cache = _load_cache()
    return cache.get("ips", {}).get(ip)
