"""Local caching for Shodan/Censys API results.

Avoids redundant API calls for IPs already looked up. Cache expires
after 7 days by default.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any


CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".cache")
SHODAN_CACHE = os.path.join(CACHE_DIR, "shodan.json")
CENSYS_CACHE = os.path.join(CACHE_DIR, "censys.json")
CACHE_TTL_DAYS = 7


def _ensure_dir() -> None:
    os.makedirs(CACHE_DIR, exist_ok=True)


def _load(path: str) -> dict[str, Any]:
    if os.path.exists(path):
        try:
            with open(path) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _save(path: str, data: dict[str, Any]) -> None:
    _ensure_dir()
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def _is_fresh(entry: dict) -> bool:
    ts = entry.get("_cached_at", 0)
    age_days = (time.time() - ts) / 86400
    return age_days < CACHE_TTL_DAYS


def get_shodan(ip: str) -> dict | None:
    """Get cached Shodan result for an IP, or None if expired/missing."""
    cache = _load(SHODAN_CACHE)
    entry = cache.get(ip)
    if entry and _is_fresh(entry):
        return entry
    return None


def set_shodan(ip: str, data: dict) -> None:
    """Cache a Shodan lookup result."""
    cache = _load(SHODAN_CACHE)
    data["_cached_at"] = time.time()
    cache[ip] = data
    _save(SHODAN_CACHE, cache)


def get_censys(ip: str) -> dict | None:
    """Get cached Censys result for an IP, or None if expired/missing."""
    cache = _load(CENSYS_CACHE)
    entry = cache.get(ip)
    if entry and _is_fresh(entry):
        return entry
    return None


def set_censys(ip: str, data: dict) -> None:
    """Cache a Censys lookup result."""
    cache = _load(CENSYS_CACHE)
    data["_cached_at"] = time.time()
    cache[ip] = data
    _save(CENSYS_CACHE, cache)


def cache_stats() -> dict[str, int]:
    """Return cache statistics."""
    shodan = _load(SHODAN_CACHE)
    censys = _load(CENSYS_CACHE)
    return {
        "shodan_entries": len(shodan),
        "censys_entries": len(censys),
    }
