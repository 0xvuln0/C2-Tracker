"""Passive C2 hunting via Shodan queries.

Queries Shodan for known C2 framework fingerprints, malware panels,
and threat infrastructure across the internet. Based on curated
search operators from public OSINT research.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import shodan
from shodan import exception as shodan_errors

from c2tracker.models import ShodanResult


# Curated Shodan queries for known C2/malware infrastructure.
# Sources:
#   - https://michaelkoczwara.medium.com/hunting-c2-with-shodan-223ca250d06f
#   - https://github.com/BushidoUK/OSINT-SearchOperators/blob/main/ShodanAdversaryInfa.md
#   - montysecurity/C2-Tracker
C2_QUERIES: dict[str, list[str]] = {
    "Cobalt Strike": [
        "ssl.cert.serial:146473198",
        "hash:-2007783223 port:50050",
        "product:'Cobalt Strike Beacon'",
        "ssl:foren.zik",
    ],
    "Metasploit": [
        "ssl:MetasploitSelfSignedCA",
        "http.favicon.hash:-127886975",
        "product:Metasploit",
    ],
    "Covenant": [
        "ssl:Covenant http.component:Blazor",
        "http.favicon.hash:-737603591",
        "product:Covenant",
    ],
    "Mythic": [
        "ssl:Mythic port:7443",
        "http.favicon.hash:-859291042",
        "product:Mythic",
    ],
    "Brute Ratel C4": [
        "http.html_hash:-1957161625",
        "product:'Brute Ratel C4'",
    ],
    "Posh C2": [
        "ssl:P18055077",
        "product:PoshC2",
        "http.html_hash:855112502",
        "http.html_hash:-1700067737",
    ],
    "Sliver": [
        "ssl:multiplayer ssl.cert.issuer.cn:operators",
        'product:\'Sliver C2\'',
    ],
    "Deimos C2": [
        "http.html_hash:-14029177",
        "product:'Deimos C2'",
    ],
    "PANDA C2": [
        "http.html:PANDA http.html:layui",
        "product:'Panda C2'",
    ],
    "NimPlant C2": [
        "http.html_hash:-1258014549",
    ],
    "Havoc": [
        "X-Havoc: true",
        "product:Havoc",
    ],
    "Caldera C2": [
        "http.favicon.hash:-636718605",
        "http.html_hash:-1702274888",
        'http.title:"Login | CALDERA"',
    ],
    "GoPhish": [
        "http.title:'Gophish - Login'",
    ],
    "Empire C2": [
        "product:'Empire C2'",
    ],
    "Villain C2": [
        "hash:856668804",
    ],
    "Pantegana C2": [
        "ssl:Pantegana ssl:localhost",
        "ssl.cert.issuer.cn:'Pantegana Root CA'",
    ],
    "Viper C2": [
        "http.html_hash:-1250764086",
    ],
    "Poseidon C2": [
        "http.favicon.hash:219045137",
        "http.html_hash:-1139460879",
        "hash:799564296",
    ],
    "Vshell C2": [
        "http.title:'Vshell - 登录'",
    ],
    "Supershell C2": [
        "http.html_hash:84573275",
        "http.favicon.hash:-1010228102",
    ],
    "RedGuard C2": [
        "http.status:307 http:'307 Temporary Redirect Content-Type: text/html; charset=utf-8 Location: https://360.net'",
    ],
    "AcidRain Stealer": [
        'http.html:"AcidRain Stealer"',
    ],
    "Misha Stealer": [
        "http.title:misha http.component:UIKit",
    ],
    "Patriot Stealer": [
        "http.favicon.hash:274603478",
        "http.html:patriotstealer",
    ],
    "RAXNET Bitcoin Stealer": [
        "http.favicon.hash:-1236243965",
    ],
    "Titan Stealer": [
        "http.html:'Titan Stealer'",
    ],
    "Collector Stealer": [
        'http.html:"Collector Stealer"',
        'http.html:getmineteam',
        'product:"Collector Stealer"',
    ],
    "Mystic Stealer": [
        "http.title:'Mystic Stealer'",
        "http.favicon.hash:-442056565",
    ],
    "Gotham Stealer": [
        "http.title:'Gotham Stealer'",
        "http.favicon.hash:-1651875345",
    ],
    "Meduza Stealer": [
        "http.html_hash:1368396833",
        "http.title:'Meduza Stealer'",
    ],
    "Bandit Stealer": [
        "http.title:Login http.html:'Welcome to Bandit' 'Content-Length: 4125' port:8080",
    ],
    "Prysmax Stealer": [
        "http.title:'Prysmax Stealer'",
    ],
    "Spectre Stealer": [
        "http.title:'Spectre Stealer - Login'",
    ],
    "XMRig Cryptominer": [
        "http.html:XMRig",
        "http.favicon.hash:-782317534",
        "http.favicon.hash:1088998712",
    ],
    "Quasar RAT": [
        "product:'Quasar RAT'",
    ],
    "AsyncRAT": [
        "product:AsyncRAT",
    ],
    "DcRAT": [
        "product:DcRat",
    ],
    "BitRAT": [
        "product:BitRAT",
    ],
    "DarkComet": [
        "product:'DarkComet Trojan'",
    ],
    "XtremeRAT": [
        "product:'XtremeRAT Trojan'",
    ],
    "NanoCore RAT": [
        "product:'NanoCore RAT Trojan'",
    ],
    "Gh0st RAT": [
        "product:'Gh0st RAT Trojan'",
    ],
    "DarkTrack RAT": [
        "product:'DarkTrack RAT Trojan'",
    ],
    "njRAT": [
        "product:'njRAT Trojan'",
    ],
    "Remcos RAT": [
        "product:'Remcos Pro RAT Trojan'",
    ],
    "Poison Ivy": [
        "product:'Poison Ivy Trojan'",
    ],
    "Orcus RAT": [
        "product:'Orcus RAT Trojan'",
    ],
    "Ares RAT": [
        "product:'Ares RAT C2'",
    ],
    "ShadowPad": [
        "product:ShadowPad",
    ],
    "7777 Botnet": [
        "hash:1357418825",
    ],
    "Scarab Botnet": [
        "http.title:'Scarab Botnet PANEL'",
    ],
    "BlackNet Botnet": [
        "http.title:'BlackNet - Login'",
    ],
    "Doxerina Botnet": [
        "http.title:'Doxerina BotNet'",
    ],
    "Mozi Botnet": [
        "http.html_hash:-1245370368",
    ],
    "Hookbot": [
        "http.title:'Hookbot Panel'",
    ],
    "Hak5 Cloud C2": [
        "product:'Hak5 Cloud C2'",
        "http.favicon.hash:1294130019",
    ],
    "RisePro Stealer": [
        "'Server: RisePro'",
    ],
    "Sectop RAT": [
        "http.headers_hash:-1731927497 port:9000,15647",
    ],
    "SpiceRAT": [
        "http.headers_hash:1955818171 http.html_hash:114440660",
    ],
    "Oyster C2": [
        "http.html_hash:-51903740",
    ],
    "SpyAgent": [
        "http.title:'SpY-Agent v1.2'",
    ],
    "BurpSuite": [
        "product:BurpSuite",
    ],
    "MobSF": [
        "http.title:'Mobile Security Framework - MobSF'",
    ],
    "NetBus": [
        "product:'NetBus Trojan'",
    ],
    "ZeroAccess": [
        "product:'ZeroAccess Trojan'",
    ],
}


@dataclass
class HuntResult:
    """Result from hunting a single product via Shodan."""
    product: str
    ips: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def hunt_shodan(
    api_key: str,
    products: list[str] | None = None,
    output_dir: str = "data",
    verbose: bool = False,
    on_progress=None,
) -> dict[str, HuntResult]:
    """Query Shodan for known C2 infrastructure across the internet.

    Args:
        api_key: Shodan API key.
        products: Specific products to hunt. None = hunt all.
        output_dir: Directory to write IP lists to.
        verbose: Print each query as it runs.
        on_progress: Callback(product, query, result_count) for progress.

    Returns:
        Dict mapping product name to HuntResult.
    """
    if not api_key:
        raise ValueError("Shodan API key is required for hunting")

    api = shodan.Shodan(api_key)
    queries = C2_QUERIES

    if products:
        queries = {k: v for k, v in C2_QUERIES.items() if k.lower() in [p.lower() for p in products]}

    os.makedirs(output_dir, exist_ok=True)

    all_ips: set[str] = set()
    results: dict[str, HuntResult] = {}

    for product, product_queries in queries.items():
        hunt = HuntResult(product=product)

        for query in product_queries:
            if verbose:
                print(f"  [query] {product}: {query}")

            try:
                for match in api.search_cursor(query):
                    ip = str(match.get("ip_str", ""))
                    if ip and ip not in hunt.ips:
                        hunt.ips.append(ip)
                        all_ips.add(ip)
            except shodan_errors.APIError as e:
                hunt.errors.append(str(e))
                continue
            except Exception as e:
                hunt.errors.append(str(e))
                continue

            if on_progress:
                on_progress(product, query, len(hunt.ips))

        # Write per-product file
        product_file = Path(output_dir) / f"{product} IPs.txt"
        with open(product_file, "w") as f:
            for ip in sorted(hunt.ips):
                f.write(f"{ip}\n")

        results[product] = hunt

    # Write combined file
    all_file = Path(output_dir) / "all.txt"
    with open(all_file, "w") as f:
        for ip in sorted(all_ips):
            f.write(f"{ip}\n")

    return results


def get_all_queries() -> dict[str, list[str]]:
    """Return the full dictionary of C2 hunting queries."""
    return dict(C2_QUERIES)


def get_products() -> list[str]:
    """Return list of all trackable product names."""
    return list(C2_QUERIES.keys())
