from __future__ import annotations

import argparse
import sys
import time
from typing import TextIO

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from c2tracker import __version__
from c2tracker.analyzer import ThreatResult, analyze_threat
from c2tracker.censys_lookup import lookup_ip as censys_lookup
from c2tracker.config import Config
from c2tracker.malware_db import (
    get_all_actors,
    get_all_families,
    get_all_ips,
    search_actor,
    search_family,
)
from c2tracker.network import Connection, get_connections, get_unique_remote_ips, is_private_ip
from c2tracker.shodan_lookup import lookup_ip as shodan_lookup

console = Console()


def print_banner() -> None:
    banner = Text()
    banner.append("  ___   _______  _____  _____  _____  __   __  ______  \n", style="bold cyan")
    banner.append(" / _ \\ |  _____||  _  ||  _  ||  _  ||  \\ |  ||  ____| \n", style="bold cyan")
    banner.append("/ /_\\ \\| |____  | |_| || |_| || |_| ||   \\| || |____  \n", style="bold cyan")
    banner.append("|  _  ||  ____| |  _  ||  _  ||  _  || |\\   ||____  | \n", style="bold cyan")
    banner.append("| | | || |____  | | | || | | || | | || | \\  | ____| | \n", style="bold cyan")
    banner.append("\\_| |_/|______/ \\_| |_/|_| |_|\\_/ |_|/  \\_\\/______| \n", style="bold cyan")
    banner.append(f"\n  v{__version__} - C2 Server Tracker\n", style="bold white")
    banner.append("  Monitor connections | Identify C2 servers | OSINT enrichment\n", style="dim")
    console.print(Panel(banner, border_style="cyan"))


def print_connections(connections: list[Connection]) -> None:
    table = Table(title="Active Connections", show_lines=True)
    table.add_column("Local", style="green")
    table.add_column("Remote", style="red")
    table.add_column("Status", style="yellow")
    table.add_column("Process", style="blue")
    table.add_column("PID", style="dim")

    for conn in connections:
        proc = conn.process_name or "unknown"
        table.add_row(
            f"{conn.local_addr}:{conn.local_port}",
            f"{conn.remote_addr}:{conn.remote_port}",
            conn.status,
            proc,
            str(conn.pid) if conn.pid else "-",
        )

    console.print(table)


def print_threat_result(result: ThreatResult) -> None:
    severity_colors = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "green",
    }
    severity_style = severity_colors.get(result.threat_label, "white")

    lines = []
    lines.append(f"[bold]IP:[/bold] {result.ip}")
    lines.append(f"[bold]Threat Level:[/bold] [{severity_style}]{result.threat_label} (score: {result.score}/100)[/{severity_style}]")

    if result.detected_frameworks:
        lines.append(f"[bold]C2 Frameworks:[/bold] {', '.join(result.detected_frameworks)}")

    if result.associated_ports:
        port_strs = [str(p) for p in result.associated_ports[:10]]
        lines.append(f"[bold]Open Ports:[/bold] {', '.join(port_strs)}")

    if result.indicators:
        lines.append("")
        lines.append("[bold]Indicators:[/bold]")
        for ind in result.indicators:
            lines.append(f"  \u2022 {ind}")

    if result.malware_db_matches:
        lines.append("")
        lines.append("[bold red]Malware Database Matches:[/bold red]")
        seen = set()
        for m in result.malware_db_matches:
            key = (m.ip, m.malware_family)
            if key in seen:
                continue
            seen.add(key)
            actor_str = f" (Actor: {m.threat_actor})" if m.threat_actor != "Various" else ""
            port_str = f" Port: {m.port}" if m.port else ""
            lines.append(f"  \u2022 [red]{m.malware_family}[/red]{actor_str} - {m.description}{port_str}")

    if result.shodan_result and not result.shodan_result.error:
        lines.append("")
        lines.append("[bold cyan]Shodan Data:[/bold cyan]")
        lines.append(f"  OS: {result.shodan_result.os or 'unknown'}")
        lines.append(f"  Org: {result.shodan_result.org or 'unknown'}")
        lines.append(f"  ISP: {result.shodan_result.isp or 'unknown'}")
        lines.append(f"  Location: {result.shodan_result.city or 'unknown'}, {result.shodan_result.country or 'unknown'}")
        if result.shodan_result.vulns:
            lines.append(f"  Vulnerabilities: {len(result.shodan_result.vulns)}")

    if result.shodan_result and result.shodan_result.error:
        lines.append(f"\n[dim]Shodan: {result.shodan_result.error}[/dim]")

    if result.censys_result and result.censys_result.error:
        lines.append(f"[dim]Censys: {result.censys_result.error}[/dim]")

    content = "\n".join(lines)
    border = "red" if result.threat_label in ("CRITICAL", "HIGH") else "yellow" if result.threat_label == "MEDIUM" else "green"
    console.print(Panel(content, title=f"Threat Analysis: {result.ip}", border_style=border))


def run_scan(args: argparse.Namespace) -> None:
    config = Config.from_env(args.env_file)

    if args.shodan_only:
        errors = config.validate(require_shodan=True, require_censys=False)
    elif args.censys_only:
        errors = config.validate(require_shodan=False, require_censys=True)
    elif args.no_api:
        errors = []
    else:
        errors = config.validate()

    if errors and not args.no_api:
        console.print("[bold red]Configuration errors:[/bold red]")
        for e in errors:
            console.print(f"  • {e}")
        console.print("\n[dim]Set API keys in .env file or use --no-api for local-only scanning[/dim]")
        if not args.no_api:
            sys.exit(1)

    if not args.no_api and not args.shodan_only and not args.censys_only:
        errors = config.validate()
        if errors:
            console.print("[yellow]Running in limited mode (no API keys configured)[/yellow]")

    console.print("\n[bold]Scanning network connections...[/bold]")
    connections = get_connections()
    console.print(f"Found [cyan]{len(connections)}[/cyan] active connections")

    if args.filter_private:
        connections = [c for c in connections if not is_private_ip(c.remote_ip)]
        console.print(f"After filtering private IPs: [cyan]{len(connections)}[/cyan] connections")

    unique_ips = list({c.remote_ip for c in connections})
    console.print(f"[cyan]{len(unique_ips)}[/cyan] unique remote IPs\n")

    if args.show_connections:
        print_connections(connections)
        console.print()

    if args.monitor:
        console.print("[bold yellow]Monitoring mode - press Ctrl+C to stop[/bold yellow]\n")
        try:
            while True:
                connections = get_connections()
                if args.filter_private:
                    connections = [c for c in connections if not is_private_ip(c.remote_ip)]
                unique_ips = list({c.remote_ip for c in connections})

                if not unique_ips:
                    console.print("[dim]No external connections found...[/dim]")
                    time.sleep(args.interval)
                    continue

                for ip in unique_ips:
                    ip_connections = [c for c in connections if c.remote_ip == ip]
                    result = analyze_single_ip(config, ip, ip_connections, args)
                    if result.score > 0:
                        print_threat_result(result)

                time.sleep(args.interval)

        except KeyboardInterrupt:
            console.print("\n[yellow]Monitoring stopped.[/yellow]")
            return

    results = []
    for ip in unique_ips:
        ip_connections = [c for c in connections if c.remote_ip == ip]
        result = analyze_single_ip(config, ip, ip_connections, args)
        results.append(result)

    results.sort(key=lambda r: r.score, reverse=True)

    console.print("[bold]═══ Results ═══[/bold]\n")

    threats_found = 0
    for result in results:
        if result.threat_label != "LOW" or args.show_all:
            print_threat_result(result)
            if result.score > 0:
                threats_found += 1
            console.print()

    if threats_found == 0:
        console.print("[green]No suspicious C2 activity detected among scanned IPs.[/green]")
    else:
        console.print(f"\n[bold yellow]{threats_found} suspicious IP(s) identified.[/bold yellow]")


def analyze_single_ip(
    config: Config,
    ip: str,
    connections: list[Connection],
    args: argparse.Namespace,
) -> ThreatResult:
    if not args.no_api:
        if args.verbose:
            console.print(f"  [dim]Looking up {ip} via Shodan...[/dim]")
        s_result = shodan_lookup(config.shodan_api_key, ip)

        if args.verbose:
            console.print(f"  [dim]Looking up {ip} via Censys...[/dim]")
        c_result = censys_lookup(config.censys_api_id, config.censys_api_secret, ip)
    else:
        s_result = None
        c_result = None

    return analyze_threat(ip, s_result, c_result, connections)


def cmd_check_ip(args: argparse.Namespace) -> None:
    print_banner()
    from c2tracker.malware_db import check_ip as db_check

    for ip in args.ips:
        matches = db_check(ip)
        if matches:
            console.print(f"\n[bold red]KNOWN MALICIOUS: {ip}[/bold red]")
            table = Table(title=f"Matches for {ip}", show_lines=True)
            table.add_column("Malware Family", style="red")
            table.add_column("Threat Actor", style="yellow")
            table.add_column("Description")
            table.add_column("Port", style="cyan")
            table.add_column("First Seen", style="dim")
            for m in matches:
                table.add_row(
                    m.malware_family,
                    m.threat_actor,
                    m.description,
                    str(m.port) if m.port else "-",
                    m.first_seen or "-",
                )
            console.print(table)
        else:
            console.print(f"[green]{ip} - not found in threat database[/green]")


def cmd_search_family(args: argparse.Namespace) -> None:
    print_banner()
    results = search_family(args.family)
    if not results:
        console.print(f"[yellow]No results for family: {args.family}[/yellow]")
        return

    console.print(f"\n[bold]Found {len(results)} record(s) for family: {args.family}[/bold]\n")
    table = Table(show_lines=True)
    table.add_column("IP", style="red")
    table.add_column("Malware Family", style="yellow")
    table.add_column("Threat Actor")
    table.add_column("Description")
    table.add_column("Port", style="cyan")
    for m in results:
        table.add_row(m.ip, m.malware_family, m.threat_actor, m.description, str(m.port) if m.port else "-")
    console.print(table)


def cmd_search_actor(args: argparse.Namespace) -> None:
    print_banner()
    results = search_actor(args.actor)
    if not results:
        console.print(f"[yellow]No results for actor: {args.actor}[/yellow]")
        return

    console.print(f"\n[bold]Found {len(results)} record(s) for actor: {args.actor}[/bold]\n")
    table = Table(show_lines=True)
    table.add_column("IP", style="red")
    table.add_column("Malware Family", style="yellow")
    table.add_column("Threat Actor")
    table.add_column("Description")
    table.add_column("Port", style="cyan")
    for m in results:
        table.add_row(m.ip, m.malware_family, m.threat_actor, m.description, str(m.port) if m.port else "-")
    console.print(table)


def cmd_list_db(args: argparse.Namespace) -> None:
    print_banner()
    families = get_all_families()
    actors = get_all_actors()
    all_ips = get_all_ips()

    console.print(f"\n[bold]Threat Database Summary[/bold]")
    console.print(f"  Total unique IPs: [cyan]{len(all_ips)}[/cyan]")
    console.print(f"  Malware families: [cyan]{len(families)}[/cyan]")
    console.print(f"  Threat actors: [cyan]{len(actors)}[/cyan]")

    if args.families:
        console.print("\n[bold]Malware Families:[/bold]")
        for f in families:
            count = len(search_family(f))
            console.print(f"  \u2022 {f} ({count} IPs)")

    if args.actors:
        console.print("\n[bold]Threat Actors:[/bold]")
        for a in actors:
            count = len(search_actor(a))
            console.print(f"  \u2022 {a} ({count} IPs)")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="c2tracker",
        description="C2 Server Tracker - Monitor connections and identify C2 infrastructure",
    )
    parser.add_argument("--version", action="version", version=f"c2tracker {__version__}")
    parser.add_argument("--env-file", default=".env", help="Path to .env file with API keys")

    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan active network connections")
    scan_parser.add_argument("-m", "--monitor", action="store_true", help="Continuous monitoring mode")
    scan_parser.add_argument("-i", "--interval", type=int, default=30, help="Monitoring interval in seconds (default: 30)")
    scan_parser.add_argument("-f", "--filter-private", action="store_true", help="Exclude private/internal IPs")
    scan_parser.add_argument("-s", "--show-connections", action="store_true", help="Show all active connections")
    scan_parser.add_argument("-a", "--show-all", action="store_true", help="Show results for all IPs (including LOW threat)")
    scan_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    scan_parser.add_argument("--no-api", action="store_true", help="Skip API lookups (local analysis only)")
    scan_parser.add_argument("--shodan-only", action="store_true", help="Only use Shodan for lookups")
    scan_parser.add_argument("--censys-only", action="store_true", help="Only use Censys for lookups")

    check_parser = subparsers.add_parser("check", help="Check IPs against the threat database")
    check_parser.add_argument("ips", nargs="+", help="IP addresses to check")

    family_parser = subparsers.add_parser("family", help="Search threat database by malware family")
    family_parser.add_argument("family", help="Malware family name to search")

    actor_parser = subparsers.add_parser("actor", help="Search threat database by threat actor")
    actor_parser.add_argument("actor", help="Threat actor name to search")

    db_parser = subparsers.add_parser("db", help="Show threat database summary")
    db_parser.add_argument("--families", action="store_true", help="List all malware families")
    db_parser.add_argument("--actors", action="store_true", help="List all threat actors")

    legacy_parser = argparse.ArgumentParser(add_help=False)
    legacy_parser.add_argument("-m", "--monitor", action="store_true")
    legacy_parser.add_argument("-i", "--interval", type=int, default=30)
    legacy_parser.add_argument("-f", "--filter-private", action="store_true")
    legacy_parser.add_argument("-s", "--show-connections", action="store_true")
    legacy_parser.add_argument("-a", "--show-all", action="store_true")
    legacy_parser.add_argument("-v", "--verbose", action="store_true")
    legacy_parser.add_argument("--no-api", action="store_true")
    legacy_parser.add_argument("--shodan-only", action="store_true")
    legacy_parser.add_argument("--censys-only", action="store_true")

    args = parser.parse_args()

    if args.command == "scan":
        print_banner()
        run_scan(args)
    elif args.command == "check":
        cmd_check_ip(args)
    elif args.command == "family":
        cmd_search_family(args)
    elif args.command == "actor":
        cmd_search_actor(args)
    elif args.command == "db":
        cmd_list_db(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
