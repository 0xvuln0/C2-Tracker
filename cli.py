"""CLI entry point for c2tracker.

Heavy dependencies (psutil, shodan, censys) are imported lazily inside
each command function so that commands like `check`, `family`, `actor`,
and `db` work without them installed.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import sys
import time

# Allow running as `python3 cli.py` from the project root
_project_root = os.path.dirname(os.path.abspath(__file__))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

try:
    from importlib.metadata import version as _get_version

    __version__ = _get_version("c2tracker")
except Exception:
    __version__ = "0.1.0"

console = Console()


def print_banner() -> None:
    """Print the application ASCII art banner."""
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


def print_connections(connections: list) -> None:
    """Display active connections in a Rich table."""
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


def print_threat_result(result) -> None:
    """Display a single ThreatResult in a Rich panel."""
    severity_colors = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "green",
    }
    severity_style = severity_colors.get(result.threat_label, "white")

    lines = []
    lines.append(f"[bold]IP:[/bold] {result.ip}")
    lines.append(
        f"[bold]Threat Level:[/bold] [{severity_style}]"
        f"{result.threat_label} (score: {result.score}/100)[/{severity_style}]"
    )

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
        seen: set[tuple[str, str]] = set()
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
        lines.append(
            f"  Location: {result.shodan_result.city or 'unknown'}, {result.shodan_result.country or 'unknown'}"
        )
        if result.shodan_result.vulns:
            lines.append(f"  Vulnerabilities: {len(result.shodan_result.vulns)}")

    if result.shodan_result and result.shodan_result.error:
        lines.append(f"\n[dim]Shodan: {result.shodan_result.error}[/dim]")

    if result.censys_result and result.censys_result.error:
        lines.append(f"[dim]Censys: {result.censys_result.error}[/dim]")

    content = "\n".join(lines)
    if result.threat_label in ("CRITICAL", "HIGH"):
        border = "red"
    elif result.threat_label == "MEDIUM":
        border = "yellow"
    else:
        border = "green"
    console.print(Panel(content, title=f"Threat Analysis: {result.ip}", border_style=border))


def _validate_ip(ip_str: str) -> str | None:
    """Validate that a string is a valid IPv4 address."""
    try:
        addr = ipaddress.ip_address(ip_str)
        if addr.version != 4:
            return None
        return str(addr)
    except ValueError:
        return None


def run_scan(args: argparse.Namespace) -> None:
    """Execute a network scan and analyze all external IPs."""
    from analyzer import analyze_threat
    from config import Config
    from network import get_connections, is_private_ip

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
            console.print(f"  \u2022 {e}")
        console.print("\n[dim]Set API keys in .env file or use --no-api for local-only scanning[/dim]")
        sys.exit(1)

    if not args.no_api and not args.shodan_only and not args.censys_only:
        missing = config.validate()
        if missing:
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
                    result = _analyze_single_ip(config, ip, ip_connections, args, analyze_threat)
                    if result.score > 0:
                        print_threat_result(result)

                time.sleep(args.interval)

        except KeyboardInterrupt:
            console.print("\n[yellow]Monitoring stopped.[/yellow]")
            return

    results = []
    for ip in unique_ips:
        ip_connections = [c for c in connections if c.remote_ip == ip]
        result = _analyze_single_ip(config, ip, ip_connections, args, analyze_threat)
        results.append(result)

    results.sort(key=lambda r: r.score, reverse=True)

    console.print("[bold]\u2550\u2550\u2550 Results \u2550\u2550\u2550[/bold]\n")

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


def _analyze_single_ip(config, ip, connections, args, analyze_threat):
    """Look up a single IP via configured APIs and run threat analysis."""
    s_result = None
    c_result = None

    if not args.no_api:
        from censys_lookup import lookup_ip as censys_lookup
        from shodan_lookup import lookup_ip as shodan_lookup

        if args.verbose:
            console.print(f"  [dim]Looking up {ip} via Shodan...[/dim]")
        s_result = shodan_lookup(config.shodan_api_key, ip)

        if args.verbose:
            console.print(f"  [dim]Looking up {ip} via Censys...[/dim]")
        c_result = censys_lookup(config.censys_api_id, config.censys_api_secret, ip)

    return analyze_threat(ip, s_result, c_result, connections)


def cmd_check_ip(args: argparse.Namespace) -> None:
    """Check one or more IPs against the local threat database."""
    print_banner()
    from malware_db import check_ip as db_check

    for raw_ip in args.ips:
        ip = _validate_ip(raw_ip)
        if ip is None:
            console.print(f"[red]Invalid IP address: {raw_ip}[/red]")
            continue

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
    """Search the threat database by malware family name."""
    print_banner()
    from malware_db import search_family

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
        table.add_row(
            m.ip,
            m.malware_family,
            m.threat_actor,
            m.description,
            str(m.port) if m.port else "-",
        )
    console.print(table)


def cmd_search_actor(args: argparse.Namespace) -> None:
    """Search the threat database by threat actor name."""
    print_banner()
    from malware_db import search_actor

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
        table.add_row(
            m.ip,
            m.malware_family,
            m.threat_actor,
            m.description,
            str(m.port) if m.port else "-",
        )
    console.print(table)


def cmd_list_db(args: argparse.Namespace) -> None:
    """Display a summary of the built-in threat database."""
    print_banner()
    from malware_db import (
        get_all_actors,
        get_all_families,
        get_all_ips,
        search_actor,
        search_family,
    )

    families = get_all_families()
    actors = get_all_actors()
    all_ips = get_all_ips()

    console.print("\n[bold]Threat Database Summary[/bold]")
    console.print(f"  Total unique IPs: [cyan]{len(all_ips)}[/cyan]")
    console.print(f"  Malware families: [cyan]{len(families)}[/cyan]")
    console.print(f"  Threat actors: [cyan]{len(actors)}[/cyan]")

    if args.families:
        console.print("\n[bold]Malware Families:[/bold]")
        for fam in families:
            count = len(search_family(fam))
            console.print(f"  \u2022 {fam} ({count} IPs)")

    if args.actors:
        console.print("\n[bold]Threat Actors:[/bold]")
        for act in actors:
            count = len(search_actor(act))
            console.print(f"  \u2022 {act} ({count} IPs)")


def cmd_hunt(args: argparse.Namespace) -> None:
    """Hunt for C2 infrastructure across the internet via Shodan queries."""
    print_banner()
    from config import Config
    from hunter import get_products, hunt_shodan

    config = Config.from_env(args.env_file)
    errors = config.validate(require_shodan=True, require_censys=False)
    if errors:
        console.print("[bold red]Configuration error:[/bold red]")
        for e in errors:
            console.print(f"  \u2022 {e}")
        console.print("\n[dim]Shodan API key is required for hunting. Set SHODAN_API_KEY in .env[/dim]")
        sys.exit(1)

    products = args.products if args.products else None
    output_dir = args.output or "data"

    console.print("\n[bold]Hunting C2 infrastructure via Shodan...[/bold]")
    if products:
        console.print(f"  Products: {', '.join(products)}")
    else:
        console.print(f"  Products: all ({len(get_products())} tracked families)")
    console.print(f"  Output: {output_dir}/\n")

    def on_progress(product, query, count):
        console.print(f"  [dim]{product}[/dim] - {count} IP(s) found")

    try:
        results = hunt_shodan(
            api_key=config.shodan_api_key,
            products=products,
            output_dir=output_dir,
            verbose=args.verbose,
            on_progress=on_progress,
        )
    except Exception as e:
        console.print(f"\n[bold red]Hunt failed: {e}[/bold red]")
        sys.exit(1)

    # Summary table
    console.print()
    table = Table(title="Hunt Results", show_lines=True)
    table.add_column("Product", style="cyan")
    table.add_column("IPs Found", style="green", justify="right")
    table.add_column("Errors", style="red", justify="right")

    total_ips = 0
    for product, result in sorted(results.items()):
        ip_count = len(result.ips)
        err_count = len(result.errors)
        total_ips += ip_count
        table.add_row(product, str(ip_count), str(err_count) if err_count else "-")

    console.print(table)
    console.print(f"\n[bold green]{total_ips} unique IP(s) written to {output_dir}/[/bold green]")


def cmd_scan_file(args: argparse.Namespace) -> None:
    """Scan files for malware signatures and suspicious behavior."""
    output_format = getattr(args, "format", None)
    if not output_format:
        print_banner()
    from concurrent.futures import ThreadPoolExecutor, as_completed

    from file_scanner import scan_file

    files = args.files
    if not files:
        console.print("[red]No files specified.[/red]")
        return

    # Expand directories
    expanded = []
    for f in files:
        if os.path.isdir(f):
            for root, _, filenames in os.walk(f):
                for fn in filenames:
                    expanded.append(os.path.join(root, fn))
        elif os.path.exists(f):
            expanded.append(f)
        else:
            console.print(f"[red]File not found: {f}[/red]")
    files = expanded

    if not files:
        console.print("[red]No valid files to scan.[/red]")
        return

    output_format = getattr(args, "format", None)
    max_workers = getattr(args, "jobs", 1) or 1

    # For machine-readable output, send progress to stderr
    import sys as _sys

    progress_console = Console(file=_sys.stderr) if output_format else console

    def _scan_one(fp):
        return scan_file(fp)

    all_results = []
    if max_workers > 1 and len(files) > 1:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(_scan_one, fp): fp for fp in files}
            for future in as_completed(futures):
                try:
                    result = future.result()
                    all_results.append(result)
                except Exception as e:
                    progress_console.print(f"[red]Error scanning {futures[future]}: {e}[/red]")
    else:
        for file_path in files:
            progress_console.print(f"Scanning: {file_path}")
            result = scan_file(file_path)
            all_results.append(result)
            if not output_format:
                _print_file_scan_result(result, verbose=args.verbose)

    # Output in requested format
    if output_format:
        _output_results(all_results, output_format)
    elif len(all_results) > 1:
        malicious = sum(1 for r in all_results if r.risk_label in ("MALICIOUS", "SUSPICIOUS"))
        console.print(
            f"\n[bold]Scan complete: {len(all_results)} file(s) scanned, {malicious} suspicious/malicious[/bold]"
        )


def _output_results(results, fmt: str) -> None:
    """Output results in the specified format."""
    import csv
    import io
    import json as _json

    if fmt == "json":
        data = []
        for r in results:
            data.append(
                {
                    "path": r.path,
                    "file_size": r.file_size,
                    "md5": r.md5,
                    "sha256": r.sha256,
                    "file_type": r.file_type,
                    "entropy": r.entropy,
                    "risk_score": r.risk_score,
                    "risk_label": r.risk_label,
                    "detected_families": r.detected_families,
                    "embedded_ips": r.embedded_ips,
                    "embedded_domains": r.embedded_domains,
                    "suspicious_behaviors": r.suspicious_strings,
                    "indicators": r.indicators,
                }
            )
        print(_json.dumps(data, indent=2))

    elif fmt == "csv":
        buf = io.StringIO()
        writer = csv.DictWriter(
            buf,
            fieldnames=[
                "path",
                "file_size",
                "md5",
                "sha256",
                "file_type",
                "entropy",
                "risk_score",
                "risk_label",
                "detected_families",
                "suspicious_behaviors",
            ],
        )
        writer.writeheader()
        for r in results:
            writer.writerow(
                {
                    "path": r.path,
                    "file_size": r.file_size,
                    "md5": r.md5,
                    "sha256": r.sha256,
                    "file_type": r.file_type,
                    "entropy": r.entropy,
                    "risk_score": r.risk_score,
                    "risk_label": r.risk_label,
                    "detected_families": "|".join(r.detected_families),
                    "suspicious_behaviors": "|".join(r.suspicious_strings),
                }
            )
        print(buf.getvalue())

    elif fmt == "ioc":
        iocs = set()
        for r in results:
            if r.sha256:
                iocs.add(f"sha256:{r.sha256}")
            if r.md5:
                iocs.add(f"md5:{r.md5}")
            for ip in r.embedded_ips:
                iocs.add(f"ip:{ip}")
            for domain in r.embedded_domains:
                iocs.add(f"domain:{domain}")
        for ioc in sorted(iocs):
            print(ioc)

    elif fmt == "summary":
        table = Table(title="Scan Summary", show_lines=True)
        table.add_column("File", style="cyan", max_width=40)
        table.add_column("Risk", justify="center")
        table.add_column("Score", justify="right")
        table.add_column("Families", max_width=30)
        table.add_column("Behaviors", justify="right")
        for r in results:
            label_colors = {"MALICIOUS": "bold red", "SUSPICIOUS": "yellow", "LOW RISK": "dim yellow", "CLEAN": "green"}
            risk_text = Text(r.risk_label, style=label_colors.get(r.risk_label, "white"))
            table.add_row(
                os.path.basename(r.path),
                risk_text,
                str(r.risk_score),
                ", ".join(r.detected_families[:2]) or "-",
                str(len(r.suspicious_strings)),
            )
        console.print(table)


def cmd_update(args: argparse.Namespace) -> None:
    """Update the malware IOC database from online feeds."""
    print_banner()
    from db_updater import (
        _needs_update,
        fetch_threatfox,
        fetch_urlhaus,
        merge_iocs,
    )

    force = getattr(args, "force", False)

    if force or _needs_update():
        console.print("[bold]Updating IOC database from online feeds...[/bold]")
        with console.status("[cyan]Fetching ThreatFox IOCs...[/cyan]"):
            tf = fetch_threatfox()
        console.print(f"  ThreatFox: {len(tf)} IOCs fetched")
        time.sleep(1)
        with console.status("[cyan]Fetching URLhaus IOCs...[/cyan]"):
            uh = fetch_urlhaus()
        console.print(f"  URLhaus: {len(uh)} IOCs fetched")
        db_path = os.path.join(_project_root, "malware_db.py")
        stats = merge_iocs(tf + uh, existing_db_path=db_path)
        console.print("\n[bold green]Update complete![/bold green]")
        console.print(f"  New IOCs added: {stats['new_count']}")
        console.print(f"  Total online IOCs: {stats['total_online']}")
        console.print(f"  Last updated: {stats['last_update']}")
    else:
        from db_updater import _load_cache

        cache = _load_cache()
        console.print(f"[yellow]Database is up to date (last update: {cache.get('last_update', 'never')})[/yellow]")
        console.print(f"  Online IOCs cached: {len(cache.get('ips', {}))}")
        console.print("  Use --force to update now")


def cmd_watch(args: argparse.Namespace) -> None:
    """Watch a directory and scan new/modified files automatically."""
    print_banner()
    from file_scanner import scan_file

    watch_dir = args.directory
    interval = args.interval
    verbose = args.verbose

    if not os.path.isdir(watch_dir):
        console.print(f"[red]Not a directory: {watch_dir}[/red]")
        return

    console.print(f"[bold]Watching: {watch_dir}[/bold]")
    console.print(f"  Interval: {interval}s | Press Ctrl+C to stop\n")

    seen_files: dict[str, float] = {}
    # Record initial state
    for root, _, filenames in os.walk(watch_dir):
        for fn in filenames:
            fp = os.path.join(root, fn)
            try:
                seen_files[fp] = os.path.getmtime(fp)
            except OSError:
                pass

    console.print(f"  Tracking {len(seen_files)} existing file(s). Waiting for changes...\n")

    try:
        while True:
            time.sleep(interval)
            current_files: dict[str, float] = {}
            for root, _, filenames in os.walk(watch_dir):
                for fn in filenames:
                    fp = os.path.join(root, fn)
                    try:
                        current_files[fp] = os.path.getmtime(fp)
                    except OSError:
                        pass

            # Find new or modified files
            for fp, mtime in current_files.items():
                if fp not in seen_files or mtime > seen_files[fp]:
                    if fp.endswith(".json") or fp.endswith(".log"):
                        continue
                    console.print(f"\n[bold cyan]New/modified: {fp}[/bold cyan]")
                    try:
                        result = scan_file(fp)
                        _print_file_scan_result(result, verbose=verbose)
                    except Exception as e:
                        console.print(f"  [red]Scan error: {e}[/red]")

            seen_files = current_files
    except KeyboardInterrupt:
        console.print("\n[yellow]Watch stopped.[/yellow]")


def cmd_learning(args: argparse.Namespace) -> None:
    """Show learning database statistics."""
    print_banner()
    from file_scanner import LearningDB

    ldb = LearningDB()
    stats = ldb.get_stats()

    console.print("\n[bold]Learning Database Statistics[/bold]\n")
    table = Table(show_header=False)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Total scans", str(stats["total_scans"]))
    table.add_row("Malicious scans", str(stats["malicious_scans"]))
    table.add_row("Known families", str(stats["known_families"]))
    table.add_row("Learned byte patterns", str(stats["learned_patterns"]))
    table.add_row("Known malicious IPs", str(stats["known_ips"]))
    table.add_row("Known malicious domains", str(stats["known_domains"]))
    table.add_row("Known file hashes", str(stats["known_hashes"]))
    console.print(table)

    if args.reset:
        if os.path.exists(ldb.path):
            os.remove(ldb.path)
            console.print("\n[green]Learning database reset successfully.[/green]")
        else:
            console.print("\n[yellow]No learning database found.[/yellow]")


def _print_file_scan_result(result, verbose: bool = False) -> None:
    """Display a single FileScanResult."""
    label_colors = {
        "MALICIOUS": "bold red",
        "SUSPICIOUS": "yellow",
        "LOW RISK": "dim yellow",
        "CLEAN": "green",
    }
    label_style = label_colors.get(result.risk_label, "white")

    lines = []
    lines.append(f"[bold]File:[/bold] {result.path}")
    lines.append(f"[bold]Type:[/bold] {result.file_type}")
    lines.append(f"[bold]Size:[/bold] {result.file_size:,} bytes")
    lines.append(f"[bold]Entropy:[/bold] {result.entropy}")
    lines.append(f"[bold]MD5:[/bold] {result.md5}")
    lines.append(f"[bold]SHA256:[/bold] {result.sha256}")
    lines.append(
        f"[bold]Risk:[/bold] [{label_style}]{result.risk_label} (score: {result.risk_score}/100)[/{label_style}]"
    )

    if result.pe_info:
        pe = result.pe_info
        pe_parts = []
        if "format" in pe:
            pe_parts.append(pe["format"])
        if "machine" in pe:
            pe_parts.append(pe["machine"])
        if "sections" in pe:
            pe_parts.append(f"{pe['sections']} sections")
        if pe_parts:
            lines.append(f"[bold]PE Info:[/bold] {', '.join(pe_parts)}")
        if "timestamp" in pe:
            lines.append(f"[bold]PE Timestamp:[/bold] {pe['timestamp']}")

    if result.indicators:
        lines.append("")
        lines.append("[bold]Indicators:[/bold]")
        for ind in result.indicators:
            lines.append(f"  \u2022 {ind}")

    if result.detected_families:
        lines.append("")
        lines.append("[bold red]Detected Malware Families:[/bold red]")
        for fam in result.detected_families:
            reasons = result.family_reasons.get(fam, [])
            if reasons:
                reason_str = "; ".join(reasons[:2])
                lines.append(f"  \u2022 [red]{fam}[/red] [dim]({reason_str})[/dim]")
            else:
                lines.append(f"  \u2022 [red]{fam}[/red]")

    if result.similar_known_malware:
        lines.append("")
        lines.append("[bold yellow]Similar To (learned):[/bold yellow]")
        for fam in result.similar_known_malware:
            lines.append(f"  \u2022 [yellow]{fam}[/yellow]")

    if result.suspicious_strings:
        lines.append("")
        lines.append("[bold yellow]Suspicious Behaviors:[/bold yellow]")
        for s in result.suspicious_strings:
            lines.append(f"  \u2022 [yellow]{s}[/yellow]")

    if verbose:
        if result.embedded_ips:
            lines.append("")
            lines.append("[bold]Embedded IPs:[/bold]")
            for ip in result.embedded_ips[:20]:
                lines.append(f"  \u2022 {ip}")
            if len(result.embedded_ips) > 20:
                lines.append(f"  ... and {len(result.embedded_ips) - 20} more")

        if result.embedded_domains:
            lines.append("")
            lines.append("[bold]Embedded Domains:[/bold]")
            for domain in result.embedded_domains[:20]:
                lines.append(f"  \u2022 {domain}")
            if len(result.embedded_domains) > 20:
                lines.append(f"  ... and {len(result.embedded_domains) - 20} more")

        if result.detected_signatures:
            lines.append("")
            lines.append("[bold]Signature Matches:[/bold]")
            for sig in result.detected_signatures:
                lines.append(f"  \u2022 {sig}")

    if result.errors:
        lines.append("")
        for err in result.errors:
            lines.append(f"[dim]Error: {err}[/dim]")

    content = "\n".join(lines)
    if result.risk_label == "MALICIOUS":
        border = "red"
    elif result.risk_label == "SUSPICIOUS":
        border = "yellow"
    else:
        border = "green"

    console.print(Panel(content, title=f"File Scan: {os.path.basename(result.path)}", border_style=border))


def main() -> None:
    """CLI entry point for c2tracker."""
    parser = argparse.ArgumentParser(
        prog="c2tracker",
        description="C2 Server Tracker - Monitor connections and identify C2 infrastructure",
    )
    parser.add_argument("--version", action="version", version=f"c2tracker {__version__}")
    parser.add_argument("--env-file", default=".env", help="Path to .env file with API keys")

    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan active network connections")
    scan_parser.add_argument("-m", "--monitor", action="store_true", help="Continuous monitoring mode")
    scan_parser.add_argument(
        "-i",
        "--interval",
        type=int,
        default=30,
        help="Monitoring interval in seconds (default: 30)",
    )
    scan_parser.add_argument("-f", "--filter-private", action="store_true", help="Exclude private/internal IPs")
    scan_parser.add_argument("-s", "--show-connections", action="store_true", help="Show all active connections")
    scan_parser.add_argument(
        "-a", "--show-all", action="store_true", help="Show results for all IPs (including LOW threat)"
    )
    scan_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    scan_parser.add_argument("--no-api", action="store_true", help="Skip API lookups (local analysis only)")
    scan_parser.add_argument("--shodan-only", action="store_true", help="Only use Shodan for lookups")
    scan_parser.add_argument("--censys-only", action="store_true", help="Only use Censys for lookups")

    check_parser = subparsers.add_parser("check", help="Check IPs against the threat database")
    check_parser.add_argument("ips", nargs="+", help="IPv4 addresses to check")

    family_parser = subparsers.add_parser("family", help="Search threat database by malware family")
    family_parser.add_argument("family", help="Malware family name to search")

    actor_parser = subparsers.add_parser("actor", help="Search threat database by threat actor")
    actor_parser.add_argument("actor", help="Threat actor name to search")

    db_parser = subparsers.add_parser("db", help="Show threat database summary")
    db_parser.add_argument("--families", action="store_true", help="List all malware families")
    db_parser.add_argument("--actors", action="store_true", help="List all threat actors")

    hunt_parser = subparsers.add_parser("hunt", help="Hunt C2 infrastructure via Shodan queries")
    hunt_parser.add_argument("products", nargs="*", help="Specific products to hunt (default: all)")
    hunt_parser.add_argument("-o", "--output", default="data", help="Output directory for IP lists")
    hunt_parser.add_argument("-v", "--verbose", action="store_true", help="Show each query as it runs")

    scanfile_parser = subparsers.add_parser("scan-file", help="Scan files for malware signatures")
    scanfile_parser.add_argument("files", nargs="+", help="File paths or directories to scan")
    scanfile_parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show embedded IPs, domains, and signatures"
    )
    scanfile_parser.add_argument(
        "-f",
        "--format",
        choices=["json", "csv", "ioc", "summary"],
        help="Output format (default: rich table)",
    )
    scanfile_parser.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=1,
        help="Number of parallel scan workers (default: 1)",
    )

    learn_parser = subparsers.add_parser("learning", help="Show learning database stats")
    learn_parser.add_argument("--reset", action="store_true", help="Reset learning database")

    update_parser = subparsers.add_parser("update", help="Update IOC database from online feeds")
    update_parser.add_argument("--force", action="store_true", help="Force update even if recent")

    watch_parser = subparsers.add_parser("watch", help="Watch directory and scan new/modified files")
    watch_parser.add_argument("directory", help="Directory to watch")
    watch_parser.add_argument("-i", "--interval", type=int, default=10, help="Poll interval in seconds (default: 10)")
    watch_parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed results")

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
    elif args.command == "hunt":
        cmd_hunt(args)
    elif args.command == "scan-file":
        cmd_scan_file(args)
    elif args.command == "learning":
        cmd_learning(args)
    elif args.command == "update":
        cmd_update(args)
    elif args.command == "watch":
        cmd_watch(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
