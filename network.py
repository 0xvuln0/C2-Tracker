"""Live network connection monitoring and IP classification.

Uses psutil to enumerate active TCP/UDP connections and provides
utilities for filtering private IPs and resolving process names.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass

import psutil


@dataclass
class Connection:
    """A single network connection observed on the local machine.

    Attributes:
        local_addr: Local IP address.
        local_port: Local port number.
        remote_addr: Remote IP address.
        remote_port: Remote port number.
        status: Connection state (e.g. ESTABLISHED, TIME_WAIT).
        pid: OS process ID owning the connection, or None.
        process_name: Name of the owning process, or None.
    """

    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    status: str
    pid: int | None
    process_name: str | None

    @property
    def remote_ip(self) -> str:
        """Alias for remote_addr for clarity in filtering."""
        return self.remote_addr

    def __str__(self) -> str:
        proc = self.process_name or "unknown"
        return (
            f"{self.local_addr}:{self.local_port} -> "
            f"{self.remote_addr}:{self.remote_port} "
            f"[{self.status}] ({proc}, pid={self.pid})"
        )


def _resolve_process(pid: int) -> str | None:
    """Look up the process name for a given PID.

    Returns None if the process no longer exists or access is denied.
    """
    try:
        proc = psutil.Process(pid)
        return proc.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


def get_connections() -> list[Connection]:
    """Enumerate all active inbound/outbound network connections.

    Filters out loopback addresses and deduplicates connections.
    Requires root/sudo for full visibility on most systems.

    Returns:
        List of Connection objects for all active external connections.
    """
    connections: list[Connection] = []
    seen: set[tuple[str, int, str, int]] = set()

    for conn in psutil.net_connections(kind="inet"):
        if not conn.raddr:
            continue

        # raddr may be a named tuple (addr) or a plain tuple (ip, port)
        try:
            raddr = conn.raddr
            remote_ip = raddr[0] if isinstance(raddr, tuple) and len(raddr) >= 2 else raddr.ip
            remote_port = raddr[1] if isinstance(raddr, tuple) and len(raddr) >= 2 else raddr.port
        except (AttributeError, IndexError, TypeError):
            continue

        if remote_ip in ("127.0.0.1", "0.0.0.0", "::1"):
            continue

        try:
            laddr = conn.laddr
            local_ip = laddr[0] if isinstance(laddr, tuple) and len(laddr) >= 2 else laddr.ip
            local_port = laddr[1] if isinstance(laddr, tuple) and len(laddr) >= 2 else laddr.port
        except (AttributeError, IndexError, TypeError):
            continue

        key = (local_ip, local_port, remote_ip, remote_port)
        if key in seen:
            continue
        seen.add(key)

        connections.append(
            Connection(
                local_addr=local_ip,
                local_port=local_port,
                remote_addr=remote_ip,
                remote_port=remote_port,
                status=conn.status.name if hasattr(conn.status, "name") else str(conn.status),
                pid=conn.pid,
                process_name=_resolve_process(conn.pid) if conn.pid else None,
            )
        )

    return connections


def get_unique_remote_ips() -> list[str]:
    """Return deduplicated list of remote IPs from active connections.

    Returns:
        List of unique remote IP address strings.
    """
    seen: set[str] = set()
    ips: list[str] = []
    for conn in get_connections():
        if conn.remote_ip not in seen:
            seen.add(conn.remote_ip)
            ips.append(conn.remote_ip)
    return ips


def is_private_ip(ip: str) -> bool:
    """Check if an IP address is in a private/reserved range.

    Checks RFC 1918 (10.x, 172.16-31.x, 192.168.x) and loopback (127.x).

    Args:
        ip: IPv4 address string.

    Returns:
        True if the IP is private/reserved, False otherwise.
    """
    try:
        addr = socket.inet_aton(ip)
        first_octet = addr[0]
        if first_octet == 10:
            return True
        if first_octet == 172 and 16 <= addr[1] <= 31:
            return True
        if first_octet == 192 and addr[1] == 168:
            return True
        if first_octet == 127:
            return True
    except OSError:
        pass
    return False
