from __future__ import annotations

import socket
from dataclasses import dataclass

import psutil


@dataclass
class Connection:
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    status: str
    pid: int | None
    process_name: str | None

    @property
    def remote_ip(self) -> str:
        return self.remote_addr

    def __str__(self) -> str:
        proc = self.process_name or "unknown"
        return (
            f"{self.local_addr}:{self.local_port} -> "
            f"{self.remote_addr}:{self.remote_port} "
            f"[{self.status}] ({proc}, pid={self.pid})"
        )


def _resolve_process(pid: int) -> str | None:
    try:
        proc = psutil.Process(pid)
        return proc.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


def get_connections() -> list[Connection]:
    connections = []
    seen = set()

    for conn in psutil.net_connections(kind="inet"):
        if conn.raddr is None:
            continue

        remote_ip = conn.raddr.ip
        if remote_ip in ("127.0.0.1", "0.0.0.0", "::1"):
            continue

        key = (conn.laddr.ip, conn.laddr.port, remote_ip, conn.raddr.port)
        if key in seen:
            continue
        seen.add(key)

        connections.append(
            Connection(
                local_addr=conn.laddr.ip,
                local_port=conn.laddr.port,
                remote_addr=remote_ip,
                remote_port=conn.raddr.port,
                status=conn.status.name if hasattr(conn.status, "name") else str(conn.status),
                pid=conn.pid,
                process_name=_resolve_process(conn.pid) if conn.pid else None,
            )
        )

    return connections


def get_unique_remote_ips() -> list[str]:
    seen = set()
    ips = []
    for conn in get_connections():
        if conn.remote_ip not in seen:
            seen.add(conn.remote_ip)
            ips.append(conn.remote_ip)
    return ips


def is_private_ip(ip: str) -> bool:
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
    except socket.error:
        pass
    return False
