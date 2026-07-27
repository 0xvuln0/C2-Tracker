"""Tests for network utility functions."""

from c2tracker.network import Connection, is_private_ip


class TestIsPrivateIp:
    def test_loopback(self):
        assert is_private_ip("127.0.0.1")

    def test_class_a(self):
        assert is_private_ip("10.0.0.1")
        assert is_private_ip("10.255.255.255")

    def test_class_b(self):
        assert is_private_ip("172.16.0.1")
        assert is_private_ip("172.31.255.255")

    def test_class_b_boundary_not_private(self):
        assert not is_private_ip("172.15.255.255")
        assert not is_private_ip("172.32.0.0")

    def test_class_c(self):
        assert is_private_ip("192.168.0.1")
        assert is_private_ip("192.168.255.255")

    def test_public_ips(self):
        assert not is_private_ip("8.8.8.8")
        assert not is_private_ip("1.1.1.1")
        assert not is_private_ip("203.0.113.1")
        assert not is_private_ip("198.51.100.1")

    def test_invalid_ip(self):
        assert not is_private_ip("not-an-ip")
        assert not is_private_ip("")
        assert not is_private_ip("999.999.999.999")


class TestConnection:
    def test_remote_ip_property(self):
        conn = Connection(
            local_addr="192.168.1.1", local_port=12345,
            remote_addr="8.8.8.8", remote_port=443,
            status="ESTABLISHED", pid=1234, process_name="curl",
        )
        assert conn.remote_ip == "8.8.8.8"

    def test_str_representation(self):
        conn = Connection(
            local_addr="192.168.1.1", local_port=12345,
            remote_addr="8.8.8.8", remote_port=443,
            status="ESTABLISHED", pid=1234, process_name="curl",
        )
        s = str(conn)
        assert "192.168.1.1:12345" in s
        assert "8.8.8.8:443" in s
        assert "curl" in s

    def test_str_unknown_process(self):
        conn = Connection(
            local_addr="10.0.0.1", local_port=80,
            remote_addr="1.2.3.4", remote_port=443,
            status="ESTABLISHED", pid=None, process_name=None,
        )
        s = str(conn)
        assert "unknown" in s
