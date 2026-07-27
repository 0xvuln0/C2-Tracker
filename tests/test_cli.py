"""Tests for CLI utilities and Config."""

from config import Config


class TestConfig:
    def test_validate_missing_shodan(self):
        c = Config(shodan_api_key="", censys_api_id="x", censys_api_secret="y")
        errors = c.validate(require_shodan=True, require_censys=False)
        assert len(errors) == 1
        assert "SHODAN" in errors[0]

    def test_validate_missing_censys(self):
        c = Config(shodan_api_key="x", censys_api_id="", censys_api_secret="")
        errors = c.validate(require_shodan=False, require_censys=True)
        assert len(errors) == 2

    def test_validate_all_present(self):
        c = Config(shodan_api_key="k", censys_api_id="i", censys_api_secret="s")
        assert c.validate() == []

    def test_validate_no_requirements(self):
        c = Config()
        assert c.validate(require_shodan=False, require_censys=False) == []


class TestValidateIp:
    def test_valid_ip(self):
        from cli import _validate_ip
        assert _validate_ip("8.8.8.8") == "8.8.8.8"

    def test_invalid_ip(self):
        from cli import _validate_ip
        assert _validate_ip("not-an-ip") is None

    def test_ipv6_rejected(self):
        from cli import _validate_ip
        assert _validate_ip("::1") is None

    def test_empty_string(self):
        from cli import _validate_ip
        assert _validate_ip("") is None
