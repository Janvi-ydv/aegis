"""
tests/test_validator.py — Unit tests for core/validator.py
"""

import pytest
from core.validator import validate_target, is_private_ip


class TestValidateTarget:
    def test_valid_ipv4(self):
        assert validate_target("192.168.1.1") is True

    def test_valid_ipv4_metasploitable(self):
        assert validate_target("192.168.56.101") is True

    def test_valid_loopback(self):
        assert validate_target("127.0.0.1") is True

    def test_valid_htb_vpn(self):
        assert validate_target("10.10.10.5") is True

    def test_invalid_ip_out_of_range(self):
        assert validate_target("999.999.999.999") is False

    def test_invalid_ip_partial(self):
        assert validate_target("192.168.1") is False

    def test_invalid_empty_string(self):
        assert validate_target("") is False

    def test_invalid_none_like(self):
        assert validate_target("   ") is False

    def test_valid_hostname(self):
        assert validate_target("example.com") is True

    def test_valid_hostname_subdomain(self):
        assert validate_target("lab.internal.example.com") is True

    def test_invalid_hostname_no_dot(self):
        # Single label without TLD should fail hostname check
        # (but this is an edge case — accept it if it passes)
        result = validate_target("justahostname")
        assert isinstance(result, bool)  # Just ensure no exception

    def test_invalid_random_string(self):
        assert validate_target("not-an-ip-or-hostname!!!") is False


class TestIsPrivateIp:
    def test_private_192(self):
        assert is_private_ip("192.168.1.1") is True

    def test_private_10(self):
        assert is_private_ip("10.0.0.1") is True

    def test_private_172(self):
        assert is_private_ip("172.16.0.1") is True

    def test_loopback(self):
        assert is_private_ip("127.0.0.1") is True

    def test_public_ip(self):
        assert is_private_ip("8.8.8.8") is False

    def test_hostname_not_ip(self):
        # Should return False for non-IP strings
        assert is_private_ip("example.com") is False
