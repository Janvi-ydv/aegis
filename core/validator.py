"""
core/validator.py — Target validation for AEGIS
"""

import ipaddress
import re
import logging

from ui.console import console, print_error

logger = logging.getLogger("aegis")

# RFC 1918 private ranges
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]

# Hostname regex
_HOSTNAME_RE = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"\.)*[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
)


def validate_target(target: str) -> bool:
    """
    Returns True if target is a valid IP address or hostname format.
    Does NOT perform DNS resolution.
    """
    if not target or not target.strip():
        return False

    target = target.strip()

    # Strings that look like IPs must be strictly valid
    _IP_LIKE = re.compile(r"^\d[\d.]*$")
    if _IP_LIKE.match(target):
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False

    # IPv6 and other strict IP forms
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    # Hostname
    if _HOSTNAME_RE.match(target):
        return True

    return False


def is_private_ip(target: str) -> bool:
    """Returns True if the target is an RFC 1918 private/loopback address."""
    try:
        addr = ipaddress.ip_address(target)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


def validate_and_authorize(target: str) -> bool:
    """
    Validates the target format and returns True if valid.
    No authorization prompt — scanning starts immediately.
    """
    if not validate_target(target):
        print_error(
            f"Invalid target: '{target}' is not a valid IP address or hostname.",
            hint="Examples: 192.168.1.100 or example.com",
        )
        return False

    if target in ("127.0.0.1", "localhost", "::1"):
        console.print(
            "\n  [bold yellow]⚠[/bold yellow]  "
            "[yellow]Scanning localhost — ensure this is intentional.[/yellow]\n"
        )

    logger.info(f"Target validated: {target}")
    return True
