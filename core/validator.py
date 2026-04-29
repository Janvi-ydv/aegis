"""
core/validator.py — Target validation and scope authorization for AEGIS
"""

import ipaddress
import re
import logging

from ui.console import console, print_error, scope_prompt as _scope_prompt

logger = logging.getLogger("aegis")

# RFC 1918 private ranges
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]

# Hostname regex (simple, covers most lab hostnames)
_HOSTNAME_RE = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"\.)*[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
)


def validate_target(target: str) -> bool:
    """
    Returns True if target is a valid IP address or resolvable hostname format.
    Does NOT perform DNS resolution — just validates the format.
    """
    if not target or not target.strip():
        return False

    target = target.strip()

    # If the string looks like an IP (digits and dots only), validate strictly as IP
    _IP_LIKE = re.compile(r"^\d[\d.]*$")
    if _IP_LIKE.match(target):
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False  # Looks like an IP but is invalid (e.g. 999.x.x.x or 192.168.1)

    # Try exact IP parse first (catches IPv6, etc.)
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    # Try hostname
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


def scope_authorization_prompt(target: str) -> bool:
    """
    Show scope authorization prompt and return True if user confirms.
    Always shown — no bypass in normal operation.
    Default is NO (user must explicitly type 'y').
    """
    return _scope_prompt(target)


def validate_and_authorize(target: str) -> bool:
    """
    Full validation + authorization flow.

    Returns True if target is valid AND user authorizes.
    Prints error messages and returns False on any failure.
    """
    # 1. Format validation
    if not validate_target(target):
        print_error(
            f"Invalid target: '{target}' is not a valid IP address or hostname.",
            hint="Examples: 192.168.1.100 or example.com",
        )
        return False

    # 2. Localhost warning
    if target in ("127.0.0.1", "localhost", "::1"):
        console.print(
            "\n  [bold yellow]⚠[/bold yellow]  "
            "[yellow]Scanning localhost — ensure this is intentional.[/yellow]\n"
        )

    logger.info(f"Target validated: {target}")

    # 3. Scope authorization prompt
    authorized = scope_authorization_prompt(target)
    if not authorized:
        console.print(
            "\n  [bold cyan]AEGIS[/bold cyan]  "
            "[white]Scan aborted. Always obtain explicit written authorization "
            "before scanning any target.[/white]\n"
        )
        logger.info("Scan aborted by user at authorization prompt.")
    return authorized
