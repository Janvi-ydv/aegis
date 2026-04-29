"""
cli/parser.py — AEGIS CLI argument parser

Supports two modes:
  aegis setup           — interactive configuration wizard
  aegis --target <IP>   — run a vulnerability scan
"""

import argparse

__version__ = "1.0.0"


def build_parser() -> argparse.ArgumentParser:
    """Build and return the AEGIS ArgumentParser."""
    parser = argparse.ArgumentParser(
        prog="aegis",
        description="AEGIS — Adaptive Exploitation & Global Intelligence System\n"
        "An AI-powered automated vulnerability assessment pipeline.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  setup              Interactive setup wizard (configure API key, settings)
  setup --show       Display current configuration

Scan Profiles:
  quick    Top 1000 ports, fast timing
  full     All 65535 ports, service/OS detection (default)
  web      HTTP/HTTPS ports only (80, 443, 8080, 8443)
  stealth  Slow timing, SYN scan, lower detection risk (requires root)

Examples:
  python aegis.py setup
  python aegis.py setup --show
  python aegis.py --target 192.168.1.100
  python aegis.py --target 192.168.1.100 --profile quick
  python aegis.py --target 10.10.10.5 --profile web --format markdown
  python aegis.py --target 192.168.1.100 --no-ai --verbose

IMPORTANT: Only use AEGIS on targets you have explicit written authorization to scan.
""",
    )

    # ── Subcommand: setup ──────────────────────────────────────────────────
    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    setup_parser = subparsers.add_parser(
        "setup",
        help="Configure AEGIS (API key, model, settings)",
        description="Interactive wizard to configure AEGIS settings and save them to .env",
    )
    setup_parser.add_argument(
        "--show",
        action="store_true",
        help="Display current configuration without editing",
    )

    # ── Scan options ───────────────────────────────────────────────────────
    parser.add_argument(
        "--target",
        default=None,
        metavar="<IP/hostname>",
        help="Target IP address or hostname to scan",
    )

    parser.add_argument(
        "--profile",
        choices=["quick", "full", "web", "stealth"],
        default="full",
        metavar="<preset>",
        help="Scan profile preset: quick|full|web|stealth (default: full)",
    )

    parser.add_argument(
        "--format",
        choices=["pdf", "json", "markdown"],
        default="pdf",
        dest="output_format",
        metavar="<type>",
        help="Output report format: pdf|json|markdown (default: pdf)",
    )

    parser.add_argument(
        "--output",
        default=None,
        metavar="<path>",
        help="Custom report output path",
    )

    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Disable AI analysis — generate raw scan report only (offline mode)",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show raw tool output during scanning",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"AEGIS {__version__}",
    )

    return parser
