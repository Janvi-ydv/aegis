#!/usr/bin/env python3
"""
aegis.py — AEGIS Entry Point

Adaptive Exploitation & Global Intelligence System v1.0

Usage:
    python aegis.py setup                        # Configure API key & settings
    python aegis.py setup --show                 # Show current config
    python aegis.py --target <IP> [options]      # Run a scan

For authorized testing only.
"""

import os
import sys
import logging
from dotenv import load_dotenv

# Load .env before any module reads env vars
load_dotenv()

# ── Logging setup ──────────────────────────────────────────────────────────
_debug = os.getenv("AEGIS_DEBUG", "false").lower() == "true"
logging.basicConfig(
    filename="aegis.log",
    level=logging.DEBUG if _debug else logging.WARNING,
    format="%(asctime)s | %(levelname)s | %(module)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# ── AEGIS modules ──────────────────────────────────────────────────────────
from ui.console import print_banner, print_error  # noqa: E402
from cli.parser import build_parser  # noqa: E402


def main() -> int:
    """
    Main entry point for AEGIS.

    Returns:
        Exit code (0 = success, 1 = error)
    """
    print_banner()

    parser = build_parser()
    args = parser.parse_args()

    # ── setup subcommand ───────────────────────────────────────────────────
    if args.command == "setup":
        from core.setup_wizard import run_setup, show_current_config
        if getattr(args, "show", False):
            show_current_config()
        else:
            run_setup()
        return 0

    # ── scan mode — --target is required ──────────────────────────────────
    if not args.target:
        parser.print_help()
        print()
        print_error(
            "--target is required for scanning.",
            hint="Example: python aegis.py --target 192.168.1.100\n"
                 "         python aegis.py setup  (to configure API key)",
        )
        return 1

    # Check API key is set (warn early, don't block — --no-ai works without it)
    api_key = os.getenv("OPENROUTER_API_KEY", "")
    if not api_key and not args.no_ai:
        from ui.console import print_warning
        print_warning(
            "OPENROUTER_API_KEY not set. AI analysis will be skipped.\n"
            "         Run 'python aegis.py setup' to configure your API key,\n"
            "         or use --no-ai to suppress this warning."
        )

    # ── Run orchestrator pipeline ──────────────────────────────────────────
    try:
        from core.orchestrator import Orchestrator

        orch = Orchestrator(
            target=args.target,
            profile=args.profile,
            output_format=args.output_format,
            output_path=getattr(args, "output", None),
            no_ai=args.no_ai,
            verbose=args.verbose,
        )
        report_path = orch.run()
        return 0 if report_path else 1

    except Exception as e:
        print_error(f"Fatal error: {str(e)}", hint="Run with --verbose for more details.")
        logging.getLogger("aegis").critical(f"Fatal: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
