"""
core/dependency.py — Pre-flight dependency checker for AEGIS

Checks all required system tools and Python packages before scanning.
"""

import shutil
import importlib
import logging

from rich.table import Table
from rich.panel import Panel
from rich import box

from ui.console import console

logger = logging.getLogger("aegis")

# Required external tools: tool_name -> install command
REQUIRED_TOOLS = {
    "nmap": "sudo apt install nmap",
    "nikto": "sudo apt install nikto",
    "gobuster": "sudo apt install gobuster",
    "enum4linux": "sudo apt install enum4linux",
}

# Required Python packages: import_name -> install command
REQUIRED_PYTHON_PACKAGES = {
    "rich": "pip install rich",
    "requests": "pip install requests",
    "fpdf": "pip install fpdf2",
    "dotenv": "pip install python-dotenv",
    "nmap": "pip install python-nmap",
}


def check_system_tools() -> tuple:
    """
    Check that all required system tools are installed.

    Returns:
        (all_ok: bool, missing: list[str])
    """
    missing = []
    for tool in REQUIRED_TOOLS:
        if shutil.which(tool) is None:
            missing.append(tool)
    return len(missing) == 0, missing


def check_python_packages() -> tuple:
    """
    Check that all required Python packages are importable.

    Returns:
        (all_ok: bool, missing: list[str])
    """
    missing = []
    for pkg in REQUIRED_PYTHON_PACKAGES:
        try:
            importlib.import_module(pkg)
        except ImportError:
            missing.append(pkg)
    return len(missing) == 0, missing


def check_dependencies(verbose: bool = True) -> bool:
    """
    Run full pre-flight dependency check and print a Rich table.

    Args:
        verbose: If True, print the full table. If False, just return bool.

    Returns:
        True if all dependencies are satisfied, False otherwise.
    """
    table = Table(
        title="[ PREFLIGHT ] Dependency Check",
        box=box.ROUNDED,
        title_style="bold cyan",
        header_style="bold white",
        show_lines=True,
    )
    table.add_column("Type", width=10)
    table.add_column("Tool / Package", width=18)
    table.add_column("Status", width=12)
    table.add_column("Install Command", width=38)

    all_ok = True

    # Check system tools
    for tool, install_cmd in REQUIRED_TOOLS.items():
        found = shutil.which(tool) is not None
        status = "[bold green]✓ Found[/bold green]" if found else "[bold red]✗ Missing[/bold red]"
        hint = "" if found else install_cmd
        table.add_row("system", tool, status, hint)
        if not found:
            all_ok = False
            logger.error(f"Missing system tool: {tool}. Install: {install_cmd}")

    # Check Python packages
    for pkg, install_cmd in REQUIRED_PYTHON_PACKAGES.items():
        try:
            importlib.import_module(pkg)
            status = "[bold green]✓ Found[/bold green]"
            hint = ""
        except ImportError:
            status = "[bold red]✗ Missing[/bold red]"
            hint = install_cmd
            all_ok = False
            logger.error(f"Missing Python package: {pkg}. Install: {install_cmd}")

        table.add_row("python", pkg, status, hint)

    if verbose:
        console.print(table)

    if all_ok:
        console.print(
            Panel(
                "[bold green]✓ All dependencies satisfied. Proceeding with scan.[/bold green]",
                border_style="green",
            )
        )
    else:
        console.print(
            Panel(
                "[bold red]✗ Missing dependencies detected. "
                "Install the items listed above and re-run AEGIS.[/bold red]",
                title="[bold red][ PREFLIGHT FAILED ][/bold red]",
                border_style="red",
            )
        )

    return all_ok
