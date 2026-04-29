"""
ui/console.py — AEGIS CLI UI Public API

All terminal output flows through this module using the Rich library.
Modules must NOT import Rich directly — use functions from this module.
"""

import os
import logging
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text
from rich import box

__version__ = "1.0.0"

import os
import sys

# On Windows, set UTF-8 mode via environment (doesn't break pytest capturing)
if sys.platform == "win32":
    os.environ.setdefault("PYTHONUTF8", "1")

console = Console()
logger = logging.getLogger("aegis")

# ─────────────────────────────────────────────
# Status Icons
# ─────────────────────────────────────────────

ICONS = {
    "success": "[bold green]✓[/bold green]",
    "error": "[bold red]✗[/bold red]",
    "warning": "[bold yellow]⚠[/bold yellow]",
    "info": "[bold blue]ℹ[/bold blue]",
    "running": "[cyan]►[/cyan]",
    "critical": "[bold red]💀[/bold red]",
    "high": "[red]🔴[/red]",
    "medium": "[yellow]🟡[/yellow]",
    "low": "[cyan]🔵[/cyan]",
}

# ─────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────


def print_banner() -> None:
    """Display the AEGIS ASCII art banner. Always shown first."""
    banner = r"""
    +===========================================================+
    |    ___    ___  ____ ___ ____                              |
    |   / _ \  | __|/ ___|_ _/ ___|                            |
    |  | |_| | | _|| |  _ | |\___ \                            |
    |   \__,_| |___|\____|___\____/                            |
    |                                                           |
    |   Adaptive Exploitation & Global Intelligence System      |
    |   Version 1.0.0  |  For authorized testing only          |
    +===========================================================+
    """
    console.print(banner, style="bold cyan")


# ─────────────────────────────────────────────
# Scope Authorization Prompt
# ─────────────────────────────────────────────


def scope_prompt(target: str) -> bool:
    """
    Display scope authorization prompt and return True if user confirms.
    Default is NO — user must explicitly type 'y'.
    """
    console.print(
        Panel(
            f"[bold white]Target:[/bold white] [cyan]{target}[/cyan]\n\n"
            "[yellow]AEGIS will perform active scanning against this target.\n"
            "Unauthorized scanning is illegal and unethical.\n\n"
            "[bold white]Do you have explicit written authorization to scan this target?[/bold white]",
            title="[bold yellow][ ⚠ AUTHORIZATION CHECK ][/bold yellow]",
            border_style="yellow",
        )
    )
    answer = console.input("[bold yellow]Confirm [y/N]:[/bold yellow] ").strip().lower()
    return answer == "y"


# ─────────────────────────────────────────────
# Error & Warning Output
# ─────────────────────────────────────────────


def print_error(message: str, hint: str = None) -> None:
    """Display a fatal error panel in red."""
    content = f"[bold red]{message}[/bold red]"
    if hint:
        content += f"\n\n[yellow]→ {hint}[/yellow]"
    console.print(
        Panel(content, title="[bold red][ ERROR ][/bold red]", border_style="red")
    )
    logger.error(message)


def print_warning(message: str) -> None:
    """Display a non-fatal inline warning."""
    console.print(f"  [bold yellow]⚠[/bold yellow]  [yellow]{message}[/yellow]")
    logger.warning(message)


def print_info(message: str) -> None:
    """Display an informational message."""
    console.print(f"  [bold blue]ℹ[/bold blue]  {message}")
    logger.info(message)


# ─────────────────────────────────────────────
# Spinner
# ─────────────────────────────────────────────


def run_with_spinner(task_label: str, func, *args, **kwargs):
    """
    Run func(*args, **kwargs) while displaying a spinner.
    Spinner disappears when function returns (transient=True).
    """
    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[bold cyan]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(f"[ {task_label} ] Running...", total=None)
        result = func(*args, **kwargs)
        progress.update(task, completed=True)
    return result


# ─────────────────────────────────────────────
# Module Result Tables
# ─────────────────────────────────────────────


def print_port_table(ports: list) -> None:
    """Print nmap open ports table."""
    if not ports:
        console.print("[dim]  No open ports found.[/dim]")
        return

    table = Table(
        title="[ RECON ] Open Ports & Services",
        box=box.ROUNDED,
        title_style="bold cyan",
        header_style="bold white",
        show_lines=True,
    )
    table.add_column("PORT", style="bold white", width=8)
    table.add_column("PROTOCOL", width=10)
    table.add_column("SERVICE", style="cyan", width=15)
    table.add_column("VERSION", width=35)
    table.add_column("STATE", width=8)

    for port in ports:
        state_style = "bold green" if port.get("state") == "open" else "dim"
        version_str = (port.get("version") or "Unknown")[:35]
        table.add_row(
            str(port.get("port", "")),
            port.get("protocol", ""),
            port.get("service", ""),
            version_str,
            Text(port.get("state", "").upper(), style=state_style),
        )
    console.print(table)


def print_web_findings_table(findings: list, paths: list) -> None:
    """Print nikto + gobuster findings table."""
    if findings:
        table = Table(
            title="[ WEB ] Nikto Vulnerability Findings",
            box=box.ROUNDED,
            title_style="bold cyan",
            header_style="bold white",
            show_lines=True,
        )
        table.add_column("PATH", style="cyan", width=25)
        table.add_column("METHOD", width=8)
        table.add_column("DESCRIPTION", width=55)

        for f in findings[:30]:
            desc = (f.get("description") or "")[:55]
            table.add_row(
                (f.get("path") or "")[:25],
                f.get("method", "GET"),
                desc,
            )
        console.print(table)

    if paths:
        table2 = Table(
            title="[ WEB ] Gobuster Discovered Paths",
            box=box.ROUNDED,
            title_style="bold cyan",
            header_style="bold white",
            show_lines=True,
        )
        table2.add_column("PATH", style="cyan", width=35)
        table2.add_column("STATUS", width=8)
        table2.add_column("SIZE", width=10)

        for p in paths[:30]:
            status = p.get("status_code", 0)
            status_style = "bold green" if status == 200 else "yellow" if status == 301 else "dim"
            table2.add_row(
                p.get("path", "")[:35],
                Text(str(status), style=status_style),
                str(p.get("size", "")),
            )
        console.print(table2)


def print_smb_table(smb_data: dict) -> None:
    """Print SMB enumeration results table."""
    shares = smb_data.get("shares", [])
    users = smb_data.get("users", [])

    if shares:
        table = Table(
            title="[ SMB ] Shares",
            box=box.ROUNDED,
            title_style="bold cyan",
            header_style="bold white",
            show_lines=True,
        )
        table.add_column("SHARE NAME", style="cyan", width=20)
        table.add_column("TYPE", width=10)
        table.add_column("COMMENT", width=40)
        for share in shares:
            table.add_row(
                share.get("name", ""),
                share.get("type", ""),
                share.get("comment", ""),
            )
        console.print(table)

    if users:
        console.print(
            f"  [bold white]SMB Users:[/bold white] [cyan]{', '.join(users)}[/cyan]"
        )

    null_sess = smb_data.get("null_session", False)
    style = "bold red" if null_sess else "bold green"
    console.print(
        f"  [bold white]Null Session:[/bold white] [{style}]{'ALLOWED' if null_sess else 'DENIED'}[/{style}]"
    )


def print_service_result(module: str, result: dict) -> None:
    """Print a simple key-value result for FTP/SSH/MySQL modules."""
    table = Table(
        title=f"[ {module.upper()} ] Results",
        box=box.ROUNDED,
        title_style="bold cyan",
        header_style="bold white",
        show_lines=False,
        show_header=False,
    )
    table.add_column("Key", style="bold white", width=20)
    table.add_column("Value", width=55)

    skip_keys = {"enabled", "error"}
    for k, v in result.items():
        if k in skip_keys:
            continue
        if isinstance(v, list):
            v_str = ", ".join(str(x) for x in v) if v else "None"
        elif isinstance(v, bool):
            style = "bold red" if v and k in ("anonymous_login", "accessible") else ""
            v_str = Text("YES" if v else "NO", style=style)
        else:
            v_str = str(v) if v is not None else "None"
        table.add_row(k.replace("_", " ").title(), v_str)

    if result.get("error"):
        console.print(f"  [bold yellow]⚠[/bold yellow]  [yellow]{result['error']}[/yellow]")
    else:
        console.print(table)


# ─────────────────────────────────────────────
# AI Intelligence Panel
# ─────────────────────────────────────────────


def print_ai_panel(ai_result: dict) -> None:
    """Display the AI intelligence summary panel."""
    risk = ai_result.get("risk_level", "Unknown")
    risk_colors = {
        "Critical": "bold red",
        "High": "red",
        "Medium": "yellow",
        "Low": "cyan",
    }
    color = risk_colors.get(risk, "white")

    summary = ai_result.get("executive_summary", "No summary available.")
    cve_count = len(ai_result.get("cves", []))
    ttp_count = len(ai_result.get("ttps", []))

    panel_content = (
        f"[{color}]Risk Level: {risk.upper()}[/{color}]\n\n"
        f"[white]{summary}[/white]\n\n"
        f"[bold white]CVEs Identified:[/bold white] [red]{cve_count}[/red]\n"
        f"[bold white]ATT&CK TTPs Mapped:[/bold white] [yellow]{ttp_count}[/yellow]\n"
    )

    console.print(
        Panel(
            panel_content,
            title="[bold white][ AI ] Intelligence Report[/bold white]",
            border_style=color.replace("bold ", ""),
            padding=(1, 2),
        )
    )


def print_cve_table(cves: list) -> None:
    """Print CVE findings table."""
    if not cves:
        return

    table = Table(
        title="[ AI ] CVE Findings",
        box=box.ROUNDED,
        title_style="bold red",
        header_style="bold white",
        show_lines=True,
    )
    table.add_column("CVE ID", style="bold red", width=18)
    table.add_column("CVSS", width=6)
    table.add_column("SERVICE", width=15)
    table.add_column("DESCRIPTION", width=45)

    for cve in cves:
        try:
            cvss = float(cve.get("cvss", 0))
        except (ValueError, TypeError):
            cvss = 0.0

        if cvss >= 9:
            cvss_style = "bold red"
        elif cvss >= 7:
            cvss_style = "red"
        elif cvss >= 4:
            cvss_style = "yellow"
        else:
            cvss_style = "cyan"

        desc = cve.get("description", "")
        if len(desc) > 45:
            desc = desc[:42] + "..."

        table.add_row(
            cve.get("id", ""),
            Text(str(cvss), style=cvss_style),
            (cve.get("service") or "")[:15],
            desc,
        )
    console.print(table)


def print_ttp_table(ttps: list) -> None:
    """Print MITRE ATT&CK TTP table."""
    if not ttps:
        return

    table = Table(
        title="[ AI ] MITRE ATT&CK TTPs",
        box=box.ROUNDED,
        title_style="bold yellow",
        header_style="bold white",
        show_lines=True,
    )
    table.add_column("TTP ID", style="bold yellow", width=14)
    table.add_column("NAME", width=35)
    table.add_column("TACTIC", style="cyan", width=25)

    for ttp in ttps:
        table.add_row(
            ttp.get("id", ""),
            ttp.get("name", ""),
            ttp.get("tactic", ""),
        )
    console.print(table)


# ─────────────────────────────────────────────
# Status Badge
# ─────────────────────────────────────────────


def print_status_badge(module: str, count: int, status: str = "success") -> None:
    """Print a one-line status badge after a module completes."""
    styles = {
        "success": "bold green",
        "warning": "bold yellow",
        "error": "bold red",
        "skipped": "dim",
    }
    icons = {"success": "✓", "warning": "⚠", "error": "✗", "skipped": "—"}
    style = styles.get(status, "white")
    icon = icons.get(status, "•")
    console.print(
        f"  {icon} [{style}]{module}[/{style}] → {count} finding(s)"
    )


# ─────────────────────────────────────────────
# Verbose Mode
# ─────────────────────────────────────────────


def print_verbose(label: str, content: str) -> None:
    """Print raw tool output in dim style for verbose mode."""
    console.print(f"\n[dim]--- {label} (verbose) ---[/dim]")
    console.print(f"[dim]{content[:4000]}[/dim]")
    console.print(f"[dim]--- end {label} ---[/dim]\n")


# ─────────────────────────────────────────────
# Final Summary Panel
# ─────────────────────────────────────────────


def print_final_summary(scan_meta: dict) -> None:
    """Print the scan completion summary panel."""
    risk = scan_meta.get("risk_level", "Unknown")
    risk_colors = {
        "Critical": "bold red",
        "High": "red",
        "Medium": "yellow",
        "Low": "cyan",
        "Unknown": "dim",
    }
    risk_color = risk_colors.get(risk, "white")

    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column("Key", style="bold white")
    table.add_column("Value", style="white")

    table.add_row("Target", scan_meta.get("target", ""))
    table.add_row("Duration", scan_meta.get("duration", ""))
    table.add_row("Risk Level", Text(risk, style=risk_color))
    table.add_row(
        "Findings",
        f"{scan_meta.get('total', 0)} total "
        f"({scan_meta.get('critical', 0)} critical, "
        f"{scan_meta.get('high', 0)} high, "
        f"{scan_meta.get('medium', 0)} medium, "
        f"{scan_meta.get('low', 0)} low)",
    )
    table.add_row("CVEs Mapped", str(scan_meta.get("cve_count", 0)))
    table.add_row("ATT&CK TTPs", str(scan_meta.get("ttp_count", 0)))
    table.add_row("Report", scan_meta.get("report_path", ""))

    console.print(
        Panel(
            table,
            title="[bold green][ AEGIS ] Scan Complete[/bold green]",
            border_style="green",
            padding=(1, 2),
        )
    )
