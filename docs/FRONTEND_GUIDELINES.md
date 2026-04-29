# Frontend / CLI UI Guidelines
# AEGIS — Adaptive Exploitation & Global Intelligence System

> Note: AEGIS has no web frontend. This document defines the **CLI UI design system** — the equivalent of a frontend style guide for a terminal application. It governs colors, layout, typography, component patterns, and Rich library usage to ensure a consistent, professional terminal experience.

---

## 1. Design Principles

### 1. Signal Over Noise
Every line of output must carry meaning. No verbose padding, no repeated headers. The user is mid-assessment — respect their focus.

### 2. Severity = Color
Colors are not decorative. Red = stop/critical. Yellow = warning. Green = safe/success. Blue = informational. Users must be able to parse risk at a glance.

### 3. Progressive Disclosure
Show high-level results first (summary panel), raw details last (verbose mode or appendix). Don't dump 500 lines of nmap XML into the terminal.

### 4. Fail Loudly, Recover Gracefully
Errors are displayed in bold red with clear action steps. AEGIS never silently swallows failures.

### 5. Consistent Panel Identity
Every module follows the same output rhythm: spinner during work → result table on complete → status badge. Users build muscle memory quickly.

---

## 2. Rich Library — Core Usage Rules

AEGIS uses the `rich` library (v13.7.1) exclusively for all terminal output. **Never use `print()` directly in any module.** All output flows through `ui/console.py`.

```python
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text
from rich import box

console = Console()
```

---

## 3. Color System

AEGIS uses Rich's named colors mapped to semantic meanings. These must be used consistently across ALL modules and output.

### Severity Colors

| Severity | Rich Color | Hex Approx | Usage |
|----------|-----------|------------|-------|
| CRITICAL | `bold red` | #FF0000 | Critical vulnerabilities, auth failures, RCE-class findings |
| HIGH | `red` | #FF4444 | High severity CVEs, dangerous open services |
| MEDIUM | `yellow` | #FFAA00 | Medium severity findings, potential issues |
| LOW | `cyan` | #00BBFF | Low severity, informational findings |
| INFO | `blue` | #4488FF | Module status, configuration info |
| SUCCESS | `bold green` | #00CC44 | Completed steps, clean checks |
| WARNING | `bold yellow` | `⚠` warnings, skipped modules, fallback behavior |
| ERROR | `bold red` | Fatal errors, dependency failures |
| DIM | `dim white` | Verbose/secondary output, raw tool output |

### Status Icons

Always combine color with an icon for accessibility (not everyone can distinguish color):

```python
ICONS = {
    "success":  "[bold green]✓[/bold green]",
    "error":    "[bold red]✗[/bold red]",
    "warning":  "[bold yellow]⚠[/bold yellow]",
    "info":     "[bold blue]ℹ[/bold blue]",
    "running":  "[cyan]►[/cyan]",
    "critical": "[bold red]💀[/bold red]",
    "high":     "[red]🔴[/red]",
    "medium":   "[yellow]🟡[/yellow]",
    "low":      "[cyan]🔵[/cyan]",
}
```

---

## 4. Typography & Text Rules

### Text Hierarchy
```
BANNER TEXT          → bold white, large ASCII art
Panel Titles         → bold white (in Rich Panel borders)
Module Headers       → bold cyan  e.g. "[ RECON ] Network Scan"
Table Headers        → bold white
Table Data           → white (default) or severity-colored
Status Messages      → color by severity
Error Messages       → bold red
Verbose/Raw Output   → dim white
```

### Capitalization Rules
- Module names in brackets are ALL CAPS: `[ RECON ]`, `[ WEB ]`, `[ SMB ]`
- Severity labels are ALL CAPS: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`
- Service names are lowercase: `ftp`, `ssh`, `http`
- CVE IDs are uppercase: `CVE-2011-2523`
- ATT&CK TTP IDs follow standard format: `T1110.001`

### Text Width
- Target terminal width: 100 columns
- Rich's `Console()` auto-detects terminal width — no hard-coding needed
- Panels should not exceed 90% of terminal width

---

## 5. Component Patterns

### 5.1 Banner Component

Displayed once at startup.

```python
def print_banner():
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║    █████╗ ███████╗ ██████╗ ██╗███████╗                   ║
    ║   ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝                   ║
    ║   ███████║█████╗  ██║  ███╗██║███████╗                   ║
    ║   ██╔══██║██╔══╝  ██║   ██║██║╚════██║                   ║
    ║   ██║  ██║███████╗╚██████╔╝██║███████║                   ║
    ║   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝                   ║
    ║                                                           ║
    ║   Adaptive Exploitation & Global Intelligence System      ║
    ║   Version 1.0 | github.com/<username>/aegis              ║
    ║   For authorized testing only                            ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold cyan")
```

**Rules**:
- Banner is ALWAYS printed first
- Color: `bold cyan`
- Version number must match `__version__` constant
- Warning line "For authorized testing only" always present

---

### 5.2 Module Spinner

Used during any module execution that has a wait time.

```python
def run_with_spinner(task_label: str, func, *args, **kwargs):
    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[bold cyan]{task.description}"),
        console=console,
        transient=True,   # Spinner disappears when done (replaced by result panel)
    ) as progress:
        task = progress.add_task(f"[ {task_label} ] Running...", total=None)
        result = func(*args, **kwargs)
        progress.update(task, completed=True)
    return result
```

**Rules**:
- `transient=True` — spinner line is consumed when module completes
- Label format: `[ MODULE_NAME ] Running...` — uppercase module name, trailing ellipsis
- Spinner color: cyan
- After spinner: print result table immediately

**Example output (during run)**:
```
⠸ [ RECON ] Running nmap scan...
```

---

### 5.3 Module Result Table

Printed after each module completes. Each module has a standardized table.

```python
def print_port_table(ports: list[dict]):
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
    table.add_column("VERSION", width=30)
    table.add_column("STATE", width=8)

    for port in ports:
        state_style = "bold green" if port["state"] == "open" else "dim"
        table.add_row(
            str(port["port"]),
            port["protocol"],
            port["service"],
            port["version"] or "Unknown",
            Text(port["state"].upper(), style=state_style),
        )
    console.print(table)
```

**Standard table rules**:
- `box=box.ROUNDED` for all tables
- Title: `[ MODULE_NAME ] Description` in `bold cyan`
- Header row: `bold white`
- Data rows: default white unless severity-colored
- Always use `show_lines=True` for readability
- Max column width: 40 characters (truncate with `...` if longer)

---

### 5.4 Status Badge

Printed at bottom of each module output to confirm completion.

```python
def print_status_badge(module: str, finding_count: int, status: str = "success"):
    styles = {
        "success": "bold green",
        "warning": "bold yellow",
        "error": "bold red",
        "skipped": "dim",
    }
    icon = {"success": "✓", "warning": "⚠", "error": "✗", "skipped": "—"}
    console.print(
        f"  {icon[status]} [{styles[status]}]{module}[/{styles[status]}] "
        f"→ {finding_count} finding(s)",
    )
```

**Example outputs**:
```
  ✓ [bold green]RECON[/bold green] → 22 findings
  ⚠ [bold yellow]WEB[/bold yellow] → 8 findings
  — [dim]SMB[/dim] → skipped (port 445 not open)
```

---

### 5.5 AI Intelligence Panel

Displayed after AI engine completes. This is the highest-visibility output.

```python
def print_ai_panel(ai_result: dict):
    risk = ai_result["risk_level"]
    risk_colors = {
        "Critical": "bold red",
        "High": "red",
        "Medium": "yellow",
        "Low": "cyan",
    }
    color = risk_colors.get(risk, "white")

    panel_content = (
        f"[{color}]Risk Level: {risk.upper()}[/{color}]\n\n"
        f"[white]{ai_result['executive_summary']}[/white]\n\n"
        f"[bold white]CVEs Identified:[/bold white] [red]{len(ai_result['cves'])}[/red]\n"
        f"[bold white]ATT&CK TTPs Mapped:[/bold white] [yellow]{len(ai_result['ttps'])}[/yellow]\n"
    )

    console.print(Panel(
        panel_content,
        title="[bold white][ AI ] Intelligence Report[/bold white]",
        border_style=color,
        padding=(1, 2),
    ))
```

**Rules**:
- Panel border color matches risk level color
- Risk level displayed FIRST and in ALL CAPS
- Executive summary rendered as plain white text
- CVE count in red, TTP count in yellow

**Example output** (Critical risk):
```
╭─────────────────────────────── [ AI ] Intelligence Report ────────────────────────────────╮
│                                                                                            │
│  Risk Level: CRITICAL                                                                      │
│                                                                                            │
│  The target exposes multiple critical vulnerabilities including an exploitable              │
│  vsftpd 2.3.4 backdoor (CVE-2011-2523), unauthenticated MySQL access, and open SMB        │
│  shares. An attacker could achieve remote code execution within minutes of discovery.      │
│                                                                                            │
│  CVEs Identified: 8                                                                        │
│  ATT&CK TTPs Mapped: 12                                                                    │
│                                                                                            │
╰────────────────────────────────────────────────────────────────────────────────────────────╯
```

---

### 5.6 Error Panel

Used for fatal errors that stop execution.

```python
def print_error(message: str, hint: str = None):
    content = f"[bold red]{message}[/bold red]"
    if hint:
        content += f"\n\n[yellow]→ {hint}[/yellow]"
    console.print(Panel(content, title="[bold red][ ERROR ][/bold red]", border_style="red"))
```

**Example**:
```
╭────────────────────── [ ERROR ] ──────────────────────╮
│                                                        │
│  nmap not found on this system.                       │
│                                                        │
│  → Install with: sudo apt install nmap                │
│                                                        │
╰────────────────────────────────────────────────────────╯
```

---

### 5.7 Warning Message (inline, non-fatal)

```python
def print_warning(message: str):
    console.print(f"  [bold yellow]⚠[/bold yellow]  [yellow]{message}[/yellow]")
```

**Example**:
```
  ⚠  nikto timed out after 600s. Skipping web vulnerability scan.
```

---

### 5.8 Final Summary Panel

Printed at end of every successful scan.

```python
def print_final_summary(scan_meta: dict):
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column("Key", style="bold white")
    table.add_column("Value", style="white")

    table.add_row("Target",     scan_meta["target"])
    table.add_row("Duration",   scan_meta["duration"])
    table.add_row("Risk Level", Text(scan_meta["risk_level"], style=risk_color))
    table.add_row("Findings",   f"{scan_meta['total']} total ({scan_meta['critical']} critical)")
    table.add_row("CVEs",       str(scan_meta["cve_count"]))
    table.add_row("TTPs",       str(scan_meta["ttp_count"]))
    table.add_row("Report",     scan_meta["report_path"])

    console.print(Panel(
        table,
        title="[bold green][ AEGIS ] Scan Complete[/bold green]",
        border_style="green",
        padding=(1, 2),
    ))
```

---

## 6. Verbose Mode Output

When `--verbose` is active, raw subprocess output is printed BELOW module result tables in dim style.

```python
def print_verbose(label: str, content: str):
    console.print(f"\n[dim]--- {label} (verbose) ---[/dim]")
    console.print(f"[dim]{content}[/dim]")
    console.print(f"[dim]--- end {label} ---[/dim]\n")
```

**Rules**:
- Always wrapped in `--- label ---` delimiters
- `dim` styling for all verbose output
- Printed AFTER the structured result table, not before

---

## 7. Scope Authorization Prompt

```python
def scope_prompt(target: str) -> bool:
    console.print(Panel(
        f"[bold white]Target:[/bold white] [cyan]{target}[/cyan]\n\n"
        "[yellow]AEGIS will perform active scanning against this target.\n"
        "Unauthorized scanning is illegal and unethical.\n\n"
        "[bold white]Do you have explicit written authorization to scan this target?[/bold white]",
        title="[bold yellow][ ⚠ AUTHORIZATION CHECK ][/bold yellow]",
        border_style="yellow",
    ))
    answer = console.input("[bold yellow]Confirm [y/N]:[/bold yellow] ").strip().lower()
    return answer == "y"
```

**Rules**:
- Always shown — no way to bypass in normal operation
- Default is NO (user must explicitly type 'y')
- Border color: yellow (warning, not red — red implies danger has already occurred)

---

## 8. CVE & TTP Table Pattern

```python
def print_cve_table(cves: list[dict]):
    table = Table(
        title="[ AI ] CVE Findings",
        box=box.ROUNDED,
        title_style="bold red",
        header_style="bold white",
        show_lines=True,
    )
    table.add_column("CVE ID", style="bold red", width=18)
    table.add_column("CVSS", width=6)
    table.add_column("SERVICE", width=12)
    table.add_column("DESCRIPTION", width=50)

    for cve in cves:
        cvss = float(cve["cvss"])
        cvss_style = "bold red" if cvss >= 9 else "red" if cvss >= 7 else "yellow" if cvss >= 4 else "cyan"
        table.add_row(
            cve["id"],
            Text(str(cvss), style=cvss_style),
            cve["service"],
            cve["description"][:50] + "..." if len(cve["description"]) > 50 else cve["description"],
        )
    console.print(table)
```

---

## 9. Console.py Public API

All UI functions must be defined in `ui/console.py` and imported by modules. Modules must NOT import `rich` directly.

```python
# ui/console.py — Public API

def print_banner() -> None
def scope_prompt(target: str) -> bool
def print_error(message: str, hint: str = None) -> None
def print_warning(message: str) -> None
def run_with_spinner(task_label: str, func, *args, **kwargs) -> any
def print_port_table(ports: list[dict]) -> None
def print_web_findings_table(findings: list[dict]) -> None
def print_smb_table(smb_data: dict) -> None
def print_service_result(module: str, result: dict) -> None
def print_ai_panel(ai_result: dict) -> None
def print_cve_table(cves: list[dict]) -> None
def print_ttp_table(ttps: list[dict]) -> None
def print_final_summary(scan_meta: dict) -> None
def print_status_badge(module: str, count: int, status: str) -> None
def print_verbose(label: str, content: str) -> None
def print_info(message: str) -> None
```

---

## 10. Accessibility Notes

- Every color-coded element also includes a text label or icon (not color-only)
- All severity levels spelled out: "CRITICAL", "HIGH" — not assumed from color alone
- Error messages always include: what went wrong + what to do about it
- No color codes in log files (strip Rich markup before writing to `aegis.log`)
