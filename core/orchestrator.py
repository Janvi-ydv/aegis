"""
core/orchestrator.py — Main pipeline coordinator for AEGIS

Sequences: Validator → Dependency Check → Nmap → Module Dispatch
          → AI Engine → Report Generator → Final Summary.

All module failures are caught and logged; execution always continues.
"""

import os
import time
import logging
from datetime import datetime

from ui.console import (
    print_error,
    print_warning,
    print_info,
    print_ai_panel,
    print_cve_table,
    print_ttp_table,
    print_final_summary,
    run_with_spinner,
    console,
)
from core.validator import validate_and_authorize
from core.dependency import check_dependencies
from modules.nmap_scanner import NmapScanner
from modules.web_scanner import WebScanner
from modules.smb_enum import SmbEnum
from modules.ftp_probe import FtpProbe
from modules.ssh_probe import SshProbe
from modules.mysql_probe import MySqlProbe
from ai.intelligence import call_ai_engine
from utils.file_utils import cleanup_temp_files, build_report_path, ensure_reports_dir

logger = logging.getLogger("aegis")

# Ports that trigger each conditional module
TRIGGER_PORTS = {
    "web": {80, 443, 8080, 8443},
    "smb": {139, 445},
    "ftp": {21},
    "ssh": {22},
    "mysql": {3306},
}

AEGIS_VERSION = "1.0.0"


class Orchestrator:
    """
    Sequences all AEGIS modules and manages the central ScanResult dict.
    """

    def __init__(
        self,
        target: str,
        profile: str,
        output_format: str,
        output_path: str = None,
        no_ai: bool = False,
        verbose: bool = False,
    ):
        self.target = target
        self.profile = profile
        self.output_format = output_format
        self.custom_output_path = output_path
        self.no_ai = no_ai
        self.verbose = verbose
        self.api_key = os.getenv("OPENROUTER_API_KEY", "")
        self.scan_result = self._init_scan_result()

    # ──────────────────────────────────────────────────────
    # Main Pipeline
    # ──────────────────────────────────────────────────────

    def run(self) -> str:
        """
        Execute the full AEGIS scan pipeline.

        Returns:
            Path to the generated report file.

        The orchestrator's run() method NEVER propagates unhandled exceptions
        to the CLI layer — all module failures are caught and logged.
        """
        start_time = time.time()
        report_path = None

        try:
            # ── Step 1: Target Validation + Authorization ──────
            if not validate_and_authorize(self.target):
                return ""

            # ── Step 2: Dependency Check ───────────────────────
            if not check_dependencies(verbose=True):
                return ""

            # ── Step 3: Nmap Reconnaissance ────────────────────
            print_info("Starting network reconnaissance...")
            nmap_result = run_with_spinner(
                "RECON",
                self._run_nmap,
            )
            self.scan_result["nmap"] = nmap_result

            if nmap_result.get("error") and not nmap_result.get("open_ports"):
                if "not found" in (nmap_result.get("error") or ""):
                    print_error(
                        nmap_result["error"],
                        hint="sudo apt install nmap",
                    )
                    return ""

            # ── Step 4: Module Dispatch ────────────────────────
            self._dispatch_modules()

            # ── Step 5: AI Intelligence Engine ────────────────
            if self.no_ai:
                console.print(
                    "\n  [bold yellow]ℹ[/bold yellow]  "
                    "[yellow][ AI ] AI engine disabled (--no-ai). "
                    "Generating raw report.[/yellow]\n"
                )
                self.scan_result["ai"]["enabled"] = False
            else:
                print_info("Sending findings to AI intelligence engine...")
                ai_result = run_with_spinner("AI", self._run_ai)

                if ai_result:
                    self.scan_result["ai"].update(ai_result)
                    self.scan_result["ai"]["enabled"] = True
                    print_ai_panel(ai_result)
                    print_cve_table(ai_result.get("cves", []))
                    print_ttp_table(ai_result.get("ttps", []))
                else:
                    print_warning(
                        "AI engine unavailable. Report will use raw scan data only."
                    )
                    self.scan_result["ai"]["enabled"] = False

            # ── Step 6: Report Generation ──────────────────────
            duration = time.time() - start_time
            self.scan_result["meta"]["scan_end"] = datetime.now().isoformat()
            self.scan_result["meta"]["duration_seconds"] = round(duration, 1)

            report_path = run_with_spinner("REPORT", self._generate_report)

            # ── Step 7: Final Summary ──────────────────────────
            self._print_final_summary(report_path, duration)

        except KeyboardInterrupt:
            console.print(
                "\n\n  [bold yellow]⚠[/bold yellow]  "
                "[yellow]Scan interrupted by user. Saving partial results...[/yellow]\n"
            )
            logger.info("Scan interrupted by KeyboardInterrupt.")
            if report_path is None:
                try:
                    self.scan_result["meta"]["scan_end"] = datetime.now().isoformat()
                    report_path = self._generate_report()
                    console.print(
                        f"  [bold green]✓[/bold green]  "
                        f"Partial report saved: [cyan]{report_path}[/cyan]\n"
                    )
                except Exception as e:
                    logger.error(f"Could not save partial report: {e}")

        except Exception as e:
            logger.error(f"Unexpected orchestrator error: {e}", exc_info=True)
            print_error(f"Unexpected error: {str(e)}", hint="Check aegis.log for details.")

        finally:
            cleanup_temp_files()

        return report_path or ""

    # ──────────────────────────────────────────────────────
    # Module Runners
    # ──────────────────────────────────────────────────────

    def _run_nmap(self) -> dict:
        scanner = NmapScanner(self.target, self.profile, verbose=self.verbose)
        return scanner.run()

    def _dispatch_modules(self) -> None:
        """Read open ports from nmap result and dispatch conditional modules."""
        open_ports = self.scan_result.get("nmap", {}).get("open_ports", [])

        if not open_ports:
            print_warning(
                "No open ports detected. Target may be offline or all ports filtered. "
                "Skipping service modules."
            )
            return

        port_nums = {p.get("port") for p in open_ports}

        # Web
        if port_nums & TRIGGER_PORTS["web"]:
            self.scan_result["web"]["enabled"] = True
            from modules.web_scanner import WebScanner
            base_url = WebScanner.determine_base_url(self.target, open_ports)
            self.scan_result["web"]["base_url"] = base_url
            web_result = run_with_spinner(
                "WEB",
                lambda: WebScanner(
                    self.target, base_url, verbose=self.verbose
                ).run(),
            )
            self.scan_result["web"].update(web_result)
        else:
            print_info("[ WEB ] No HTTP ports detected — skipping web module.")

        # SMB
        if port_nums & TRIGGER_PORTS["smb"]:
            self.scan_result["smb"]["enabled"] = True
            smb_result = run_with_spinner(
                "SMB",
                lambda: SmbEnum(self.target, verbose=self.verbose).run(),
            )
            self.scan_result["smb"].update(smb_result)
        else:
            print_info("[ SMB ] Port 445/139 not detected — skipping SMB module.")

        # FTP
        if port_nums & TRIGGER_PORTS["ftp"]:
            self.scan_result["ftp"]["enabled"] = True
            ftp_result = run_with_spinner(
                "FTP",
                lambda: FtpProbe(self.target, verbose=self.verbose).run(),
            )
            self.scan_result["ftp"].update(ftp_result)
        else:
            print_info("[ FTP ] Port 21 not detected — skipping FTP module.")

        # SSH
        if port_nums & TRIGGER_PORTS["ssh"]:
            self.scan_result["ssh"]["enabled"] = True
            ssh_result = run_with_spinner(
                "SSH",
                lambda: SshProbe(self.target, verbose=self.verbose).run(),
            )
            self.scan_result["ssh"].update(ssh_result)
        else:
            print_info("[ SSH ] Port 22 not detected — skipping SSH module.")

        # MySQL
        if port_nums & TRIGGER_PORTS["mysql"]:
            self.scan_result["mysql"]["enabled"] = True
            mysql_result = run_with_spinner(
                "MYSQL",
                lambda: MySqlProbe(self.target, verbose=self.verbose).run(),
            )
            self.scan_result["mysql"].update(mysql_result)
        else:
            print_info("[ MYSQL ] Port 3306 not detected — skipping MySQL module.")

    def _run_ai(self) -> dict | None:
        return call_ai_engine(self.scan_result, self.api_key)

    def _generate_report(self) -> str:
        """Generate the report in the specified format."""
        reports_dir = os.getenv("AEGIS_REPORTS_DIR", "./reports")
        ensure_reports_dir(reports_dir)

        if self.custom_output_path:
            output_path = self.custom_output_path
        else:
            output_path = build_report_path(
                self.target, self.output_format, reports_dir
            )

        if self.output_format == "pdf":
            from reporting.pdf_generator import PdfGenerator
            gen = PdfGenerator(self.scan_result, output_path)
            return gen.generate()

        elif self.output_format == "json":
            from reporting.json_exporter import export_json
            return export_json(self.scan_result, output_path)

        elif self.output_format == "markdown":
            from reporting.markdown_gen import generate_markdown
            return generate_markdown(self.scan_result, output_path)

        return output_path

    # ──────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────

    def _init_scan_result(self) -> dict:
        """Initialize the empty ScanResult dict per BACKEND_STRUCTURE.md §2."""
        return {
            "meta": {
                "target": self.target,
                "scan_start": datetime.now().isoformat(),
                "scan_end": None,
                "duration_seconds": None,
                "profile": self.profile,
                "aegis_version": AEGIS_VERSION,
            },
            "nmap": {
                "raw_xml_path": None,
                "os_guess": None,
                "open_ports": [],
                "interesting_services": [],
                "error": None,
            },
            "web": {
                "enabled": False,
                "base_url": None,
                "nikto": {"findings": [], "error": None},
                "gobuster": {"paths": [], "error": None},
            },
            "smb": {
                "enabled": False,
                "shares": [],
                "users": [],
                "os_version": None,
                "workgroup": None,
                "null_session": False,
                "error": None,
            },
            "ftp": {
                "enabled": False,
                "anonymous_login": False,
                "banner": None,
                "accessible_files": [],
                "error": None,
            },
            "ssh": {
                "enabled": False,
                "banner": None,
                "version": None,
                "weak_algorithms": [],
                "known_cves": [],
                "error": None,
            },
            "mysql": {
                "enabled": False,
                "accessible": False,
                "credentials_found": None,
                "error": None,
            },
            "ai": {
                "enabled": False,
                "risk_level": None,
                "executive_summary": None,
                "cves": [],
                "ttps": [],
                "findings": [],
                "raw_response": None,
                "error": None,
            },
            "errors": [],
        }

    def _print_final_summary(self, report_path: str, duration: float) -> None:
        """Compute stats and print the final summary panel."""
        ai = self.scan_result.get("ai", {})
        findings = ai.get("findings", [])

        sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for f in findings:
            sev = f.get("severity", "Low")
            if sev in sev_counts:
                sev_counts[sev] += 1

        total = sum(sev_counts.values())
        if total == 0:
            # Fallback to nmap port count
            total = len(self.scan_result.get("nmap", {}).get("open_ports", []))

        minutes = int(duration // 60)
        seconds = int(duration % 60)
        duration_str = f"{minutes}m {seconds}s" if minutes else f"{seconds}s"

        scan_meta = {
            "target": self.target,
            "duration": duration_str,
            "risk_level": ai.get("risk_level", "Unknown"),
            "total": total,
            "critical": sev_counts["Critical"],
            "high": sev_counts["High"],
            "medium": sev_counts["Medium"],
            "low": sev_counts["Low"],
            "cve_count": len(ai.get("cves", [])),
            "ttp_count": len(ai.get("ttps", [])),
            "report_path": report_path or "N/A",
        }
        print_final_summary(scan_meta)

    # ──────────────────────────────────────────────────────
    # Conditional Port Checks (for testing)
    # ──────────────────────────────────────────────────────

    def _get_open_port_nums(self) -> set:
        ports = self.scan_result.get("nmap", {}).get("open_ports", [])
        return {p.get("port") for p in ports}

    def _should_run_web(self) -> bool:
        return bool(self._get_open_port_nums() & TRIGGER_PORTS["web"])

    def _should_run_smb(self) -> bool:
        return bool(self._get_open_port_nums() & TRIGGER_PORTS["smb"])

    def _should_run_ftp(self) -> bool:
        return bool(self._get_open_port_nums() & TRIGGER_PORTS["ftp"])

    def _should_run_ssh(self) -> bool:
        return bool(self._get_open_port_nums() & TRIGGER_PORTS["ssh"])

    def _should_run_mysql(self) -> bool:
        return bool(self._get_open_port_nums() & TRIGGER_PORTS["mysql"])
