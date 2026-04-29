"""
reporting/pdf_generator.py — PDF report generator for AEGIS

Builds a professional multi-page PDF report from ScanResult data
using the fpdf2 library. Works with or without AI analysis data.
"""

import os
import logging
from datetime import datetime

from fpdf import FPDF

logger = logging.getLogger("aegis")

# Severity → RGB color for PDF elements
SEVERITY_COLORS = {
    "Critical": (220, 0, 0),
    "High": (255, 100, 0),
    "Medium": (255, 165, 0),
    "Low": (0, 120, 200),
    "Info": (100, 100, 200),
    "Unknown": (150, 150, 150),
}

# Risk level → PDF text color
RISK_COLORS = {
    "Critical": (220, 0, 0),
    "High": (200, 60, 0),
    "Medium": (200, 140, 0),
    "Low": (0, 100, 180),
    "Unknown": (100, 100, 100),
}


class AegisPdf(FPDF):
    """Custom FPDF subclass with AEGIS header/footer."""

    def __init__(self, target: str, scan_date: str):
        super().__init__()
        self.target = target
        self.scan_date = scan_date
        self.set_auto_page_break(auto=True, margin=20)
        self.set_margins(15, 15, 15)

    def header(self):
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(100, 100, 100)
        self.cell(0, 8, f"AEGIS Vulnerability Assessment Report — {self.target}", align="L")
        self.set_x(-60)
        self.cell(0, 8, self.scan_date, align="R")
        self.ln(4)
        self.set_draw_color(200, 200, 200)
        self.line(15, self.get_y(), 195, self.get_y())
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, f"Page {self.page_no()} | AEGIS v1.0 | For authorized use only", align="C")

    def section_title(self, title: str, color: tuple = (0, 80, 160)):
        """Print a colored section heading."""
        self.set_font("Helvetica", "B", 13)
        self.set_text_color(*color)
        self.ln(4)
        self.cell(0, 10, title, ln=True)
        self.set_draw_color(*color)
        self.line(15, self.get_y(), 195, self.get_y())
        self.ln(4)
        self.set_text_color(0, 0, 0)

    def body_text(self, text: str, size: int = 10):
        """Print body text with word wrap."""
        self.set_font("Helvetica", "", size)
        self.set_text_color(30, 30, 30)
        self.multi_cell(0, 6, text)
        self.ln(2)

    def severity_badge(self, severity: str, x: float = None, y: float = None):
        """Print a small colored severity rectangle with text."""
        color = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["Unknown"])
        if x is None:
            x = self.get_x()
        if y is None:
            y = self.get_y()
        self.set_fill_color(*color)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 9)
        self.set_xy(x, y)
        self.cell(22, 6, severity.upper(), fill=True, align="C")
        self.set_text_color(0, 0, 0)

    def table_header(self, columns: list, widths: list):
        """Print a table header row."""
        self.set_font("Helvetica", "B", 9)
        self.set_fill_color(40, 40, 80)
        self.set_text_color(255, 255, 255)
        for col, w in zip(columns, widths):
            self.cell(w, 7, col, border=1, fill=True, align="C")
        self.ln()
        self.set_text_color(0, 0, 0)

    def table_row(self, values: list, widths: list, fill: bool = False):
        """Print a table data row with alternating fill."""
        self.set_font("Helvetica", "", 8)
        if fill:
            self.set_fill_color(240, 240, 250)
        else:
            self.set_fill_color(255, 255, 255)
        for val, w in zip(values, widths):
            val_str = str(val)[:int(w * 2)] if val else ""
            self.cell(w, 6, val_str, border=1, fill=True)
        self.ln()


class PdfGenerator:
    """Generates the full AEGIS PDF report from a ScanResult dict."""

    def __init__(self, scan_result: dict, output_path: str):
        self.scan_result = scan_result
        self.output_path = output_path

        meta = scan_result.get("meta", {})
        self.target = meta.get("target", "Unknown")
        self.scan_date = meta.get("scan_start", datetime.now().isoformat())[:10]
        self.ai = scan_result.get("ai", {})

    def generate(self) -> str:
        """Build and save the PDF. Returns output_path."""
        pdf = AegisPdf(self.target, self.scan_date)

        self._build_cover_page(pdf)
        self._build_executive_summary(pdf)
        self._build_findings_section(pdf)
        self._build_cve_table(pdf)
        self._build_ttp_table(pdf)
        self._build_raw_appendix(pdf)

        os.makedirs(os.path.dirname(self.output_path), exist_ok=True)
        pdf.output(self.output_path)
        logger.info(f"PDF report saved: {self.output_path}")
        return self.output_path

    # ──────────────────────────────────────────────────
    # Cover Page
    # ──────────────────────────────────────────────────

    def _build_cover_page(self, pdf: AegisPdf):
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 28)
        pdf.set_text_color(0, 60, 130)
        pdf.ln(30)
        pdf.cell(0, 15, "AEGIS", align="C", ln=True)

        pdf.set_font("Helvetica", "", 14)
        pdf.set_text_color(80, 80, 80)
        pdf.cell(0, 10, "Vulnerability Assessment Report", align="C", ln=True)
        pdf.ln(20)

        # Info box
        pdf.set_fill_color(245, 248, 255)
        pdf.set_draw_color(0, 60, 130)
        pdf.rect(30, pdf.get_y(), 150, 60, style="DF")

        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(0, 0, 0)
        pdf.set_xy(35, pdf.get_y() + 8)

        rows = [
            ("Target:", self.target),
            ("Assessment Date:", self.scan_date),
            ("Profile:", self.scan_result.get("meta", {}).get("profile", "full").title()),
            ("Generated by:", "AEGIS v1.0"),
        ]
        for label, value in rows:
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_x(35)
            pdf.cell(45, 8, label)
            pdf.set_font("Helvetica", "", 10)
            pdf.cell(90, 8, value, ln=True)
            pdf.set_x(35)

        # Risk badge
        risk = self.ai.get("risk_level", "Unknown")
        color = RISK_COLORS.get(risk, (100, 100, 100))
        pdf.ln(15)
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(*color)
        pdf.cell(0, 10, f"OVERALL RISK: {risk.upper()}", align="C", ln=True)

        # Disclaimer
        pdf.ln(40)
        pdf.set_font("Helvetica", "I", 9)
        pdf.set_text_color(150, 0, 0)
        pdf.multi_cell(
            0, 5,
            "CONFIDENTIAL: This report contains sensitive security information. "
            "It is intended solely for authorized personnel. "
            "AEGIS is for authorized testing only.",
            align="C",
        )

    # ──────────────────────────────────────────────────
    # Executive Summary
    # ──────────────────────────────────────────────────

    def _build_executive_summary(self, pdf: AegisPdf):
        pdf.add_page()
        pdf.section_title("Executive Summary")

        # Summary text
        summary = self.ai.get("executive_summary")
        if summary:
            pdf.body_text(summary)
        else:
            pdf.body_text(
                "AI analysis was not available for this scan. "
                "Please review the raw scan data in the appendix for detailed findings."
            )

        # Findings count table
        pdf.ln(4)
        findings = self.ai.get("findings", [])
        sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for f in findings:
            sev = f.get("severity", "Low")
            if sev in sev_counts:
                sev_counts[sev] += 1

        # Also count nmap + other module data if no AI findings
        if not findings:
            nmap_ports = self.scan_result.get("nmap", {}).get("open_ports", [])
            sev_counts["Low"] = len(nmap_ports)

        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 8, "Finding Severity Breakdown:", ln=True)
        pdf.ln(2)

        cols = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "TOTAL"]
        widths = [35, 35, 35, 35, 35]
        pdf.table_header(cols, widths)

        total = sum(sev_counts.values())
        pdf.table_row(
            [
                str(sev_counts["Critical"]),
                str(sev_counts["High"]),
                str(sev_counts["Medium"]),
                str(sev_counts["Low"]),
                str(total),
            ],
            widths,
        )

        # CVE / TTP summary
        pdf.ln(8)
        cve_count = len(self.ai.get("cves", []))
        ttp_count = len(self.ai.get("ttps", []))
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 7, f"CVEs Identified: {cve_count}    |    MITRE ATT&CK TTPs Mapped: {ttp_count}", ln=True)

    # ──────────────────────────────────────────────────
    # Vulnerability Findings
    # ──────────────────────────────────────────────────

    def _build_findings_section(self, pdf: AegisPdf):
        findings = self.ai.get("findings", [])
        if not findings:
            return

        pdf.add_page()
        pdf.section_title("Vulnerability Findings")

        # Sort: Critical → High → Medium → Low
        sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        findings_sorted = sorted(
            findings, key=lambda f: sev_order.get(f.get("severity", "Low"), 3)
        )

        for i, finding in enumerate(findings_sorted, 1):
            if pdf.get_y() > 240:
                pdf.add_page()

            severity = finding.get("severity", "Low")
            title = finding.get("title", f"Finding {i}")
            description = finding.get("description", "")
            recommendation = finding.get("recommendation", "")

            # Finding header
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_text_color(0, 0, 0)
            y_before = pdf.get_y()
            pdf.cell(0, 8, f"{i}. {title}", ln=True)

            # Severity badge
            pdf.severity_badge(severity, x=15, y=y_before)
            pdf.ln(2)

            # Description
            pdf.set_font("Helvetica", "", 10)
            pdf.set_text_color(40, 40, 40)
            pdf.multi_cell(0, 5, description)
            pdf.ln(2)

            # Recommendation
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(0, 80, 0)
            pdf.cell(0, 6, "Recommendation:", ln=True)
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(30, 30, 30)
            pdf.multi_cell(0, 5, recommendation)
            pdf.ln(6)

            # Separator
            pdf.set_draw_color(220, 220, 220)
            pdf.line(15, pdf.get_y(), 195, pdf.get_y())
            pdf.ln(4)

    # ──────────────────────────────────────────────────
    # CVE Table
    # ──────────────────────────────────────────────────

    def _build_cve_table(self, pdf: AegisPdf):
        cves = self.ai.get("cves", [])
        if not cves:
            return

        pdf.add_page()
        pdf.section_title("CVE Findings", color=(180, 0, 0))

        cols = ["CVE ID", "CVSS", "SERVICE", "DESCRIPTION", "RECOMMENDATION"]
        widths = [30, 12, 28, 55, 55]
        pdf.table_header(cols, widths)

        for i, cve in enumerate(cves):
            try:
                cvss = float(cve.get("cvss", 0))
            except (ValueError, TypeError):
                cvss = 0.0

            desc = (cve.get("description") or "")[:70]
            rec = (cve.get("recommendation") or "")[:70]
            service = (cve.get("service") or "")[:25]

            pdf.table_row(
                [
                    cve.get("id", ""),
                    f"{cvss:.1f}",
                    service,
                    desc,
                    rec,
                ],
                widths,
                fill=(i % 2 == 0),
            )

    # ──────────────────────────────────────────────────
    # MITRE ATT&CK TTP Table
    # ──────────────────────────────────────────────────

    def _build_ttp_table(self, pdf: AegisPdf):
        ttps = self.ai.get("ttps", [])
        if not ttps:
            return

        pdf.add_page()
        pdf.section_title("MITRE ATT&CK TTPs", color=(140, 100, 0))

        cols = ["TTP ID", "NAME", "TACTIC"]
        widths = [25, 85, 70]
        pdf.table_header(cols, widths)

        for i, ttp in enumerate(ttps):
            pdf.table_row(
                [
                    ttp.get("id", ""),
                    (ttp.get("name") or "")[:60],
                    (ttp.get("tactic") or "")[:40],
                ],
                widths,
                fill=(i % 2 == 0),
            )

    # ──────────────────────────────────────────────────
    # Raw Scan Appendix
    # ──────────────────────────────────────────────────

    def _build_raw_appendix(self, pdf: AegisPdf):
        pdf.add_page()
        pdf.section_title("Appendix: Raw Scan Data", color=(60, 60, 60))

        # nmap open ports
        open_ports = self.scan_result.get("nmap", {}).get("open_ports", [])
        if open_ports:
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_text_color(0, 0, 0)
            pdf.cell(0, 8, "Network Reconnaissance (nmap)", ln=True)
            pdf.ln(2)

            os_guess = self.scan_result.get("nmap", {}).get("os_guess")
            if os_guess:
                pdf.set_font("Helvetica", "", 9)
                pdf.cell(0, 6, f"OS Guess: {os_guess}", ln=True)
                pdf.ln(2)

            cols = ["PORT", "PROTOCOL", "SERVICE", "VERSION"]
            widths = [18, 20, 30, 112]
            pdf.table_header(cols, widths)
            for i, port in enumerate(open_ports):
                pdf.table_row(
                    [
                        str(port.get("port", "")),
                        port.get("protocol", "tcp"),
                        (port.get("service") or "")[:25],
                        (port.get("version") or "")[:80],
                    ],
                    widths,
                    fill=(i % 2 == 0),
                )
            pdf.ln(8)

        # FTP
        ftp = self.scan_result.get("ftp", {})
        if ftp.get("enabled"):
            pdf.set_font("Helvetica", "B", 11)
            pdf.cell(0, 8, "FTP Probe Results", ln=True)
            pdf.set_font("Helvetica", "", 9)
            pdf.cell(0, 6, f"Anonymous Login: {'YES' if ftp.get('anonymous_login') else 'NO'}", ln=True)
            if ftp.get("banner"):
                pdf.cell(0, 6, f"Banner: {ftp['banner'][:100]}", ln=True)
            if ftp.get("notes"):
                pdf.cell(0, 6, f"Notes: {ftp['notes']}", ln=True)
            pdf.ln(6)

        # SSH
        ssh = self.scan_result.get("ssh", {})
        if ssh.get("enabled"):
            pdf.set_font("Helvetica", "B", 11)
            pdf.cell(0, 8, "SSH Probe Results", ln=True)
            pdf.set_font("Helvetica", "", 9)
            if ssh.get("version"):
                pdf.cell(0, 6, f"Version: {ssh['version']}", ln=True)
            if ssh.get("known_cves"):
                pdf.cell(0, 6, f"Known CVEs: {', '.join(ssh['known_cves'])}", ln=True)
            pdf.ln(6)

        # MySQL
        mysql = self.scan_result.get("mysql", {})
        if mysql.get("enabled"):
            pdf.set_font("Helvetica", "B", 11)
            pdf.cell(0, 8, "MySQL Probe Results", ln=True)
            pdf.set_font("Helvetica", "", 9)
            pdf.cell(0, 6, f"Accessible: {'YES' if mysql.get('accessible') else 'NO'}", ln=True)
            if mysql.get("credentials_found"):
                pdf.cell(0, 6, f"Credentials Found: {mysql['credentials_found']}", ln=True)
            pdf.ln(6)

        # SMB
        smb = self.scan_result.get("smb", {})
        if smb.get("enabled") and smb.get("shares"):
            pdf.set_font("Helvetica", "B", 11)
            pdf.cell(0, 8, "SMB Enumeration Results", ln=True)
            pdf.set_font("Helvetica", "", 9)
            pdf.cell(0, 6, f"Null Session: {'YES' if smb.get('null_session') else 'NO'}", ln=True)
            shares_str = ", ".join(s["name"] for s in smb["shares"])
            pdf.cell(0, 6, f"Shares: {shares_str}", ln=True)
            if smb.get("users"):
                pdf.cell(0, 6, f"Users: {', '.join(smb['users'][:10])}", ln=True)
            pdf.ln(6)

        # Scan errors
        errors = self.scan_result.get("errors", [])
        if errors:
            pdf.set_font("Helvetica", "B", 11)
            pdf.cell(0, 8, "Non-Fatal Scan Errors", ln=True)
            pdf.set_font("Helvetica", "", 9)
            for err in errors:
                pdf.multi_cell(0, 5, f"• {err}")
            pdf.ln(4)
