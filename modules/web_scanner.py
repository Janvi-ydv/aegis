"""
modules/web_scanner.py — Web application scanning module for AEGIS

Runs nikto (vulnerability scanner) and gobuster (directory enumeration)
against discovered HTTP/HTTPS services, parses their outputs into
structured data for the AI engine and report generator.
"""

import os
import re
import logging
import xml.etree.ElementTree as ET

from ui.console import (
    print_warning,
    print_verbose,
    print_web_findings_table,
    print_status_badge,
    print_info,
)
from utils.subprocess_utils import run_tool
from utils.file_utils import temp_path

logger = logging.getLogger("aegis")

# Default wordlist — can be overridden via env
DEFAULT_WORDLIST = os.getenv(
    "AEGIS_WORDLIST", "/usr/share/wordlists/dirb/common.txt"
)

# Gobuster output line format
# /admin                (Status: 200) [Size: 1234]
_GOBUSTER_RE = re.compile(
    r"^(/\S*)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)\]", re.MULTILINE
)


class WebScanner:
    """Runs nikto and gobuster against a web target."""

    def __init__(
        self,
        target: str,
        base_url: str,
        verbose: bool = False,
        wordlist: str = None,
    ):
        self.target = target
        self.base_url = base_url.rstrip("/")
        self.verbose = verbose
        self.wordlist = wordlist or DEFAULT_WORDLIST
        self.nikto_path = temp_path("nikto")
        self.gobuster_path = temp_path("gobuster")

    def run(self) -> dict:
        """
        Execute nikto and gobuster, return the web section of ScanResult.
        Never raises — catches all exceptions internally.
        """
        result = {
            "enabled": True,
            "base_url": self.base_url,
            "nikto": {"findings": [], "error": None},
            "gobuster": {"paths": [], "error": None},
        }

        # ── Nikto ──────────────────────────────────────
        print_info(f"[ WEB ] Running nikto against {self.base_url} ...")
        nikto_result = self._run_nikto()
        result["nikto"] = nikto_result

        # ── Gobuster ───────────────────────────────────
        if not os.path.exists(self.wordlist):
            result["gobuster"]["error"] = (
                f"Wordlist not found: {self.wordlist}. Install: sudo apt install dirb"
            )
            print_warning(result["gobuster"]["error"])
        else:
            print_info(f"[ WEB ] Running gobuster against {self.base_url} ...")
            gobuster_result = self._run_gobuster()
            result["gobuster"] = gobuster_result

        # ── Display ────────────────────────────────────
        nikto_findings = result["nikto"].get("findings", [])
        gobuster_paths = result["gobuster"].get("paths", [])
        print_web_findings_table(nikto_findings, gobuster_paths)

        total = len(nikto_findings) + len(gobuster_paths)
        status = "success" if total > 0 else "warning"
        print_status_badge("WEB", total, status)

        return result

    # ────────────────────────────────────────────────
    # Nikto
    # ────────────────────────────────────────────────

    def _run_nikto(self) -> dict:
        """Run nikto and parse XML output."""
        result = {"findings": [], "error": None}

        args = [
            "nikto",
            "-h", self.base_url,
            "-Format", "xml",
            "-o", self.nikto_path,
            "-maxtime", "600",
        ]

        rc, stdout, stderr = run_tool(args, timeout=660, verbose=self.verbose)

        if self.verbose and stdout:
            print_verbose("nikto stdout", stdout)

        if rc == -2:
            result["error"] = "nikto not found. Install: sudo apt install nikto"
            print_warning(result["error"])
            return result

        if rc == -1:
            print_warning("nikto timed out after 10 min. Using partial results.")

        if os.path.exists(self.nikto_path):
            try:
                result["findings"] = self._parse_nikto_xml(self.nikto_path)
            except Exception as e:
                result["error"] = f"Failed to parse nikto XML: {str(e)}"
                logger.warning(result["error"])
        else:
            result["error"] = "nikto produced no XML output."

        return result

    def _parse_nikto_xml(self, xml_path: str) -> list:
        """Parse nikto XML output into a list of finding dicts."""
        findings = []
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
        except ET.ParseError as e:
            logger.warning(f"Nikto XML parse error: {e}")
            return findings

        # nikto XML structure varies — handle both <niktoscan> and <scandetails>
        items = root.findall(".//item")
        for item in items:
            def _text(tag: str) -> str:
                elem = item.find(tag)
                return elem.text.strip() if elem is not None and elem.text else ""

            finding = {
                "id": _text("namelink") or _text("osvdbid") or "",
                "path": _text("uri") or _text("url") or "/",
                "method": _text("method") or "GET",
                "description": _text("description"),
                "reference": _text("reference") or _text("namelink") or "",
            }
            if finding["description"]:
                findings.append(finding)

        return findings

    # ────────────────────────────────────────────────
    # Gobuster
    # ────────────────────────────────────────────────

    def _run_gobuster(self) -> dict:
        """Run gobuster dir enumeration and parse output."""
        result = {"paths": [], "error": None}

        args = [
            "gobuster", "dir",
            "-u", self.base_url,
            "-w", self.wordlist,
            "-o", self.gobuster_path,
            "-q",
            "-t", "20",
            "--timeout", "10s",
        ]

        rc, stdout, stderr = run_tool(args, timeout=300, verbose=self.verbose)

        if self.verbose and stdout:
            print_verbose("gobuster stdout", stdout)

        if rc == -2:
            result["error"] = "gobuster not found. Install: sudo apt install gobuster"
            print_warning(result["error"])
            return result

        if rc == -1:
            print_warning("gobuster timed out. Using partial results.")

        if os.path.exists(self.gobuster_path):
            try:
                with open(self.gobuster_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                result["paths"] = self._parse_gobuster_output(content)
            except Exception as e:
                result["error"] = f"Failed to parse gobuster output: {str(e)}"
                logger.warning(result["error"])
        else:
            # Also try parsing stdout if file wasn't written
            if stdout:
                result["paths"] = self._parse_gobuster_output(stdout)

        return result

    def _parse_gobuster_output(self, output: str) -> list:
        """
        Parse gobuster text output into a list of path dicts.

        Format: /path  (Status: 200) [Size: 1234]
        """
        paths = []
        for match in _GOBUSTER_RE.finditer(output):
            paths.append(
                {
                    "path": match.group(1),
                    "status_code": int(match.group(2)),
                    "size": int(match.group(3)),
                }
            )
        return paths

    @staticmethod
    def determine_base_url(target: str, open_ports: list) -> str:
        """
        Determine HTTP base URL from nmap open ports.
        Prefers HTTPS (443) over HTTP (80).
        """
        port_nums = {p.get("port") for p in open_ports}
        if 443 in port_nums:
            return f"https://{target}"
        if 8443 in port_nums:
            return f"https://{target}:8443"
        if 8080 in port_nums:
            return f"http://{target}:8080"
        return f"http://{target}"
