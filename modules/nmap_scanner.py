"""
modules/nmap_scanner.py — Nmap network scanner module for AEGIS

Executes nmap with the appropriate flags for the scan profile,
parses the XML output, and returns a structured dict.
"""

import os
import logging
import xml.etree.ElementTree as ET

from ui.console import print_warning, print_verbose, print_port_table, print_status_badge
from utils.subprocess_utils import run_tool
from utils.file_utils import temp_path

logger = logging.getLogger("aegis")

# Map scan profile → nmap arguments
PROFILE_ARGS = {
    "quick": ["-sV", "-sC", "-p", "1-1000", "--open"],
    "full": ["-sV", "-sC", "-O", "-p-", "--open"],
    "web": ["-sV", "-p", "80,443,8080,8443", "--open"],
    "stealth": ["-sS", "-O", "-p-", "--open", "-T2"],
}

# Services that warrant further investigation
INTERESTING_SERVICES = {
    "ftp", "ssh", "http", "https", "smtp", "smb",
    "microsoft-ds", "netbios-ssn", "mysql", "telnet",
    "rlogin", "rsh", "rexec", "vnc", "rdp", "mssql",
}

# Known vulnerable version strings → CVE hints (for flagging)
INTERESTING_VERSIONS = {
    "vsftpd 2.3.4": "CVE-2011-2523 (backdoor)",
    "openssh 4.7": "CVE-2008-0166 (Debian weak keys)",
    "apache 2.2": "Outdated Apache — multiple CVEs",
    "apache 2.4.49": "CVE-2021-41773 (path traversal/RCE)",
    "openssh 5.": "CVE-2010-4478 (J-PAKE bypass)",
}


class NmapScanner:
    """Executes nmap and returns parsed port/service data."""

    def __init__(self, target: str, profile: str, verbose: bool = False):
        self.target = target
        self.profile = profile
        self.verbose = verbose
        self.xml_path = temp_path("nmap")
        self.timeout = int(os.getenv("AEGIS_NMAP_TIMEOUT", 600))

    def run(self) -> dict:
        """
        Execute nmap scan and return the nmap section of ScanResult.
        Never raises — returns error key on failure.
        """
        result = {
            "raw_xml_path": self.xml_path,
            "os_guess": None,
            "open_ports": [],
            "interesting_services": [],
            "error": None,
        }

        args = self._build_nmap_args()
        if self.verbose:
            print_verbose("nmap command", " ".join(args))

        rc, stdout, stderr = run_tool(args, timeout=self.timeout, verbose=self.verbose)

        if rc == -2:
            result["error"] = "nmap not found on this system. Install: sudo apt install nmap"
            logger.error(result["error"])
            return result

        if rc == -1:
            result["error"] = f"nmap timed out after {self.timeout}s"
            print_warning(result["error"])
            # Still try to parse partial XML if it exists
        elif rc not in (0, 1):
            # nmap returns 1 for some warnings that are non-fatal
            if stderr and "QUITTING" in stderr.upper():
                result["error"] = f"nmap failed (rc={rc}): {stderr[:200]}"
                logger.error(result["error"])
                return result

        # Parse XML
        if os.path.exists(self.xml_path):
            try:
                parsed = self._parse_xml(self.xml_path)
                result.update(parsed)
            except Exception as e:
                result["error"] = f"Failed to parse nmap XML: {str(e)}"
                logger.error(result["error"])
        else:
            result["error"] = "nmap did not produce XML output — may require sudo for -O/-sS flags"
            print_warning(result["error"])

        # Print results
        if result["open_ports"]:
            print_port_table(result["open_ports"])
            print_status_badge("RECON", len(result["open_ports"]), "success")
        else:
            print_warning("No open ports found. Target may be offline or all ports filtered.")
            print_status_badge("RECON", 0, "warning")

        if self.verbose and stdout:
            print_verbose("nmap stdout", stdout)

        return result

    def _build_nmap_args(self) -> list:
        """Return the nmap command as a list of args for the given profile."""
        profile_flags = PROFILE_ARGS.get(self.profile, PROFILE_ARGS["full"])
        return ["nmap"] + profile_flags + ["-oX", self.xml_path, self.target]

    def _parse_xml(self, xml_path: str) -> dict:
        """
        Parse nmap XML output into a structured dict.

        Returns dict with keys: open_ports, os_guess, interesting_services
        """
        tree = ET.parse(xml_path)
        root = tree.getroot()

        open_ports = []
        os_guess = None

        # Parse OS detection
        os_elem = root.find(".//osmatch")
        if os_elem is not None:
            os_guess = os_elem.attrib.get("name")

        # Parse each host
        for host in root.findall("host"):
            # Parse ports
            ports_elem = host.find("ports")
            if ports_elem is None:
                continue

            for port_elem in ports_elem.findall("port"):
                state_elem = port_elem.find("state")
                if state_elem is None:
                    continue
                if state_elem.attrib.get("state") != "open":
                    continue

                service_elem = port_elem.find("service")
                service_name = ""
                version_str = ""

                if service_elem is not None:
                    service_name = service_elem.attrib.get("name", "")
                    product = service_elem.attrib.get("product", "")
                    version = service_elem.attrib.get("version", "")
                    extrainfo = service_elem.attrib.get("extrainfo", "")
                    parts = [p for p in [product, version, extrainfo] if p]
                    version_str = " ".join(parts)

                # Parse NSE scripts
                scripts = {}
                for script_elem in port_elem.findall("script"):
                    scripts[script_elem.attrib.get("id", "")] = script_elem.attrib.get("output", "")

                port_data = {
                    "port": int(port_elem.attrib.get("portid", 0)),
                    "protocol": port_elem.attrib.get("protocol", "tcp"),
                    "service": service_name,
                    "version": version_str,
                    "state": "open",
                    "scripts": scripts,
                }
                open_ports.append(port_data)

        # Sort by port number
        open_ports.sort(key=lambda x: x["port"])

        interesting = self._extract_interesting_services(open_ports)

        return {
            "open_ports": open_ports,
            "os_guess": os_guess,
            "interesting_services": interesting,
        }

    def _extract_interesting_services(self, ports: list) -> list:
        """Flag services worth deeper investigation."""
        flagged = []
        for port in ports:
            service = (port.get("service") or "").lower()
            version = (port.get("version") or "").lower()

            if service in INTERESTING_SERVICES:
                note = service
                # Check for known vulnerable versions
                for ver_key, cve_hint in INTERESTING_VERSIONS.items():
                    if ver_key.lower() in version:
                        note = f"{service} [{cve_hint}]"
                        break
                if note not in flagged:
                    flagged.append(note)

        return flagged
