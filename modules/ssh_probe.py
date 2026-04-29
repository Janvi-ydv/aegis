"""
modules/ssh_probe.py — SSH banner grab and version analysis for AEGIS

Grabs the SSH service banner via TCP socket and checks the version
against a table of known-vulnerable OpenSSH versions.
"""

import socket
import re
import logging

from ui.console import print_service_result, print_status_badge, print_warning

logger = logging.getLogger("aegis")

# Known vulnerable SSH version strings → list of CVE IDs
KNOWN_VULNERABLE_SSH = {
    "OpenSSH_4.7": ["CVE-2008-0166"],        # Debian weak key generation
    "OpenSSH_4.":  ["CVE-2008-0166"],
    "OpenSSH_5.":  ["CVE-2010-4478"],        # J-PAKE auth bypass
    "OpenSSH_6.":  ["CVE-2014-1692"],        # Memory corruption
    "OpenSSH_7.2": ["CVE-2016-0777"],        # Roaming info leak
    "OpenSSH_7.":  ["CVE-2018-15473"],       # Username enumeration
    "dropbear_0.": ["CVE-2012-0920"],        # Use-after-free
}

# Weak algorithms commonly found in old SSH servers
WEAK_ALGORITHMS = ["diffie-hellman-group1-sha1", "arcfour", "des-cbc", "blowfish-cbc"]

# SSH version string extraction regex
_SSH_VERSION_RE = re.compile(r"SSH-[\d\.]+-([^\r\n]+)", re.IGNORECASE)


class SshProbe:
    """Grabs SSH banner and checks version against known-vulnerable list."""

    def __init__(self, target: str, verbose: bool = False):
        self.target = target
        self.verbose = verbose

    def run(self) -> dict:
        """
        Probe SSH service and return the ssh section of ScanResult.
        Never raises — catches all exceptions internally.
        """
        result = {
            "enabled": True,
            "banner": None,
            "version": None,
            "weak_algorithms": [],
            "known_cves": [],
            "error": None,
        }

        try:
            banner = self._grab_banner()
            if banner:
                result["banner"] = banner
                result["version"] = self._extract_version(banner)
                cves, weak_algos = self._check_version(banner)
                result["known_cves"] = cves
                result["weak_algorithms"] = weak_algos

                if self.verbose:
                    logger.debug(f"SSH banner: {banner}")
                    logger.debug(f"SSH CVEs detected: {cves}")
            else:
                result["error"] = "No SSH banner received — port may be filtered."

        except Exception as e:
            result["error"] = f"SSH probe error: {str(e)}"
            logger.warning(result["error"])

        # Display
        print_service_result("SSH", result)
        findings = len(result["known_cves"]) + len(result["weak_algorithms"])
        status = "warning" if findings > 0 else "success"
        print_status_badge("SSH", findings, status)

        return result

    def _grab_banner(self) -> str | None:
        """Open TCP connection to port 22 and read the SSH banner line."""
        try:
            with socket.create_connection((self.target, 22), timeout=10) as sock:
                data = sock.recv(1024)
                return data.decode("utf-8", errors="replace").strip()
        except (ConnectionRefusedError, socket.timeout, OSError) as e:
            logger.debug(f"SSH banner grab failed: {e}")
            return None

    def _extract_version(self, banner: str) -> str | None:
        """
        Extract version string from SSH banner.
        Example banner: SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1
        """
        match = _SSH_VERSION_RE.search(banner)
        return match.group(1).strip() if match else banner.strip()

    def _check_version(self, banner: str) -> tuple:
        """
        Compare banner against known-vulnerable SSH versions.

        Returns:
            (known_cves: list[str], weak_algorithms: list[str])
        """
        cves = []
        # Check known vulnerable version strings (most specific first)
        for version_key, cve_ids in KNOWN_VULNERABLE_SSH.items():
            if version_key in banner:
                for cve in cve_ids:
                    if cve not in cves:
                        cves.append(cve)

        # Report weak algorithms only if OpenSSH < 7 (common indicator)
        weak_algos = []
        if any(old in banner for old in ["OpenSSH_4.", "OpenSSH_5.", "OpenSSH_6."]):
            weak_algos = ["diffie-hellman-group1-sha1", "arcfour"]

        return cves, weak_algos
