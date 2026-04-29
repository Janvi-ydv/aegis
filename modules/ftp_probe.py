"""
modules/ftp_probe.py — FTP anonymous login probe for AEGIS

Tests anonymous FTP login using Python's stdlib ftplib.
Flags vsftpd 2.3.4 backdoor (CVE-2011-2523).
"""

import ftplib
import socket
import logging

from ui.console import print_warning, print_service_result, print_status_badge

logger = logging.getLogger("aegis")

# Known vulnerable FTP versions → CVE hints
KNOWN_VULNERABLE_FTP = {
    "vsftpd 2.3.4": "CVE-2011-2523 (backdoor — port 6200 may be open)",
    "proftpd 1.3.3": "CVE-2010-4221 (buffer overflow)",
}


class FtpProbe:
    """Tests FTP anonymous login and checks for known vulnerabilities."""

    def __init__(self, target: str, verbose: bool = False):
        self.target = target
        self.verbose = verbose

    def run(self) -> dict:
        """
        Probe FTP service and return the ftp section of ScanResult.
        Never raises — catches all exceptions internally.
        """
        result = {
            "enabled": True,
            "anonymous_login": False,
            "banner": None,
            "accessible_files": [],
            "known_cves": [],
            "notes": None,
            "error": None,
        }

        try:
            anonymous_ok, banner, files = self._test_anonymous_login()
            result["anonymous_login"] = anonymous_ok
            result["banner"] = banner
            result["accessible_files"] = files[:20]  # Cap at 20

            # Check for known vulnerable versions from banner
            if banner:
                for version_str, cve_hint in KNOWN_VULNERABLE_FTP.items():
                    if version_str.lower() in banner.lower():
                        result["known_cves"].append(
                            cve_hint.split(" ")[0]
                        )
                        result["notes"] = (
                            f"{version_str} detected: {cve_hint}"
                        )
                        logger.warning(f"FTP: {result['notes']}")
                        break

        except Exception as e:
            result["error"] = f"FTP probe error: {str(e)}"
            logger.warning(result["error"])

        if self.verbose:
            logger.debug(f"FTP result: {result}")

        # Display
        print_service_result("FTP", result)
        findings = (1 if result["anonymous_login"] else 0) + len(result["known_cves"])
        status = "warning" if result["anonymous_login"] else "success"
        print_status_badge("FTP", findings, status)

        return result

    def _test_anonymous_login(self) -> tuple:
        """
        Attempt anonymous FTP login.

        Returns:
            (success: bool, banner: str | None, files: list[str])
        """
        banner = None
        files = []

        try:
            ftp = ftplib.FTP()
            ftp.connect(self.target, 21, timeout=10)
            banner = ftp.getwelcome()

            try:
                ftp.login("anonymous", "anonymous@example.com")
                # Successfully logged in
                try:
                    files = ftp.nlst()
                except Exception:
                    files = []
                finally:
                    ftp.quit()
                return True, banner, files

            except ftplib.error_perm:
                # 530 Login incorrect — anonymous not allowed
                try:
                    ftp.quit()
                except Exception:
                    pass
                return False, banner, []

        except ConnectionRefusedError:
            return False, None, []
        except socket.timeout:
            return False, None, []
        except OSError as e:
            logger.debug(f"FTP connection error: {e}")
            return False, None, []
