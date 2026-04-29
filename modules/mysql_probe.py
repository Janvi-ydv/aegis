"""
modules/mysql_probe.py — MySQL default credential probe for AEGIS

Tests a list of common default credentials against MySQL port 3306.
Uses PyMySQL if available, falls back gracefully if not installed.
"""

import logging

from ui.console import print_service_result, print_status_badge, print_warning

logger = logging.getLogger("aegis")

# Default credentials to test (user, password)
DEFAULT_CREDENTIALS = [
    ("root", ""),
    ("root", "root"),
    ("root", "toor"),
    ("root", "mysql"),
    ("root", "password"),
    ("admin", "admin"),
    ("admin", ""),
    ("mysql", "mysql"),
]


class MySqlProbe:
    """Tests MySQL default credentials using PyMySQL."""

    def __init__(self, target: str, verbose: bool = False):
        self.target = target
        self.verbose = verbose

    def run(self) -> dict:
        """
        Probe MySQL service and return the mysql section of ScanResult.
        Never raises — catches all exceptions internally.
        """
        result = {
            "enabled": True,
            "accessible": False,
            "credentials_found": None,
            "error": None,
        }

        try:
            import pymysql  # noqa: F401
            accessible, creds = self._test_credentials()
            result["accessible"] = accessible
            result["credentials_found"] = creds

            if accessible:
                logger.warning(f"MySQL accessible on {self.target} with: {creds}")
            elif self.verbose:
                logger.debug(f"MySQL: no default credentials worked on {self.target}")

        except ImportError:
            result["error"] = "PyMySQL not installed — skipping MySQL probe. Run: pip install PyMySQL"
            print_warning(result["error"])
        except Exception as e:
            result["error"] = f"MySQL probe error: {str(e)}"
            logger.warning(result["error"])

        # Display
        print_service_result("MYSQL", result)
        findings = 1 if result["accessible"] else 0
        status = "warning" if result["accessible"] else "success"
        print_status_badge("MYSQL", findings, status)

        return result

    def _test_credentials(self) -> tuple:
        """
        Attempt to connect with each credential pair.

        Returns:
            (accessible: bool, "user:pass" | None)
        """
        import pymysql

        for user, password in DEFAULT_CREDENTIALS:
            try:
                conn = pymysql.connect(
                    host=self.target,
                    port=3306,
                    user=user,
                    password=password,
                    connect_timeout=5,
                    read_timeout=5,
                )
                conn.close()
                cred_str = f"{user}:{password if password else '(empty)'}"
                logger.warning(f"MySQL default creds work: {cred_str}")
                return True, cred_str

            except pymysql.err.OperationalError as e:
                # 1045 = Access denied — expected for wrong credentials
                # 2003 = Can't connect — port not open or firewall
                err_code = e.args[0] if e.args else 0
                if err_code == 2003:
                    # Port not reachable — no point trying more credentials
                    logger.debug(f"MySQL port 3306 not reachable on {self.target}")
                    return False, None
                continue

            except Exception as e:
                logger.debug(f"MySQL credential test error: {e}")
                continue

        return False, None
