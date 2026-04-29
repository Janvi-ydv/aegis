"""
modules/smb_enum.py — SMB enumeration module for AEGIS

Runs enum4linux against targets with open SMB ports (139/445),
parses shares, users, OS version, workgroup, and null session status.
"""

import re
import logging

from ui.console import print_warning, print_verbose, print_smb_table, print_status_badge
from utils.subprocess_utils import run_tool

logger = logging.getLogger("aegis")

# ── Parsing patterns ──────────────────────────────────────────────────

# Shares: lines in share table after header
_SHARES_RE = re.compile(
    r"^\s{2,}(\S+)\s+(Disk|IPC|Printer|Print-Queue)\s*(.*?)\s*$",
    re.MULTILINE | re.IGNORECASE,
)

# Users: user:[username] rid:[xxx]
_USERS_RE = re.compile(r"user:\[(.+?)\]", re.IGNORECASE)

# Null session patterns
_NULL_SESSION_RE = re.compile(
    r"(Session Check Ok|allows sessions|null session|anonymous logon)",
    re.IGNORECASE,
)

# OS string: OS=[Windows ...] or just OS=
_OS_RE = re.compile(r"OS=\[([^\]]+)\]", re.IGNORECASE)

# Workgroup
_WORKGROUP_RE = re.compile(r"Workgroup=\[([^\]]+)\]", re.IGNORECASE)


class SmbEnum:
    """Runs enum4linux and returns parsed SMB data."""

    def __init__(self, target: str, verbose: bool = False):
        self.target = target
        self.verbose = verbose

    def run(self) -> dict:
        """
        Execute enum4linux and return the smb section of ScanResult.
        Never raises — catches all exceptions internally.
        """
        result = {
            "enabled": True,
            "shares": [],
            "users": [],
            "os_version": None,
            "workgroup": None,
            "null_session": False,
            "error": None,
        }

        raw_output = self._run_enum4linux()

        if raw_output is None:
            result["error"] = "enum4linux not found. Install: sudo apt install enum4linux"
            print_warning(result["error"])
            print_status_badge("SMB", 0, "error")
            return result

        if not raw_output.strip():
            result["error"] = "enum4linux produced no output — target may not have SMB."
            print_warning(result["error"])
            print_status_badge("SMB", 0, "warning")
            return result

        # Parse all fields
        result["shares"] = self._parse_shares(raw_output)
        result["users"] = self._parse_users(raw_output)
        result["null_session"] = self._check_null_session(raw_output)
        result["os_version"] = self._extract_os(raw_output)
        result["workgroup"] = self._extract_workgroup(raw_output)

        if self.verbose:
            print_verbose("enum4linux output", raw_output[:3000])

        # Display
        print_smb_table(result)
        total = len(result["shares"]) + len(result["users"])
        status = "warning" if result["null_session"] else "success"
        print_status_badge("SMB", total, status)

        return result

    def _run_enum4linux(self):
        """Run enum4linux -a and return stdout string, or None if not found."""
        args = ["enum4linux", "-a", self.target]
        rc, stdout, stderr = run_tool(args, timeout=120, verbose=self.verbose)

        if rc == -2:
            return None  # Not found
        if rc == -1:
            print_warning("enum4linux timed out after 120s. Using partial output.")

        return stdout

    def _parse_shares(self, output: str) -> list:
        """Extract share information from enum4linux output."""
        shares = []
        seen = set()

        for match in _SHARES_RE.finditer(output):
            name = match.group(1).strip()
            share_type = match.group(2).strip()
            comment = match.group(3).strip()

            if name not in seen:
                seen.add(name)
                shares.append({
                    "name": name,
                    "type": share_type,
                    "comment": comment,
                })

        return shares

    def _parse_users(self, output: str) -> list:
        """Extract usernames from enum4linux output."""
        users = list(set(_USERS_RE.findall(output)))
        users.sort()
        return users

    def _check_null_session(self, output: str) -> bool:
        """Returns True if enum4linux detected a null session."""
        return bool(_NULL_SESSION_RE.search(output))

    def _extract_os(self, output: str) -> str | None:
        """Extract OS version from enum4linux output."""
        match = _OS_RE.search(output)
        return match.group(1).strip() if match else None

    def _extract_workgroup(self, output: str) -> str | None:
        """Extract workgroup from enum4linux output."""
        match = _WORKGROUP_RE.search(output)
        return match.group(1).strip() if match else None
