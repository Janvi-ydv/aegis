"""
utils/file_utils.py — Temp file management and path utilities for AEGIS
"""

import os
import logging

logger = logging.getLogger("aegis")

# Temp file paths used across modules
TEMP_FILES = {
    "nmap": "/tmp/aegis_nmap.xml",
    "nikto": "/tmp/aegis_nikto.xml",
    "gobuster": "/tmp/aegis_gobuster.txt",
    "smb": "/tmp/aegis_smb.txt",
}


def cleanup_temp_files() -> None:
    """
    Remove all AEGIS temp files from /tmp.
    Called at end of orchestrator run() regardless of success/failure.
    """
    for name, path in TEMP_FILES.items():
        try:
            if os.path.exists(path):
                os.remove(path)
                logger.debug(f"Cleaned up temp file: {path}")
        except OSError as e:
            logger.warning(f"Could not delete temp file {path}: {e}")


def ensure_reports_dir(reports_dir: str = "./reports") -> str:
    """
    Create reports directory if it doesn't exist.
    Returns the absolute path to the reports directory.
    """
    abs_path = os.path.abspath(reports_dir)
    os.makedirs(abs_path, exist_ok=True)
    return abs_path


def build_report_path(target: str, output_format: str, reports_dir: str = "./reports") -> str:
    """
    Build a timestamped report output path.

    Args:
        target: Target IP/hostname
        output_format: 'pdf', 'json', or 'markdown'
        reports_dir: Directory to write report into

    Returns:
        Absolute path string like: /abs/path/reports/192.168.1.1_20260426_143022.pdf
    """
    from datetime import datetime

    ext_map = {"pdf": "pdf", "json": "json", "markdown": "md"}
    ext = ext_map.get(output_format, "pdf")

    # Sanitize target for filename
    safe_target = target.replace(":", "_").replace("/", "_").replace("\\", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{safe_target}_{timestamp}.{ext}"

    abs_reports = ensure_reports_dir(reports_dir)
    return os.path.join(abs_reports, filename)


def temp_path(module: str) -> str:
    """Return the temp file path for a given module name."""
    return TEMP_FILES.get(module, f"/tmp/aegis_{module}.tmp")
