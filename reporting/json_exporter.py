"""
reporting/json_exporter.py — JSON export for AEGIS scan results
"""

import json
import os
import logging

logger = logging.getLogger("aegis")


def export_json(scan_result: dict, output_path: str) -> str:
    """Serialize the full ScanResult to a formatted JSON file."""
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(scan_result, f, indent=2, ensure_ascii=False, default=str)
    logger.info(f"JSON report saved: {output_path}")
    return output_path
