"""
utils/subprocess_utils.py — Safe subprocess wrapper for AEGIS

All external tool execution goes through run_tool().
Never use subprocess.run() directly in modules.
"""

import subprocess
import logging

from ui.console import print_info

logger = logging.getLogger("aegis")


def run_tool(
    args: list,
    timeout: int = 600,
    capture_output: bool = True,
    verbose: bool = False,
) -> tuple:
    """
    Safe subprocess wrapper.

    Args:
        args: Command as list — NEVER as string with shell=True.
        timeout: Max seconds before TimeoutExpired (default 600).
        capture_output: Capture stdout/stderr (default True).
        verbose: Print command before running.

    Returns:
        (returncode: int, stdout: str, stderr: str)

    Never raises — catches all exceptions and returns error in stderr.
    Exit code conventions:
        -1  = timeout
        -2  = command not found
        -3  = permission denied
        -99 = unexpected error
    """
    if verbose:
        print_info(f"[CMD] {' '.join(str(a) for a in args)}")
        logger.debug(f"[CMD] {' '.join(str(a) for a in args)}")

    try:
        result = subprocess.run(
            args,
            capture_output=capture_output,
            text=True,
            timeout=timeout,
            shell=False,  # NEVER True — prevents shell injection
        )
        if verbose and result.stdout:
            logger.debug(f"[STDOUT] {result.stdout[:500]}")
        return result.returncode, result.stdout, result.stderr

    except subprocess.TimeoutExpired:
        msg = f"Command timed out after {timeout}s: {args[0]}"
        logger.warning(msg)
        return -1, "", msg

    except FileNotFoundError:
        msg = f"Command not found: {args[0]}"
        logger.error(msg)
        return -2, "", msg

    except PermissionError:
        msg = f"Permission denied: {args[0]} — may require sudo"
        logger.error(msg)
        return -3, "", msg

    except Exception as e:
        msg = f"Unexpected error running {args[0]}: {str(e)}"
        logger.error(msg)
        return -99, "", msg
