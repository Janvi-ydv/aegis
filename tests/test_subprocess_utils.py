"""
tests/test_subprocess_utils.py — Unit tests for utils/subprocess_utils.py
"""

import pytest
from utils.subprocess_utils import run_tool


class TestRunTool:
    def test_valid_command_returns_zero(self):
        """A valid command should return rc=0."""
        # Use 'python' with -c as it works cross-platform
        import sys
        rc, stdout, stderr = run_tool([sys.executable, "-c", "print('hello')"])
        assert rc == 0
        assert "hello" in stdout

    def test_stdout_captured(self):
        import sys
        rc, stdout, stderr = run_tool(
            [sys.executable, "-c", "print('aegis_test_output')"]
        )
        assert "aegis_test_output" in stdout

    def test_command_not_found_returns_minus_two(self):
        rc, stdout, stderr = run_tool(["nonexistent_command_aegis_12345"])
        assert rc == -2
        assert "not found" in stderr.lower() or "Command not found" in stderr

    def test_timeout_returns_minus_one(self):
        import sys
        rc, stdout, stderr = run_tool(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            timeout=1,
        )
        assert rc == -1
        assert "timed out" in stderr.lower()

    def test_nonzero_exit_code(self):
        import sys
        rc, stdout, stderr = run_tool(
            [sys.executable, "-c", "import sys; sys.exit(2)"]
        )
        assert rc == 2

    def test_returns_tuple_of_three(self):
        import sys
        result = run_tool([sys.executable, "--version"])
        assert isinstance(result, tuple)
        assert len(result) == 3

    def test_shell_false_enforced(self):
        """Verify shell injection is not possible — shell=False means list args only."""
        # Passing a string that would be dangerous with shell=True
        # but is benign as a literal command name with shell=False
        rc, stdout, stderr = run_tool(["echo && echo injected"])
        # Should fail to find command (no shell expansion)
        assert rc in (-2, 1, 2, -99)  # Some failure code
