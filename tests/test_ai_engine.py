"""
tests/test_ai_engine.py — Unit tests for ai/intelligence.py

Uses unittest.mock to simulate OpenRouter API responses.
No real API calls are made.
"""

import json
import pytest
from unittest.mock import patch, MagicMock

from ai.intelligence import call_ai_engine, _validate_ai_response

# ── Mock response fixtures ────────────────────────────────────────────────

MOCK_VALID_AI_RESPONSE = {
    "risk_level": "Critical",
    "executive_summary": (
        "The target exposes multiple critical vulnerabilities including a vsftpd 2.3.4 "
        "backdoor and unauthenticated MySQL access."
    ),
    "cves": [
        {
            "id": "CVE-2011-2523",
            "cvss": "10.0",
            "service": "ftp:vsftpd 2.3.4",
            "description": "vsftpd 2.3.4 backdoor — remote code execution via port 6200",
            "recommendation": "Upgrade vsftpd to 2.3.5 or later immediately.",
        }
    ],
    "ttps": [
        {
            "id": "T1190",
            "name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
        },
        {
            "id": "T1110.001",
            "name": "Brute Force: Password Guessing",
            "tactic": "Credential Access",
        },
    ],
    "findings": [
        {
            "title": "vsftpd 2.3.4 Backdoor",
            "severity": "Critical",
            "description": "The FTP service is running vsftpd 2.3.4 which contains a deliberate backdoor.",
            "recommendation": "Immediately upgrade vsftpd and audit all systems.",
        }
    ],
}

MINIMAL_SCAN_RESULT = {
    "meta": {
        "target": "192.168.56.101",
        "profile": "full",
        "scan_start": "2026-04-26T14:00:00",
    },
    "nmap": {
        "open_ports": [
            {"port": 21, "protocol": "tcp", "service": "ftp", "version": "vsftpd 2.3.4", "state": "open", "scripts": {}}
        ],
        "os_guess": "Linux 2.6.X",
        "interesting_services": ["ftp [CVE-2011-2523 (backdoor)]"],
        "error": None,
    },
    "web": {"enabled": False, "base_url": None, "nikto": {"findings": [], "error": None}, "gobuster": {"paths": [], "error": None}},
    "smb": {"enabled": False},
    "ftp": {"enabled": True, "anonymous_login": True, "banner": "220 (vsFTPd 2.3.4)", "accessible_files": [], "error": None},
    "ssh": {"enabled": False},
    "mysql": {"enabled": False},
    "ai": {"enabled": False},
    "errors": [],
}


def _make_mock_response(body: dict, status_code: int = 200):
    """Build a mock requests.Response object."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.json.return_value = {
        "choices": [{"message": {"content": json.dumps(body)}}]
    }
    mock_resp.raise_for_status = MagicMock()
    return mock_resp


# ── Tests ─────────────────────────────────────────────────────────────────

class TestCallAiEngine:
    def test_success_returns_parsed_result(self):
        with patch("requests.post") as mock_post:
            mock_post.return_value = _make_mock_response(MOCK_VALID_AI_RESPONSE)
            result = call_ai_engine(MINIMAL_SCAN_RESULT, "fake_api_key")

        assert result is not None
        assert result["risk_level"] == "Critical"

    def test_cve_list_returned(self):
        with patch("requests.post") as mock_post:
            mock_post.return_value = _make_mock_response(MOCK_VALID_AI_RESPONSE)
            result = call_ai_engine(MINIMAL_SCAN_RESULT, "fake_api_key")

        assert len(result["cves"]) == 1
        assert result["cves"][0]["id"] == "CVE-2011-2523"

    def test_ttp_list_returned(self):
        with patch("requests.post") as mock_post:
            mock_post.return_value = _make_mock_response(MOCK_VALID_AI_RESPONSE)
            result = call_ai_engine(MINIMAL_SCAN_RESULT, "fake_api_key")

        assert len(result["ttps"]) == 2
        assert result["ttps"][0]["id"] == "T1190"

    def test_no_api_key_returns_none(self):
        result = call_ai_engine(MINIMAL_SCAN_RESULT, "")
        assert result is None

    def test_connection_error_returns_none_after_retries(self):
        import requests as req
        with patch("requests.post") as mock_post:
            mock_post.side_effect = req.RequestException("Connection refused")
            result = call_ai_engine(MINIMAL_SCAN_RESULT, "fake_key", max_retries=1)

        assert result is None

    def test_malformed_json_returns_none_after_retries(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "NOT VALID JSON {{{{"}}]
        }
        mock_resp.raise_for_status = MagicMock()

        with patch("requests.post") as mock_post:
            mock_post.return_value = mock_resp
            result = call_ai_engine(MINIMAL_SCAN_RESULT, "fake_key", max_retries=1)

        assert result is None

    def test_rate_limit_retries_and_succeeds(self):
        """First call returns 429, second call succeeds."""
        rate_limit_resp = MagicMock()
        rate_limit_resp.status_code = 429
        rate_limit_resp.raise_for_status = MagicMock()

        success_resp = _make_mock_response(MOCK_VALID_AI_RESPONSE, status_code=200)

        with patch("requests.post") as mock_post, patch("time.sleep"):
            mock_post.side_effect = [rate_limit_resp, success_resp]
            result = call_ai_engine(MINIMAL_SCAN_RESULT, "fake_key", max_retries=3)

        assert result is not None
        assert result["risk_level"] == "Critical"

    def test_500_error_retries(self):
        server_error = MagicMock()
        server_error.status_code = 500
        server_error.raise_for_status = MagicMock()

        with patch("requests.post") as mock_post, patch("time.sleep"):
            mock_post.return_value = server_error
            result = call_ai_engine(MINIMAL_SCAN_RESULT, "fake_key", max_retries=2)

        assert result is None

    def test_json_with_markdown_fences_is_parsed(self):
        """LLM sometimes wraps response in ```json ... ``` — should still parse."""
        wrapped_content = f"```json\n{json.dumps(MOCK_VALID_AI_RESPONSE)}\n```"
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": wrapped_content}}]
        }
        mock_resp.raise_for_status = MagicMock()

        with patch("requests.post") as mock_post:
            mock_post.return_value = mock_resp
            result = call_ai_engine(MINIMAL_SCAN_RESULT, "fake_key")

        assert result is not None
        assert result["risk_level"] == "Critical"


class TestValidateAiResponse:
    def test_valid_response_passes(self):
        data = {
            "risk_level": "High",
            "executive_summary": "test",
            "cves": [],
            "ttps": [],
            "findings": [],
        }
        _validate_ai_response(data)  # Should not raise

    def test_missing_key_raises(self):
        data = {"risk_level": "High"}
        with pytest.raises(ValueError):
            _validate_ai_response(data)

    def test_invalid_risk_level_normalized(self):
        data = {
            "risk_level": "critical",  # lowercase
            "executive_summary": "test",
            "cves": [],
            "ttps": [],
            "findings": [],
        }
        _validate_ai_response(data)
        assert data["risk_level"] == "Critical"

    def test_non_list_cves_normalized(self):
        data = {
            "risk_level": "High",
            "executive_summary": "test",
            "cves": "not a list",
            "ttps": [],
            "findings": [],
        }
        _validate_ai_response(data)
        assert isinstance(data["cves"], list)
