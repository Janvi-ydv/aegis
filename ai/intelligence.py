"""
ai/intelligence.py — OpenRouter API client for AEGIS

Sends structured scan results to an LLM via OpenRouter's
OpenAI-compatible API. Includes retry logic for 429 and 5xx errors.

OpenRouter supports hundreds of models — default is Qwen2.5-72B-Instruct.
API docs: https://openrouter.ai/docs
"""

import os
import time
import json
import logging

import requests

from ai.prompts import SYSTEM_PROMPT, build_user_message
from ui.console import print_warning, print_info

logger = logging.getLogger("aegis")

# OpenRouter uses the OpenAI-compatible endpoint
OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"

# Default model — free / very capable on OpenRouter
DEFAULT_MODEL = "qwen/qwen2.5-72b-instruct"

# OpenRouter requires these headers for rate-limit attribution
OPENROUTER_APP_NAME = "AEGIS-Vulnerability-Scanner"
OPENROUTER_APP_URL = "https://github.com/username/aegis"


def call_ai_engine(
    scan_result: dict,
    api_key: str,
    max_retries: int = None,
) -> dict | None:
    """
    Call OpenRouter API with structured scan data and return parsed AI result.

    Args:
        scan_result: The full ScanResult dict from the Orchestrator.
        api_key: OpenRouter API key (sk-or-...).
        max_retries: Number of retry attempts (default from env AEGIS_API_RETRIES).

    Returns:
        Parsed dict with keys: risk_level, executive_summary, cves, ttps, findings
        Returns None if all retries fail.
    """
    if not api_key:
        print_warning("No OPENROUTER_API_KEY set. Run 'python aegis.py setup' to configure.")
        logger.warning("AI engine: no API key provided.")
        return None

    if max_retries is None:
        max_retries = int(os.getenv("AEGIS_API_RETRIES", 3))

    timeout = int(os.getenv("AEGIS_API_TIMEOUT", 60))
    model = os.getenv("AEGIS_MODEL", DEFAULT_MODEL)

    user_message = build_user_message(scan_result)

    if os.getenv("AEGIS_DEBUG", "false").lower() == "true":
        logger.debug(f"AI user message:\n{user_message[:2000]}")

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        # OpenRouter attribution headers (recommended, not required)
        "HTTP-Referer": OPENROUTER_APP_URL,
        "X-Title": OPENROUTER_APP_NAME,
    }

    payload = {
        "model": model,
        "max_tokens": 4096,
        "temperature": 0.1,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ],
    }

    for attempt in range(1, max_retries + 1):
        try:
            logger.info(f"AI engine: attempt {attempt}/{max_retries} — model={model}")

            response = requests.post(
                OPENROUTER_API_URL,
                headers=headers,
                json=payload,
                timeout=timeout,
            )

            # Rate limit
            if response.status_code == 429:
                wait = 30 * attempt
                print_warning(
                    f"AI engine rate limited. Retrying in {wait}s... "
                    f"(attempt {attempt}/{max_retries})"
                )
                logger.warning(f"AI engine 429 — waiting {wait}s")
                time.sleep(wait)
                continue

            # Server errors — retry
            if response.status_code >= 500:
                wait = 10 * attempt
                print_warning(
                    f"AI engine server error ({response.status_code}). "
                    f"Retrying in {wait}s... (attempt {attempt}/{max_retries})"
                )
                logger.warning(f"AI engine HTTP {response.status_code}")
                time.sleep(wait)
                continue

            # Client errors — don't retry
            if response.status_code >= 400:
                err_body = ""
                try:
                    err_body = response.json().get("error", {}).get("message", "")
                except Exception:
                    err_body = response.text[:200]
                logger.error(
                    f"AI engine client error {response.status_code}: {err_body}"
                )
                if response.status_code == 401:
                    print_warning(
                        "OpenRouter API key is invalid or expired. "
                        "Run 'python aegis.py setup' to update it."
                    )
                elif response.status_code == 402:
                    print_warning(
                        "OpenRouter account has insufficient credits. "
                        "Visit https://openrouter.ai to top up."
                    )
                else:
                    print_warning(
                        f"AI engine returned {response.status_code}: {err_body}"
                    )
                return None

            response.raise_for_status()

            # Parse response
            content = response.json()["choices"][0]["message"]["content"]
            logger.debug(f"AI raw response (first 500 chars): {content[:500]}")

            # Strip markdown code fences if LLM included them
            content = content.strip()
            if content.startswith("```"):
                content = content.split("```")[1]
                if content.startswith("json"):
                    content = content[4:]
                content = content.strip()

            parsed = json.loads(content)
            _validate_ai_response(parsed)

            logger.info(
                f"AI engine success: risk={parsed.get('risk_level')}, "
                f"cves={len(parsed.get('cves', []))}, "
                f"ttps={len(parsed.get('ttps', []))}"
            )
            return parsed

        except json.JSONDecodeError as e:
            logger.warning(f"AI engine JSON parse error (attempt {attempt}): {e}")
            if attempt < max_retries:
                time.sleep(5)
                continue
            print_warning("AI engine returned malformed JSON after all retries.")
            return None

        except requests.Timeout:
            logger.warning(f"AI engine request timed out (attempt {attempt})")
            if attempt < max_retries:
                time.sleep(10)
                continue
            print_warning("AI engine timed out. Generating report without AI analysis.")
            return None

        except requests.RequestException as e:
            logger.warning(f"AI engine request error (attempt {attempt}): {e}")
            if attempt < max_retries:
                time.sleep(10)
                continue
            print_warning(f"AI engine connection failed: {str(e)}")
            return None

        except Exception as e:
            logger.error(f"AI engine unexpected error (attempt {attempt}): {e}")
            if attempt < max_retries:
                time.sleep(5)
                continue
            return None

    logger.error("AI engine: all retry attempts exhausted.")
    return None


def test_api_connection(api_key: str) -> tuple:
    """
    Send a minimal test request to OpenRouter to verify the API key works.

    Returns:
        (success: bool, message: str)
    """
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": OPENROUTER_APP_URL,
        "X-Title": OPENROUTER_APP_NAME,
    }
    payload = {
        "model": os.getenv("AEGIS_MODEL", DEFAULT_MODEL),
        "max_tokens": 10,
        "messages": [{"role": "user", "content": "Reply with: OK"}],
    }
    try:
        resp = requests.post(
            OPENROUTER_API_URL,
            headers=headers,
            json=payload,
            timeout=20,
        )
        if resp.status_code == 200:
            return True, "API key verified successfully."
        elif resp.status_code == 401:
            return False, "Invalid API key — authentication failed."
        elif resp.status_code == 402:
            return False, "API key valid but account has no credits."
        elif resp.status_code == 429:
            return True, "API key valid (rate limited — this is expected on free tier)."
        else:
            try:
                err = resp.json().get("error", {}).get("message", resp.text[:100])
            except Exception:
                err = resp.text[:100]
            return False, f"API returned {resp.status_code}: {err}"
    except requests.Timeout:
        return False, "Connection timed out — check your internet connection."
    except requests.RequestException as e:
        return False, f"Connection error: {str(e)}"


def _validate_ai_response(data: dict) -> None:
    """
    Validate that the AI response has the required top-level keys.
    Raises ValueError if the structure is invalid.
    """
    required_keys = {"risk_level", "executive_summary", "cves", "ttps", "findings"}
    missing = required_keys - set(data.keys())
    if missing:
        raise ValueError(f"AI response missing required keys: {missing}")

    valid_risk = {"Critical", "High", "Medium", "Low"}
    if data.get("risk_level") not in valid_risk:
        rl = str(data.get("risk_level", "")).strip().title()
        if rl in valid_risk:
            data["risk_level"] = rl
        else:
            data["risk_level"] = "High"

    for key in ("cves", "ttps", "findings"):
        if not isinstance(data.get(key), list):
            data[key] = []
