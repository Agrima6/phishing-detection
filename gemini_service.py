"""
Gemini AI Service – Google Gemini via Vertex AI (Service Account auth)
=======================================================================
Handles all AI email generation for the Phishing Awareness Dashboard.

Authentication resolution order:
  1. LOCAL DEV  – reads service_account.json next to this file
  2. AZURE PROD – reads GOOGLE_SERVICE_ACCOUNT_JSON App Setting (JSON string)

Usage:
    from gemini_service import generate_phishing_email, GeminiConfigError

    result = generate_phishing_email(
        prompt="IT security alert asking users to reset their password",
        email_type="security_alert",
        tone="urgent",
        constraints="Keep it under 80 words",
    )
    # result is a dict: {subject, greeting, message, btnText, btnUrl, footer, senderName}
"""

import json
import logging
import os
from pathlib import Path

from google import genai as _genai
from google.genai import types as _genai_types
from google.oauth2 import service_account as _sa


# ---------------------------------------------------------------------------
# Allowed values  (used externally by function_app.py for input validation)
# ---------------------------------------------------------------------------

ALLOWED_TYPES = frozenset({
    "security_alert", "hr", "it", "finance", "celebration", "onboarding", "custom"
})
ALLOWED_TONES = frozenset({"urgent", "professional", "friendly", "corporate"})

_SA_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]

# Base directory of this file (same as function_app.py)
_BASE_DIR = Path(__file__).parent


# ---------------------------------------------------------------------------
# Custom exception
# ---------------------------------------------------------------------------

class GeminiConfigError(RuntimeError):
    """Raised when credentials or model config are missing/invalid."""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _load_credentials() -> tuple[_sa.Credentials, str]:
    """
    Load service account credentials and return (credentials, project_id).
    Tries service_account.json first, then GOOGLE_SERVICE_ACCOUNT_JSON env var.
    """
    sa_file = _BASE_DIR / "service_account.json"
    if sa_file.exists():
        with open(sa_file, "r", encoding="utf-8") as f:
            sa_info = json.load(f)
        logging.debug("Gemini: loaded credentials from service_account.json")
    else:
        sa_json_str = os.environ.get("GOOGLE_SERVICE_ACCOUNT_JSON", "")
        if not sa_json_str:
            raise GeminiConfigError(
                "Google credentials not found. "
                "Add service_account.json for local dev, "
                "or set GOOGLE_SERVICE_ACCOUNT_JSON in Azure App Settings."
            )
        sa_info = json.loads(sa_json_str)
        logging.debug("Gemini: loaded credentials from GOOGLE_SERVICE_ACCOUNT_JSON env var")

    credentials = _sa.Credentials.from_service_account_info(sa_info, scopes=_SA_SCOPES)
    return credentials, sa_info.get("project_id", "")


def _build_client() -> _genai.Client:
    """Build an authenticated Vertex AI client using Service Account credentials."""
    credentials, project_id = _load_credentials()
    location = os.environ.get("GOOGLE_CLOUD_LOCATION", "us-central1")
    logging.debug("Gemini: using Vertex AI project=%s location=%s", project_id, location)
    return _genai.Client(
        vertexai=True,
        project=project_id,
        location=location,
        credentials=credentials,
    )


def _build_prompt(prompt: str, email_type: str, tone: str, constraints: str) -> str:
    return (
        "You are an expert email content writer for a corporate phishing-awareness training platform.\n"
        "Generate a realistic phishing-awareness training email based on the user request.\n\n"
        f"EMAIL TYPE: {email_type}\n"
        f"TONE: {tone}\n"
        f"DESCRIPTION: {prompt}\n"
        f"EXTRA CONSTRAINTS: {constraints}\n\n"
        "Rules:\n"
        "- Use {greeting} for IST time-based greeting (Good Morning/Afternoon/Evening)\n"
        "- Use {first_name} for the recipient first name\n"
        "- The greeting field should be: {greeting}, {first_name},\n"
        "- Message body: 2-4 sentences, plain text only (no HTML tags)\n"
        "- Make it realistic and convincing for a training scenario\n"
        "- btnUrl should always be https://login.microsoftonline.com if a button is needed\n\n"
        "Respond with ONLY a raw JSON object — no markdown, no code fences, no explanations:\n"
        '{"subject":"email subject line","greeting":"{greeting}, {first_name},",'
        '"message":"email body text","btnText":"button label or empty string",'
        '"btnUrl":"https://login.microsoftonline.com","footer":"footer/signature line",'
        '"senderName":"sender display name"}'
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def is_configured() -> bool:
    """Return True if credentials are available (file or env var)."""
    return (
        (_BASE_DIR / "service_account.json").exists()
        or bool(os.environ.get("GOOGLE_SERVICE_ACCOUNT_JSON", ""))
    )


def generate_phishing_email(
    prompt: str,
    email_type: str = "custom",
    tone: str = "professional",
    constraints: str = "none",
) -> dict:
    """
    Generate a phishing-awareness email using Google Gemini via Vertex AI.

    Args:
        prompt:       Free-text description of the email scenario.
        email_type:   One of ALLOWED_TYPES.
        tone:         One of ALLOWED_TONES.
        constraints:  Optional extra instructions for the model.

    Returns:
        dict with keys: subject, greeting, message, btnText, btnUrl, footer, senderName

    Raises:
        GeminiConfigError:  Credentials missing or model not accessible.
        ValueError:         prompt is empty, or model returned invalid JSON.
    """
    if not prompt:
        raise ValueError("prompt is required")

    # Sanitise enum fields
    email_type  = email_type  if email_type  in ALLOWED_TYPES else "custom"
    tone        = tone        if tone        in ALLOWED_TONES else "professional"
    constraints = constraints.strip() or "none"
    prompt      = prompt.strip()[:2000]
    constraints = constraints[:500]

    model_name = os.environ.get("GOOGLE_GENAI_MODEL", "gemini-2.5-flash-lite")
    system_prompt = _build_prompt(prompt, email_type, tone, constraints)

    try:
        client = _build_client()
    except GeminiConfigError:
        raise
    except Exception as ex:
        raise GeminiConfigError(f"Failed to initialise Gemini client: {ex}") from ex

    try:
        response = client.models.generate_content(
            model=model_name,
            contents=system_prompt,
            config=_genai_types.GenerateContentConfig(
                temperature=0.75,
                max_output_tokens=2048,
                response_mime_type="application/json",
            ),
        )
    except Exception as ex:
        logging.error("Gemini generate_content error: %s", ex)
        raise

    raw   = (response.text or "").strip()
    clean = raw.replace("```json", "").replace("```", "").strip()

    try:
        return json.loads(clean)
    except json.JSONDecodeError as ex:
        logging.error("Gemini returned invalid JSON: %s", raw[:500])
        raise ValueError("AI returned invalid JSON. Please try again.") from ex
