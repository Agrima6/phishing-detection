"""
Phishing Awareness Dashboard – Flask Container App
"""

import json
import logging
import os
import random
import re
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Load .env file for local development (no-op if file absent or python-dotenv not installed)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import smtplib
import base64
import dns.resolver
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.utils import formataddr

from flask import Flask, request, jsonify, make_response, Response, send_from_directory, session as flask_session
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, From, To, Subject, HtmlContent

from gemini_service import (
    generate_phishing_email as _ai_generate_email,
    is_configured as _ai_is_configured,
    ALLOWED_TYPES as _AI_ALLOWED_TYPES,
    ALLOWED_TONES as _AI_ALLOWED_TONES,
    GeminiConfigError,
)

from config import config
from phishing_campaign_service import PhishingCampaignService
from auth_clerk import auth_clerk_bp, is_clerk_configured

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

app = Flask(__name__, static_folder="static")
app.secret_key = config.SECRET_KEY

# Register Clerk authentication blueprint
app.register_blueprint(auth_clerk_bp)

logging.basicConfig(level=logging.INFO)

_sendgrid_client = SendGridAPIClient(config.SENDGRID_API_KEY) if config.SENDGRID_API_KEY else None

# Ensure uploads directory exists at startup
_UPLOADS_DIR = Path(__file__).parent / "static" / "uploads"
_UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _send_via_sendgrid(to_email: str, subject: str, body_html: str, sender_display_name: str) -> None:
    """Send via SendGrid HTTP API (port 443 – firewall-safe)."""
    message = Mail(
        from_email=From(config.SENDGRID_FROM_EMAIL, sender_display_name),
        to_emails=To(to_email),
        subject=Subject(subject),
        html_content=HtmlContent(body_html),
    )
    if _sendgrid_client is None:
        raise RuntimeError("SendGrid is not configured (missing SENDGRID_API_KEY)")
    response = _sendgrid_client.send(message)
    if response.status_code >= 400:
        raise RuntimeError(f"SendGrid error {response.status_code}: {response.body}")


def _retry_delay(attempt: int) -> float:
    """Exponential backoff with jitter for transient delivery errors."""
    return (config.SEND_RETRY_BASE_SEC * (2 ** (attempt - 1))) + random.uniform(0, 0.6)


def _is_transient_send_error(exc: Exception) -> bool:
    msg = str(exc).lower()
    transient_markers = (
        "421", "450", "451", "452", "4.7.", "rate limit", "too many",
        "temporar", "timeout", "timed out", "try again", "server busy",
        "connection unexpectedly closed", "service not available",
    )
    return any(m in msg for m in transient_markers)


@contextmanager
def _smtp_connection():
    """Open a single authenticated SMTP connection with retry (reuse for batch sends)."""
    last_err = None
    for attempt in range(3):
        try:
            if config.SMTP_USE_SSL:
                server = smtplib.SMTP_SSL(config.SMTP_HOST, config.SMTP_PORT, timeout=30)
            else:
                server = smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=30)
                server.ehlo()
                server.starttls()
                server.ehlo()
            server.login(config.SMTP_USERNAME, config.SMTP_PASSWORD)
            break
        except Exception as e:
            last_err = e
            logging.warning(f"SMTP connect attempt {attempt+1}/3 failed: {e}")
            time.sleep(2 * (attempt + 1))  # 2s, 4s backoff
    else:
        raise last_err  # all 3 attempts failed
    try:
        yield server
    finally:
        try:
            server.quit()
        except Exception:
            pass


def _send_batch(svc, campaign, recipients, label="Send"):
    """Send to a list of recipients, reusing one SMTP connection with per-email fallback."""
    sent_count = 0
    failed_count = 0
    errors = []
    smtp_conn = None

    try:
        with _smtp_connection() as conn:
            smtp_conn = conn
            for i, r in enumerate(recipients):
                try:
                    _dispatch_single_email(svc, campaign, r, _conn=smtp_conn)
                    sent_count += 1
                except smtplib.SMTPServerDisconnected:
                    # Connection died mid-batch – reconnect and retry this one
                    logging.warning(f"SMTP disconnected mid-batch at {r['email']}, reconnecting...")
                    try:
                        smtp_conn.quit()
                    except Exception:
                        pass
                    time.sleep(2)
                    smtp_conn = None  # signal to use per-email fallback below
                    break
                except Exception as exc:
                    logging.error(f"{label} failed to {r['email']}: {exc}")
                    svc.mark_failed(campaign["id"], r["email"], str(exc))
                    failed_count += 1
                    errors.append(str(exc))
                if i < len(recipients) - 1:
                    time.sleep(max(0.0, config.SEND_DELAY_SEC))
    except Exception as exc:
        # Could not establish connection at all – fall back to per-email mode
        logging.warning(f"Batch SMTP connection failed: {exc}. Falling back to per-email mode.")
        smtp_conn = None

    # Handle remaining recipients (skipped after mid-batch disconnect, or all if connect failed)
    already_processed = sent_count + failed_count
    remaining = recipients[already_processed:]
    for i, r in enumerate(remaining):
        try:
            _dispatch_single_email(svc, campaign, r)  # individual connection
            sent_count += 1
        except Exception as exc:
            logging.error(f"{label} failed to {r['email']}: {exc}")
            svc.mark_failed(campaign["id"], r["email"], str(exc))
            failed_count += 1
            errors.append(str(exc))
        if i < len(remaining) - 1:
            time.sleep(max(0.0, config.SEND_FALLBACK_DELAY_SEC))

    return sent_count, failed_count, errors


# ---------------------------------------------------------------------------
# Background send jobs – fire-and-forget so one click can dispatch a large
# campaign without holding the HTTP request open for minutes (which was
# triggering Azure log-stream "Max connection open time" cutoffs and risking
# browser/proxy timeouts on big lists).
# ---------------------------------------------------------------------------

_send_jobs: dict[str, dict] = {}
_send_jobs_lock = threading.Lock()


def _job_snapshot(campaign_id: str) -> dict | None:
    with _send_jobs_lock:
        job = _send_jobs.get(campaign_id)
        return dict(job) if job else None


def _job_update(campaign_id: str, **fields) -> None:
    with _send_jobs_lock:
        job = _send_jobs.get(campaign_id)
        if job is not None:
            job.update(fields)


def _run_send_job(campaign_id: str, label: str, do_validate: bool) -> None:
    """Worker that performs validation (optional) + the actual SMTP send.

    Runs in a background thread so the HTTP handler can return immediately.
    Progress + final result are written to _send_jobs[campaign_id].
    """
    try:
        svc = PhishingCampaignService()
        campaign = svc.get_campaign(campaign_id)
        if not campaign:
            _job_update(campaign_id, state="error", error="Campaign not found",
                        finished_at=datetime.now(timezone.utc).isoformat())
            return

        recipients_list = svc.list_recipients(campaign_id)
        to_send = [r for r in recipients_list if r.get("status") == "pending"]

        skipped_invalid = 0
        if do_validate and to_send:
            validation_mode = (config.PRE_SEND_VALIDATION or "dns").lower()
            if validation_mode not in {"dns", "smtp", "none"}:
                validation_mode = "dns"
            logging.info(f"Send validation mode: {validation_mode}")
            _job_update(campaign_id, state="validating")
            validated = []
            for r in to_send:
                if validation_mode == "none":
                    check = {"valid": True, "reason": "Validation disabled", "status": "valid"}
                elif validation_mode == "smtp":
                    check = _validate_email_address(r["email"])
                else:
                    check = _validate_email_dns_only(r["email"])
                if not check["valid"]:
                    svc.mark_failed(campaign_id, r["email"], f"Pre-send validation: {check['reason']}")
                    skipped_invalid += 1
                    logging.warning(f"Skipping invalid email {r['email']}: {check['reason']}")
                else:
                    validated.append(r)
            to_send = validated

        _job_update(campaign_id, state="sending", total=len(to_send),
                    skipped_invalid=skipped_invalid)

        if not to_send:
            _job_update(campaign_id, state="done", sent=0, failed=skipped_invalid,
                        finished_at=datetime.now(timezone.utc).isoformat())
            return

        sent_count, failed_count, errors = _send_batch(svc, campaign, to_send, label=label)
        _job_update(campaign_id,
                    state="done",
                    sent=sent_count,
                    failed=failed_count + skipped_invalid,
                    error_detail=(errors[0] if errors else None),
                    finished_at=datetime.now(timezone.utc).isoformat())
    except Exception as exc:
        logging.exception(f"Background send job failed for campaign {campaign_id}")
        _job_update(campaign_id, state="error", error=str(exc),
                    finished_at=datetime.now(timezone.utc).isoformat())


def _start_send_job(campaign_id: str, label: str, queued: int, do_validate: bool) -> bool:
    """Register and start a background send job. Returns False if one is already
    running for this campaign."""
    now = datetime.now(timezone.utc).isoformat()
    with _send_jobs_lock:
        existing = _send_jobs.get(campaign_id)
        if existing and existing.get("state") in {"queued", "validating", "sending"}:
            return False
        _send_jobs[campaign_id] = {
            "campaign_id": campaign_id,
            "label": label,
            "state": "queued",
            "queued": queued,
            "total": queued,
            "sent": 0,
            "failed": 0,
            "skipped_invalid": 0,
            "started_at": now,
            "finished_at": None,
            "error": None,
            "error_detail": None,
        }
    t = threading.Thread(
        target=_run_send_job,
        args=(campaign_id, label, do_validate),
        name=f"send-{campaign_id[:8]}",
        daemon=True,
    )
    t.start()
    return True


# ---------------------------------------------------------------------------
# CID image embedding – inline images in email HTML
# ---------------------------------------------------------------------------

_IMG_SRC_RE = re.compile(r'(<img\b[^>]*\bsrc=")([^"]+)(")', re.IGNORECASE)


def _embed_images(body_html: str) -> tuple[str, list]:
    """Replace local/data: image URLs with cid: references and return MIME parts.

    Returns (updated_html, [MIMEImage parts]).
    - /static/uploads/... URLs  → read from disk
    - data:image/...;base64,... → decoded inline
    - External https:// URLs    → left untouched
    """
    parts = []
    counter = [0]

    def _repl(m):
        prefix, src, suffix = m.group(1), m.group(2), m.group(3)
        img_data = None
        subtype = "png"

        if "/static/uploads/" in src:
            fname = src.rsplit("/static/uploads/", 1)[-1].split("?")[0]
            fp = _UPLOADS_DIR / fname
            if not fp.exists():
                return m.group(0)
            img_data = fp.read_bytes()
            ext = fp.suffix.lstrip(".").lower()
            subtype = {"jpg": "jpeg", "svg": "svg+xml"}.get(ext, ext)

        elif src.startswith("data:image/"):
            try:
                hdr, b64 = src.split(",", 1)
                subtype = hdr.split(";")[0].split("/")[1]
                img_data = base64.b64decode(b64)
            except Exception:
                return m.group(0)

        if img_data is None:
            return m.group(0)  # external URL – leave as-is

        cid = f"img{counter[0]}@phishdash"
        counter[0] += 1
        part = MIMEImage(img_data, _subtype=subtype)
        part.add_header("Content-ID", f"<{cid}>")
        part.add_header("Content-Disposition", "inline")
        parts.append(part)
        return f"{prefix}cid:{cid}{suffix}"

    updated = _IMG_SRC_RE.sub(_repl, body_html)
    return updated, parts


def _send_via_smtp(to_email: str, subject: str, body_html: str, sender_display_name: str,
                   _conn: smtplib.SMTP | None = None) -> None:
    """Send via Gmail or Outlook SMTP with CID-embedded images.

    Any <img src> pointing to our /static/uploads/ folder or using data: URLs
    is automatically embedded as an inline MIME attachment so images display
    in all email clients without external hosting.
    """
    # Embed local/data images as CID parts
    body_html, img_parts = _embed_images(body_html)

    if img_parts:
        # multipart/related wraps HTML + inline images
        msg = MIMEMultipart("related")
        msg_alt = MIMEMultipart("alternative")
        msg_alt.attach(MIMEText(body_html, "html"))
        msg.attach(msg_alt)
        for part in img_parts:
            msg.attach(part)
    else:
        msg = MIMEMultipart("alternative")
        msg.attach(MIMEText(body_html, "html"))

    msg["Subject"] = subject
    msg["From"] = formataddr((sender_display_name, config.SMTP_FROM_EMAIL))
    msg["To"] = to_email

    if _conn is not None:
        _conn.send_message(msg)
    elif config.SMTP_USE_SSL:                       # port 465 – Gmail SSL
        with smtplib.SMTP_SSL(config.SMTP_HOST, config.SMTP_PORT, timeout=30) as s:
            s.login(config.SMTP_USERNAME, config.SMTP_PASSWORD)
            s.send_message(msg)
    else:                                           # port 587 – STARTTLS
        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=30) as s:
            s.ehlo()
            s.starttls()
            s.ehlo()
            s.login(config.SMTP_USERNAME, config.SMTP_PASSWORD)
            s.send_message(msg)


def _send_email(to_email: str, subject: str, body_html: str, sender_display_name: str,
                _conn: smtplib.SMTP | None = None) -> None:
    """Route to the configured email provider."""
    if config.EMAIL_PROVIDER == 'sendgrid':
        _send_via_sendgrid(to_email, subject, body_html, sender_display_name)
    else:  # gmail / outlook
        _send_via_smtp(to_email, subject, body_html, sender_display_name, _conn=_conn)


_TRACKING_PIXEL = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01"
    b"\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00"
    b"\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18"
    b"\xd8N\x00\x00\x00\x00IEND\xaeB`\x82"
)

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# ---------------------------------------------------------------------------
# CORS – applied globally via after_request
# ---------------------------------------------------------------------------

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Admin-Key"
    return response


# ---------------------------------------------------------------------------
# Global error handlers – always return JSON, never HTML
# ---------------------------------------------------------------------------

@app.errorhandler(404)
def not_found(e):
    return _json_response({"error": "Not found"}, 404)


@app.errorhandler(405)
def method_not_allowed(e):
    return _json_response({"error": "Method not allowed"}, 405)


@app.errorhandler(500)
def internal_error(e):
    logging.error(f"Unhandled 500: {e}")
    return _json_response({"error": "Internal server error"}, 500)


@app.errorhandler(Exception)
def handle_exception(e):
    logging.error(f"Unhandled exception: {e}", exc_info=True)
    return _json_response({"error": "Internal server error"}, 500)


# ---------------------------------------------------------------------------
# RBAC – Role-based access control
# ---------------------------------------------------------------------------

_ROLE_PERMISSIONS = {
    "admin":           {"dashboard", "view_campaigns", "create_campaign", "view_recipients", "add_recipients", "send", "report", "manage_users"},
    "operator":        {"dashboard", "view_campaigns", "create_campaign", "view_recipients", "add_recipients", "send", "report"},
    "auditor":         {"dashboard", "view_campaigns", "view_recipients", "report"},
    "template_author": {"view_campaigns", "create_campaign"},
}

_ROLE_LABELS = {
    "admin": "Admin",
    "operator": "Operator",
    "auditor": "Auditor",
    "template_author": "Template Author",
}


def _get_session_info() -> dict | None:
    # Token = "clerk" means the browser has a Flask session populated by a verified
    # Clerk sign-in (see auth_clerk.clerk_session). The role comes from the Clerk
    # user's public_metadata.role, set per-user in the Clerk Dashboard.
    provided = request.headers.get("X-Admin-Key") or ""
    if provided != "clerk":
        return None
    user = flask_session.get("clerk_user")
    if not user:
        return None
    role = user.get("role")
    if role not in _ROLE_LABELS:
        return None
    return {"role": role, "username": user.get("name") or user.get("email", "Clerk User"),
            "label": _ROLE_LABELS.get(role, role)}


def _get_role() -> str | None:
    info = _get_session_info()
    return info["role"] if info else None


def _can(role: str | None, permission: str) -> bool:
    return bool(role and permission in _ROLE_PERMISSIONS.get(role, set()))


def _json_response(data, status_code: int = 200):
    return make_response(jsonify(data), status_code)


def _unauthorized():
    return _json_response({"error": "Unauthorized – provide a valid X-Admin-Key header"}, 401)


def _forbidden(permission: str):
    return _json_response({"error": f"Forbidden – your role does not allow '{permission}'"}, 403)


# ---------------------------------------------------------------------------
# IST time-based greeting helpers
# ---------------------------------------------------------------------------

_IST_OFFSET = timedelta(hours=5, minutes=30)


def _ist_greeting() -> str:
    ist_hour = (datetime.now(timezone.utc) + _IST_OFFSET).hour
    if 5 <= ist_hour < 12:
        return "Good Morning"
    elif 12 <= ist_hour < 17:
        return "Good Afternoon"
    elif 17 <= ist_hour < 21:
        return "Good Evening"
    return "Good Night"


def _first_name(full_name: str) -> str:
    parts = (full_name or "").strip().split()
    return parts[0] if parts else (full_name or "")


# ---------------------------------------------------------------------------
# Email validation – DNS/MX + SMTP RCPT TO check
# ---------------------------------------------------------------------------

# Cache MX lookups to avoid repeated DNS queries for the same domain
_mx_cache: dict[str, list[str] | None] = {}


def _get_mx_hosts(domain: str) -> list[str] | None:
    """Return list of MX hostnames for a domain, or None if no MX records exist."""
    if domain in _mx_cache:
        return _mx_cache[domain]
    try:
        answers = dns.resolver.resolve(domain, 'MX', lifetime=10)
        hosts = sorted(answers, key=lambda r: r.preference)
        result = [str(r.exchange).rstrip('.') for r in hosts]
        _mx_cache[domain] = result if result else None
        return _mx_cache[domain]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        _mx_cache[domain] = None
        return None
    except (dns.resolver.NoAnswer, dns.resolver.LifetimeTimeout):
        # No MX but domain might exist – try A record fallback
        try:
            dns.resolver.resolve(domain, 'A', lifetime=5)
            _mx_cache[domain] = [domain]
            return _mx_cache[domain]
        except Exception:
            _mx_cache[domain] = None
            return None
    except Exception:
        return None  # Don't cache transient errors


def _validate_email_address(email: str) -> dict:
    """Validate a single email address.

    Returns dict with keys:
      - email: the email address
      - valid: True/False
      - status: 'valid', 'invalid_format', 'invalid_domain', 'undeliverable', 'unknown'
      - reason: human-readable reason
    """
    email = email.strip().lower()

    # 1. Format check
    if not _EMAIL_RE.match(email):
        return {"email": email, "valid": False, "status": "invalid_format",
                "reason": "Invalid email format"}

    domain = email.split("@", 1)[1]

    # 2. DNS/MX check – does the domain accept email?
    mx_hosts = _get_mx_hosts(domain)
    if mx_hosts is None:
        return {"email": email, "valid": False, "status": "invalid_domain",
                "reason": f"Domain '{domain}' does not exist or has no mail server (MX record)"}

    # 3. SMTP RCPT TO check – does the mailbox exist?
    from_addr = config.SMTP_FROM_EMAIL or config.SENDGRID_FROM_EMAIL or "test@example.com"
    for mx_host in mx_hosts[:2]:  # Try top 2 MX servers
        try:
            with smtplib.SMTP(mx_host, 25, timeout=10) as smtp:
                smtp.ehlo("phishdash.local")
                code, _ = smtp.mail(from_addr)
                if code != 250:
                    continue
                code, message = smtp.rcpt(email)
                smtp.rset()
                if code == 250:
                    return {"email": email, "valid": True, "status": "valid",
                            "reason": "Email address is valid and deliverable"}
                elif code == 550 or code == 551 or code == 553:
                    return {"email": email, "valid": False, "status": "undeliverable",
                            "reason": f"Mailbox does not exist ({code}: {message.decode(errors='replace')})"}
                elif code == 452 or code == 421:
                    # Temporary error – can't confirm but domain is valid
                    return {"email": email, "valid": True, "status": "unknown",
                            "reason": "Mail server busy – domain is valid but mailbox could not be verified"}
                else:
                    return {"email": email, "valid": True, "status": "unknown",
                            "reason": f"Mail server returned {code} – domain valid, mailbox unverified"}
        except (smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError,
                ConnectionRefusedError, OSError, TimeoutError):
            continue
        except Exception:
            continue

    # Could not connect to any MX server for RCPT check – domain is valid though
    return {"email": email, "valid": True, "status": "unknown",
            "reason": f"Domain '{domain}' has mail servers but could not verify mailbox (port 25 blocked or server rejected)"}


def _dispatch_single_email(svc: PhishingCampaignService, campaign: dict, recipient: dict,
                           _conn: smtplib.SMTP | None = None) -> None:
    cfg = config.get_phishing_config()
    base_url = cfg["base_url"].rstrip("/")
    tracking_pixel_url = f"{base_url}/api/track/open/{recipient['tracking_token']}"

    github_pages_url = cfg.get("github_pages_url", "").rstrip("/")
    redirect_url = (campaign.get("redirect_url") or "").strip() or "https://login.microsoftonline.com"
    if github_pages_url:
        from urllib.parse import quote as _urlencode
        click_track_url = (
            f"{github_pages_url}/?"
            f"t={recipient['tracking_token']}"
            f"&api={_urlencode(base_url, safe='')}"
            f"&r={_urlencode(redirect_url, safe='')}"
        )
    else:
        # Short clean URL – hides the tracking path from hover tooltip
        click_track_url = f"{base_url}/auth/verify/{recipient['tracking_token']}"

    body_html = campaign["body_html"]
    first_name = _first_name(recipient.get("name", recipient["email"]))
    greeting = _ist_greeting()
    body_html = (body_html
                 .replace("{{name}}", recipient.get("name", recipient["email"]))
                 .replace("{{first_name}}", first_name)
                 .replace("{{greeting}}", greeting)
                 .replace("{{email}}", recipient["email"])
                 .replace("{{phishing_link}}", click_track_url))

    pixel_img = f'<img src="{tracking_pixel_url}" width="1" height="1" style="display:none" alt="" />'
    if "</body>" in body_html.lower():
        body_html = body_html.replace("</body>", f"{pixel_img}</body>")
        body_html = body_html.replace("</BODY>", f"{pixel_img}</BODY>")
    else:
        body_html = body_html + pixel_img

    retries = max(1, config.SEND_RETRY_COUNT)
    last_exc = None
    for attempt in range(1, retries + 1):
        try:
            _send_email(
                to_email=recipient["email"],
                subject=campaign["subject"],
                body_html=body_html,
                sender_display_name=campaign.get("sender_name", "Security Team"),
                _conn=_conn,
            )
            last_exc = None
            break
        except Exception as exc:
            last_exc = exc
            if attempt >= retries or (not _is_transient_send_error(exc)):
                break
            wait_s = _retry_delay(attempt)
            logging.warning(
                f"Transient send error for {recipient['email']} (attempt {attempt}/{retries}): {exc}. "
                f"Retrying in {wait_s:.2f}s"
            )
            time.sleep(wait_s)

    if last_exc is not None:
        raise last_exc

    svc.mark_sent(campaign["id"], recipient["email"])
    logging.info(f"Email sent -> {recipient['email']} (campaign {campaign['id']})")


def _validate_email_dns_only(email: str) -> dict:
    """Fast validation for bulk sends: format + DNS/MX only."""
    email = (email or "").strip().lower()
    if not _EMAIL_RE.match(email):
        return {
            "email": email,
            "valid": False,
            "status": "invalid_format",
            "reason": "Invalid email format",
        }
    domain = email.split("@", 1)[1]
    mx_hosts = _get_mx_hosts(domain)
    if mx_hosts is None:
        return {
            "email": email,
            "valid": False,
            "status": "invalid_domain",
            "reason": f"Domain '{domain}' does not exist or has no mail server (MX record)",
        }
    return {
        "email": email,
        "valid": True,
        "status": "valid",
        "reason": "Domain has valid mail server (MX)",
    }


def _js_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "").replace("\r", "")


def _clerk_frontend_api(publishable_key: str) -> str:
    """Decode the Clerk Frontend API domain embedded in a publishable key.

    Clerk publishable keys are 'pk_test_' or 'pk_live_' followed by a
    base64-encoded '<frontend-api-domain>$'.
    """
    if not publishable_key:
        return ""
    try:
        _, _, encoded = publishable_key.split("_", 2)
        padded = encoded + "=" * (-len(encoded) % 4)
        return base64.b64decode(padded).decode("utf-8").rstrip("$")
    except Exception:
        return ""


# ===========================================================================
# ROUTES
# ===========================================================================

# ---------------------------------------------------------------------------
# Admin UI
# ---------------------------------------------------------------------------

@app.route("/", methods=["GET"])
def root_redirect():
    return Response(status=302, headers={"Location": "/api/phish/ui"})


@app.route("/api/phish/ui", methods=["GET"])
def admin_ui():
    html_path = Path(__file__).parent / "static" / "admin_ui.html"
    if not html_path.exists():
        return "Admin UI not found", 404
    html = html_path.read_text(encoding="utf-8")
    html = html.replace("__CLERK_PUBLISHABLE_KEY__", _js_escape(config.CLERK_PUBLISHABLE_KEY))
    html = html.replace("__CLERK_FRONTEND_API__", _js_escape(_clerk_frontend_api(config.CLERK_PUBLISHABLE_KEY)))
    return Response(html, mimetype="text/html")


# ---------------------------------------------------------------------------
# Role check – /api/phish/me
# ---------------------------------------------------------------------------

@app.route("/api/phish/me", methods=["GET", "OPTIONS"])
def phish_me():
    if request.method == "OPTIONS":
        return "", 200
    info = _get_session_info()
    if not info:
        return _json_response({"error": "Invalid or missing key"}, 401)
    return _json_response({"role": info["role"], "label": info["label"], "username": info.get("username", "")})


# Authentication (login/logout) and user/role management now live entirely in
# Clerk: sign-in is handled by auth_clerk_bp (/api/auth/clerk/*), and roles are
# assigned per-user in the Clerk Dashboard via public_metadata.role.


# ---------------------------------------------------------------------------
# Campaign CRUD
# ---------------------------------------------------------------------------

@app.route("/api/phish/campaigns", methods=["GET", "POST", "OPTIONS"])
def campaigns():
    if request.method == "OPTIONS":
        return "", 200
    role = _get_role()
    if request.method == "GET":
        if not _can(role, "view_campaigns"):
            return _unauthorized() if not role else _forbidden("view_campaigns")
    else:
        if not _can(role, "create_campaign"):
            return _unauthorized() if not role else _forbidden("create_campaign")
    try:
        svc = PhishingCampaignService()
        if request.method == "GET":
            return _json_response(svc.list_campaigns())
        try:
            body = request.get_json(force=True)
        except Exception:
            return _json_response({"error": "Invalid JSON body"}, 400)
        name = (body.get("name") or "").strip()
        subject = (body.get("subject") or "").strip()
        body_html = (body.get("body_html") or "").strip()
        sender_name = (body.get("sender_name") or "Security Team").strip()
        redirect_url = (body.get("redirect_url") or "").strip()
        if not name or not subject or not body_html:
            return _json_response({"error": "name, subject, and body_html are required"}, 400)
        campaign = svc.create_campaign(name, subject, body_html, sender_name, redirect_url)
        return _json_response(campaign, 201)
    except Exception as exc:
        logging.error(f"Campaigns error: {exc}", exc_info=True)
        return _json_response({"error": f"Server error: {exc}"}, 500)


@app.route("/api/phish/campaigns/<campaign_id>", methods=["GET", "DELETE", "OPTIONS"])
def campaign_detail(campaign_id):
    if request.method == "OPTIONS":
        return "", 200
    role = _get_role()
    if request.method == "DELETE":
        if not _can(role, "create_campaign"):
            return _unauthorized() if not role else _forbidden("delete_campaign")
        svc = PhishingCampaignService()
        ok = svc.delete_campaign(campaign_id)
        if not ok:
            return _json_response({"error": "Campaign not found"}, 404)
        return _json_response({"message": "Campaign deleted"})
    if not _can(role, "view_campaigns"):
        return _unauthorized() if not role else _forbidden("view_campaigns")
    svc = PhishingCampaignService()
    stats = svc.get_dashboard_stats(campaign_id)
    if not stats:
        return _json_response({"error": "Campaign not found"}, 404)
    return _json_response(stats)


# ---------------------------------------------------------------------------
# Recipients
# ---------------------------------------------------------------------------

@app.route("/api/phish/campaigns/<campaign_id>/recipients", methods=["GET", "POST", "OPTIONS"])
def recipients(campaign_id):
    if request.method == "OPTIONS":
        return "", 200
    role = _get_role()
    if request.method == "GET":
        if not _can(role, "view_recipients"):
            return _unauthorized() if not role else _forbidden("view_recipients")
    else:
        if not _can(role, "add_recipients"):
            return _unauthorized() if not role else _forbidden("add_recipients")
    svc = PhishingCampaignService()
    if request.method == "GET":
        return _json_response(svc.list_recipients(campaign_id))
    try:
        body = request.get_json(force=True)
    except Exception:
        return _json_response({"error": "Invalid JSON body"}, 400)
    raw_list = body.get("recipients", [])
    if not isinstance(raw_list, list):
        return _json_response({"error": "'recipients' must be a list"}, 400)
    valid = []
    invalid = []
    warnings = []
    for item in raw_list:
        email = (item.get("email") or "").strip().lower()
        if not _EMAIL_RE.match(email):
            invalid.append(email)
            continue
        # Quick DNS/MX domain check (no SMTP probe – keep it fast)
        domain = email.split("@", 1)[1]
        mx_hosts = _get_mx_hosts(domain)
        if mx_hosts is None:
            invalid.append(email)
            warnings.append(f"{email}: domain '{domain}' has no mail server (MX record)")
            continue
        valid.append({"email": email, "name": item.get("name", email)})
    if not valid:
        return _json_response({"error": "No valid e-mail addresses provided", "invalid": invalid,
                                "warnings": warnings}, 400)
    created = svc.add_recipients(campaign_id, valid)
    result = {"added": len(created), "invalid": invalid, "recipients": created}
    if warnings:
        result["warnings"] = warnings
    return _json_response(result, 201)


@app.route("/api/phish/campaigns/<campaign_id>/recipients/<recipient_id>", methods=["DELETE", "OPTIONS"])
def delete_recipient(campaign_id, recipient_id):
    if request.method == "OPTIONS":
        return "", 200
    role = _get_role()
    if not _can(role, "add_recipients"):
        return _unauthorized() if not role else _forbidden("add_recipients")
    svc = PhishingCampaignService()
    ok = svc.delete_recipient(recipient_id)
    if not ok:
        return _json_response({"error": "Recipient not found"}, 404)
    return _json_response({"message": "Recipient deleted"})


# ---------------------------------------------------------------------------
# Validate recipients – DNS/MX + SMTP mailbox check
# ---------------------------------------------------------------------------

@app.route("/api/phish/campaigns/<campaign_id>/validate", methods=["POST", "OPTIONS"])
def validate_recipients(campaign_id):
    if request.method == "OPTIONS":
        return "", 200
    role = _get_role()
    if not _can(role, "send"):
        return _unauthorized() if not role else _forbidden("send")
    svc = PhishingCampaignService()
    campaign = svc.get_campaign(campaign_id)
    if not campaign:
        return _json_response({"error": "Campaign not found"}, 404)
    recipients_list = svc.list_recipients(campaign_id)
    if not recipients_list:
        return _json_response({"error": "No recipients to validate"}, 400)

    results = []
    invalid_count = 0
    valid_count = 0
    for r in recipients_list:
        # Skip already-opened/clicked recipients – they're obviously valid
        status = (r.get("status") or "").lower()
        if status in ("opened",):
            results.append({"email": r["email"], "valid": True, "status": "valid",
                            "reason": "Already delivered and opened"})
            valid_count += 1
            continue

        check = _validate_email_address(r["email"])
        results.append(check)
        if not check["valid"]:
            invalid_count += 1
            svc.mark_failed(campaign_id, r["email"], f"Validation: {check['reason']}")
        else:
            valid_count += 1

    return _json_response({
        "campaign_id": campaign_id,
        "total": len(results),
        "valid": valid_count,
        "invalid": invalid_count,
        "results": results,
    })


# ---------------------------------------------------------------------------
# Validate a single email address (ad-hoc)
# ---------------------------------------------------------------------------

@app.route("/api/phish/validate-email", methods=["POST", "OPTIONS"])
def validate_email_endpoint():
    if request.method == "OPTIONS":
        return "", 200
    role = _get_role()
    if not role:
        return _unauthorized()
    try:
        body = request.get_json(force=True)
    except Exception:
        return _json_response({"error": "Invalid JSON"}, 400)
    email = (body.get("email") or "").strip().lower()
    if not email:
        return _json_response({"error": "email is required"}, 400)
    result = _validate_email_address(email)
    return _json_response(result)


# ---------------------------------------------------------------------------
# Resend campaign
# ---------------------------------------------------------------------------

@app.route("/api/phish/campaigns/<campaign_id>/resend", methods=["POST", "OPTIONS"])
def resend_campaign(campaign_id):
    if request.method == "OPTIONS":
        return "", 200
    role = _get_role()
    if not _can(role, "send"):
        return _unauthorized() if not role else _forbidden("send")
    svc = PhishingCampaignService()
    campaign = svc.get_campaign(campaign_id)
    if not campaign:
        return _json_response({"error": "Campaign not found"}, 404)
    reset_count = svc.reset_for_resend(campaign_id)
    if reset_count == 0:
        return _json_response({"message": "No recipients to resend to"}, 200)
    queued = len(svc.list_recipients(campaign_id))
    started = _start_send_job(campaign_id, label="Resend", queued=queued, do_validate=False)
    if not started:
        return _json_response({"error": "A send is already running for this campaign"}, 409)
    return _json_response({
        "queued": queued,
        "reset": reset_count,
        "campaign_id": campaign_id,
        "state": "queued",
        "message": f"Resend queued for {queued} recipient(s). Running in background."
    }, 202)


# ---------------------------------------------------------------------------
# Send campaign
# ---------------------------------------------------------------------------

@app.route("/api/phish/campaigns/<campaign_id>/send", methods=["POST", "OPTIONS"])
def send_campaign(campaign_id):
    if request.method == "OPTIONS":
        return "", 200
    role = _get_role()
    if not _can(role, "send"):
        return _unauthorized() if not role else _forbidden("send")
    svc = PhishingCampaignService()
    campaign = svc.get_campaign(campaign_id)
    if not campaign:
        return _json_response({"error": "Campaign not found"}, 404)
    recipients_list = svc.list_recipients(campaign_id)
    to_send = [r for r in recipients_list if r.get("status") == "pending"]
    if not to_send:
        return _json_response({"message": "No pending recipients – all already sent or none added"}, 200)

    started = _start_send_job(campaign_id, label="Send", queued=len(to_send), do_validate=True)
    if not started:
        return _json_response({"error": "A send is already running for this campaign"}, 409)
    return _json_response({
        "queued": len(to_send),
        "campaign_id": campaign_id,
        "state": "queued",
        "message": f"Send queued for {len(to_send)} recipient(s). Running in background."
    }, 202)


@app.route("/api/phish/campaigns/<campaign_id>/send/status", methods=["GET", "OPTIONS"])
def send_campaign_status(campaign_id):
    if request.method == "OPTIONS":
        return "", 200
    role = _get_role()
    if not _can(role, "send"):
        return _unauthorized() if not role else _forbidden("send")
    snap = _job_snapshot(campaign_id)
    if not snap:
        return _json_response({"campaign_id": campaign_id, "state": "idle"})
    return _json_response(snap)


# ---------------------------------------------------------------------------
# Resend ONLY the previously-failed recipients
# (e.g. when Gmail's 2k/day quota dropped some). Flips failed -> pending and
# reuses the exact same background send pipeline as /send, so validation,
# pacing, retries, and batching are identical.
# ---------------------------------------------------------------------------

@app.route("/api/phish/campaigns/<campaign_id>/resend-failed", methods=["POST", "OPTIONS"])
def resend_failed_campaign(campaign_id):
    if request.method == "OPTIONS":
        return "", 200
    role = _get_role()
    if not _can(role, "send"):
        return _unauthorized() if not role else _forbidden("send")
    svc = PhishingCampaignService()
    campaign = svc.get_campaign(campaign_id)
    if not campaign:
        return _json_response({"error": "Campaign not found"}, 404)
    cleared = svc.clear_failed_recipients(campaign_id)
    if cleared == 0:
        return _json_response({"message": "No failed recipients to resend"}, 200)
    started = _start_send_job(campaign_id, label="ResendFailed", queued=cleared, do_validate=True)
    if not started:
        return _json_response({"error": "A send is already running for this campaign"}, 409)
    return _json_response({
        "queued": cleared,
        "campaign_id": campaign_id,
        "state": "queued",
        "message": f"Resend queued for {cleared} previously-failed recipient(s). Running in background."
    }, 202)


# ---------------------------------------------------------------------------
# Clear failed recipients
# ---------------------------------------------------------------------------

@app.route("/api/phish/campaigns/<campaign_id>/failed", methods=["DELETE", "OPTIONS"])
def clear_failed(campaign_id):
    if request.method == "OPTIONS":
        return "", 200
    role = _get_role()
    if not _can(role, "send"):
        return _unauthorized() if not role else _forbidden("send")
    svc = PhishingCampaignService()
    cleared = svc.clear_failed_recipients(campaign_id)
    return _json_response({"cleared": cleared, "campaign_id": campaign_id})


# ---------------------------------------------------------------------------
# Clear duplicate-send counter
# ---------------------------------------------------------------------------

@app.route("/api/phish/campaigns/<campaign_id>/duplicates", methods=["DELETE", "OPTIONS"])
def clear_duplicates(campaign_id):
    if request.method == "OPTIONS":
        return "", 200
    role = _get_role()
    if not _can(role, "send"):
        return _unauthorized() if not role else _forbidden("send")
    svc = PhishingCampaignService()
    cleared = svc.clear_duplicate_count(campaign_id)
    return _json_response({"cleared": cleared, "campaign_id": campaign_id})


# ---------------------------------------------------------------------------
# Bot / Email-scanner detection
# ---------------------------------------------------------------------------
# Email security scanners (Microsoft Defender Safe Links, Proofpoint, Mimecast,
# Google's GMail prefetcher, etc.) automatically fetch images and pre-click links
# to scan for malware. They produce false "opened" and "clicked" events.
# We filter them out using:
#   1. Known bot User-Agent strings
#   2. Missing Accept headers (real browsers always send them)
#   3. Suspicious request patterns

_BOT_UA_PATTERNS = re.compile(
    # Generic crawler/scanner words
    r"\bbot\b|crawler|spider|\bscanner\b|preview|monitor|"
    # Email security gateways
    r"safelinks|defender(?!\b\s*for\s*end)|proofpoint|mimecast|barracuda|"
    r"forcepoint|symantec|trendmicro|mcafee|sophos|cisco\s*ironport|"
    # Image/link prefetchers
    r"gmailimageproxy|googleimageproxy|yahoo!\s*slurp|"
    r"outlooksafelinks|outlookconnector|outlookprotection|outlooksafelink|"
    r"bingpreview|msnbot|"
    # Headless / programmatic clients
    r"headlesschrome|phantomjs|selenium|puppeteer|playwright|"
    r"\bpython\b|\bcurl\b|\bwget\b|httpclient|okhttp|java/|libwww|"
    r"go-http-client|"
    # Social/link-preview bots
    r"facebookexternalhit|whatsapp|slackbot|telegrambot|"
    r"linkpreview|urlchecker|virustotal|urlscan",
    re.IGNORECASE,
)
# NOTE: We deliberately do NOT match "outlook" alone — the new Outlook
# desktop client identifies as "OneOutlook/x.y.z" and is a real user open.
# Only match specific scanner sub-products (OutlookSafeLinks etc.).

# Microsoft data-center IP ranges that host Defender Safe Links scanners.
# Hits from these are pre-click scans, NOT real users. Source: Microsoft
# publishes ranges via the Office 365 endpoint manifest; these are the most
# common ones we've observed in our own logs.
_MS_SCANNER_IP_PREFIXES = (
    "40.92.", "40.93.", "40.107.",
    "52.100.", "52.101.", "52.102.", "52.103.", "52.104.", "52.105.", "52.106.",
    "52.238.78.", "52.238.79.",
    "104.47.",      # Office 365 Exchange Online Protection
    "13.107.",      # Microsoft 365 Common services
    "57.155.170.", "57.155.171.",  # observed in our Defender Safe Links logs
)

# Minimum seconds that must elapse between sending the email and a tracking
# hit being treated as a real human interaction. Anything faster is almost
# certainly an automated scanner / mail-client image prefetch.
_MIN_OPEN_DELAY_SEC = 30
_MIN_CLICK_DELAY_SEC = 10


def _client_ip() -> str:
    """Return the best-guess client IP, honouring X-Forwarded-For (Container
    Apps puts the real client IP as the FIRST entry)."""
    xff = request.headers.get("X-Forwarded-For", "") or ""
    if xff:
        # First IP in the comma-separated list is the original client.
        return xff.split(",")[0].strip()
    return request.remote_addr or ""


def _is_ms_scanner_ip(ip: str) -> bool:
    if not ip:
        return False
    return any(ip.startswith(p) for p in _MS_SCANNER_IP_PREFIXES)


def _is_bot_request() -> tuple[bool, str]:
    """Detect if the current request is from an automated email scanner / bot.

    Returns (is_bot, reason).
    """
    ua = request.headers.get("User-Agent", "") or ""
    accept = request.headers.get("Accept", "") or ""
    ip = _client_ip()

    # 1. Microsoft Defender Safe Links / EOP scanner IP ranges
    if _is_ms_scanner_ip(ip):
        return True, f"Microsoft scanner IP: {ip}"

    # 2. Missing User-Agent
    if not ua:
        return True, "missing User-Agent"

    # 3. Known bot/scanner UA patterns
    if _BOT_UA_PATTERNS.search(ua):
        return True, f"bot User-Agent: {ua[:100]}"

    # 4. HEAD requests are typically scanners pre-checking links
    if request.method == "HEAD":
        return True, "HEAD request (link scanner)"

    # 5. Accept header missing entirely (real browsers always send one)
    if accept == "":
        return True, "missing Accept header"

    return False, ""


def _seconds_since_sent(svc, token: str) -> float:
    """Return seconds elapsed since the recipient's sent_at, or -1 if unknown."""
    try:
        sent_at = svc.get_sent_at_for_token(token)
        if not sent_at:
            return -1
        # sent_at is ISO 8601 UTC like "2026-05-14T19:08:43.123456+00:00" or "...Z"
        from datetime import datetime, timezone
        s = sent_at.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        delta = (datetime.now(timezone.utc) - dt).total_seconds()
        return delta
    except Exception:
        return -1


def _classify_client(ua: str) -> tuple[str, str]:
    """Classify client into (device_type, os_name) for dashboard analytics."""
    s = (ua or "").lower()

    if any(x in s for x in ["iphone", "android", "mobile", "windows phone"]):
        device = "Mobile"
    elif any(x in s for x in ["ipad", "tablet"]):
        device = "Tablet"
    elif any(x in s for x in ["windows", "macintosh", "linux", "x11", "cros"]):
        device = "Desktop"
    else:
        device = "Unknown"

    if "windows" in s:
        os_name = "Windows"
    elif any(x in s for x in ["iphone", "ipad", "ios", "cfnetwork"]):
        os_name = "iOS"
    elif "android" in s:
        os_name = "Android"
    elif any(x in s for x in ["mac os", "macintosh", "darwin"]):
        os_name = "macOS"
    elif "linux" in s:
        os_name = "Linux"
    elif "cros" in s:
        os_name = "ChromeOS"
    else:
        os_name = "Unknown"

    return device, os_name


def _log_tracking_hit(kind: str, token: str):
    """Log full request details for any tracking endpoint hit (debug aid)."""
    ua = request.headers.get("User-Agent", "") or "<empty>"
    accept = request.headers.get("Accept", "") or "<empty>"
    referer = request.headers.get("Referer", "") or "<empty>"
    ip = _client_ip() or "?"
    logging.info(
        f"TRACK[{kind}] token={token[:8]}… ip={ip} method={request.method} "
        f"UA={ua[:160]} | Accept={accept[:80]} | Referer={referer[:80]}"
    )


# ---------------------------------------------------------------------------
# Tracking pixel – records email opens
# ---------------------------------------------------------------------------

@app.route("/api/track/open/<token>", methods=["GET", "HEAD"])
def track_open(token):
    if not re.match(r'^[A-Za-z0-9_\-]{10,60}$', token):
        return Response(_TRACKING_PIXEL, mimetype="image/png",
                        headers={"Cache-Control": "no-store, no-cache"})
    _log_tracking_hit("open", token)
    is_bot, reason = _is_bot_request()
    try:
        svc = PhishingCampaignService()
        if is_bot:
            logging.info(f"  -> SKIPPED open (bot/scanner): {reason}")
            return Response(_TRACKING_PIXEL, mimetype="image/png",
                            headers={"Cache-Control": "no-store, no-cache"})
        elapsed = _seconds_since_sent(svc, token)
        if 0 <= elapsed < _MIN_OPEN_DELAY_SEC:
            logging.info(f"  -> SKIPPED open (too fast: {elapsed:.1f}s after send, "
                         f"likely auto-prefetch / scanner)")
            return Response(_TRACKING_PIXEL, mimetype="image/png",
                            headers={"Cache-Control": "no-store, no-cache"})
        ua = request.headers.get("User-Agent", "") or ""
        device_type, os_name = _classify_client(ua)
        svc.mark_opened(
            token,
            ip=_client_ip(),
            user_agent=ua,
            device_type=device_type,
            os_name=os_name,
        )
        logging.info(f"  -> COUNTED open (elapsed={elapsed:.1f}s, device={device_type}, os={os_name})")
    except Exception as exc:
        logging.warning(f"Tracking error for token {token}: {exc}")
    return Response(_TRACKING_PIXEL, mimetype="image/png",
                    headers={"Cache-Control": "no-store, no-cache"})


# ---------------------------------------------------------------------------
# Link click tracking – redirect + record click
# ---------------------------------------------------------------------------

@app.route("/api/track/click/<token>", methods=["GET", "HEAD"])
def track_click(token):
    fallback_url = "https://www.microsoft.com"
    if not re.match(r'^[A-Za-z0-9_\-]{10,60}$', token):
        return Response(status=302, headers={"Location": fallback_url})
    _log_tracking_hit("click", token)
    redirect_to = fallback_url
    try:
        svc = PhishingCampaignService()
        is_bot, reason = _is_bot_request()
        elapsed = _seconds_since_sent(svc, token)
        if is_bot:
            logging.info(f"  -> SKIPPED click (bot/scanner): {reason}")
        elif 0 <= elapsed < _MIN_CLICK_DELAY_SEC:
            logging.info(f"  -> SKIPPED click (too fast: {elapsed:.1f}s after send)")
        else:
            ua = request.headers.get("User-Agent", "") or ""
            device_type, os_name = _classify_client(ua)
            svc.mark_clicked(
                token,
                ip=_client_ip(),
                user_agent=ua,
                device_type=device_type,
                os_name=os_name,
            )
            logging.info(f"  -> COUNTED click (elapsed={elapsed:.1f}s, device={device_type}, os={os_name})")
        redirect_to = svc.get_redirect_url_for_token(token) or fallback_url
    except Exception as exc:
        logging.warning(f"Click-tracking error for token {token}: {exc}")
    return Response(status=302, headers={"Location": redirect_to, "Cache-Control": "no-store, no-cache"})


# ---------------------------------------------------------------------------
# Short redirect URL – clean URL for email button hover tooltip
# ---------------------------------------------------------------------------

@app.route("/r/<token>", methods=["GET"])
@app.route("/auth/verify/<token>", methods=["GET"])
def short_redirect(token):
    """Short clean URL that hides the tracking path from email hover tooltip.
    Internally delegates to the landing page logic."""
    return phishing_landing(token)


# ---------------------------------------------------------------------------
# Built-in phishing landing page
# ---------------------------------------------------------------------------

@app.route("/api/phish/landing/<token>", methods=["GET"])
def phishing_landing(token):
    """Render the fake login page.

    Click recording strategy (defence in depth):
      1. Server-side: if the request passes the bot/IP filter AND the
         time-window check, record the click here directly. This is the
         fallback for browsers where the in-page JS ping never fires
         (JS disabled, CSP, ad-blocker, browser extension, etc.).
      2. Client-side: the page's JS also calls /api/track/ping/<token>
         after a real-user interaction signal OR 2s after load. The DB
         `mark_clicked` uses COALESCE on `clicked_at` so the duplicate
         click only bumps `click_count`, which is the desired behaviour.
    """
    redirect_to = "https://login.microsoftonline.com"
    valid_token = bool(re.match(r'^[A-Za-z0-9_\-]{10,60}$', token))
    if valid_token:
        _log_tracking_hit("landing-render", token)
        try:
            svc = PhishingCampaignService()
            url = svc.get_redirect_url_for_token(token)
            if url:
                redirect_to = url
            # Server-side click fallback – only when this is clearly a real
            # browser (passes bot filter) AND the time window says it can't
            # be an automated scanner pre-fetch.
            is_bot, reason = _is_bot_request()
            elapsed = _seconds_since_sent(svc, token)
            if is_bot:
                logging.info(f"  -> SKIPPED landing click (bot/scanner): {reason}")
            elif 0 <= elapsed < _MIN_CLICK_DELAY_SEC:
                logging.info(f"  -> SKIPPED landing click (too fast: {elapsed:.1f}s after send)")
            else:
                ua = request.headers.get("User-Agent", "") or ""
                device_type, os_name = _classify_client(ua)
                svc.mark_clicked(
                    token,
                    ip=_client_ip(),
                    user_agent=ua,
                    device_type=device_type,
                    os_name=os_name,
                )
                logging.info(
                    f"  -> COUNTED landing click (elapsed={elapsed:.1f}s, "
                    f"device={device_type}, os={os_name})"
                )
        except Exception as exc:
            logging.warning(f"Landing page lookup error for token {token}: {exc}")
    html_path = Path(__file__).parent / "landing_page" / "index.html"
    if not html_path.exists():
        return Response(status=302, headers={"Location": redirect_to, "Cache-Control": "no-store, no-cache"})
    html = html_path.read_text(encoding="utf-8")
    html = html.replace("'__REDIRECT_URL__'", f"'{_js_escape(redirect_to)}'")
    html = html.replace("'__ORG_NAME__'", f"'{config.ORG_NAME}'")
    # Inject the tracking token so the page's JS can call /api/track/ping/<token>
    # only after observing a real user-interaction event.
    safe_token = token if valid_token else ""
    placeholder = "'__TRACKING_TOKEN__'"
    if placeholder in html:
        html = html.replace(placeholder, f"'{_js_escape(safe_token)}'")
        logging.info(f"  -> injected tracking token into landing page (token={safe_token[:8]}…)")
    else:
        logging.warning("  -> landing_page/index.html is OUTDATED: '__TRACKING_TOKEN__' "
                        "placeholder missing; click ping cannot fire. Redeploy required.")
    return Response(html, mimetype="text/html", headers={
        "Cache-Control": "no-store, no-cache, must-revalidate",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
    })


# ---------------------------------------------------------------------------
# Ping tracking – cross-origin beacon
# ---------------------------------------------------------------------------

@app.route("/api/track/ping/<token>", methods=["GET", "POST", "OPTIONS"])
def track_ping(token):
    if request.method == "OPTIONS":
        return "", 200
    if not re.match(r'^[A-Za-z0-9_\-]{10,60}$', token):
        return _json_response({"ok": False})
    _log_tracking_hit("ping", token)
    try:
        svc = PhishingCampaignService()
        is_bot, reason = _is_bot_request()
        elapsed = _seconds_since_sent(svc, token)
        if is_bot:
            logging.info(f"  -> SKIPPED ping click (bot/scanner): {reason}")
        elif 0 <= elapsed < _MIN_CLICK_DELAY_SEC:
            logging.info(f"  -> SKIPPED ping click (too fast: {elapsed:.1f}s after send)")
        else:
            ua = request.headers.get("User-Agent", "") or ""
            device_type, os_name = _classify_client(ua)
            svc.mark_clicked(
                token,
                ip=_client_ip(),
                user_agent=ua,
                device_type=device_type,
                os_name=os_name,
            )
            logging.info(f"  -> COUNTED ping click (elapsed={elapsed:.1f}s, device={device_type}, os={os_name})")
    except Exception as exc:
        logging.warning(f"Ping-tracking error for token {token}: {exc}")
    return _json_response({"ok": True})


# ---------------------------------------------------------------------------
# Report download – CSV export
# ---------------------------------------------------------------------------

@app.route("/api/phish/campaigns/<campaign_id>/report", methods=["GET", "OPTIONS"])
def download_report(campaign_id):
    if request.method == "OPTIONS":
        return "", 200
    role = _get_role()
    if not _can(role, "report"):
        return _unauthorized() if not role else _forbidden("report")
    svc = PhishingCampaignService()
    campaign = svc.get_campaign(campaign_id)
    if not campaign:
        return _json_response({"error": "Campaign not found"}, 404)
    csv_content = svc.generate_csv_report(campaign_id)
    safe_name = re.sub(r"[^a-zA-Z0-9_\-]", "_", campaign.get("name", campaign_id))
    filename = f"phishing_report_{safe_name}.csv"
    return Response(csv_content, mimetype="text/csv", headers={
        "Content-Disposition": f'attachment; filename="{filename}"',
    })


@app.route("/api/phish/campaigns/<campaign_id>/device-stats", methods=["GET", "OPTIONS"])
def campaign_device_stats(campaign_id):
    if request.method == "OPTIONS":
        return "", 200
    role = _get_role()
    if not _can(role, "view_campaigns"):
        return _unauthorized() if not role else _forbidden("view_campaigns")
    svc = PhishingCampaignService()
    campaign = svc.get_campaign(campaign_id)
    if not campaign:
        return _json_response({"error": "Campaign not found"}, 404)
    return _json_response(svc.get_engagement_device_stats(campaign_id))


# ---------------------------------------------------------------------------
# Dashboard stats – all campaigns summary
# ---------------------------------------------------------------------------

@app.route("/api/phish/dashboard", methods=["GET", "OPTIONS"])
def dashboard_summary():
    if request.method == "OPTIONS":
        return "", 200
    role = _get_role()
    if not _can(role, "dashboard"):
        return _unauthorized() if not role else _forbidden("dashboard")
    try:
        svc = PhishingCampaignService()
        campaigns_list = svc.list_campaigns()
        summary = []
        for c in campaigns_list:
            stats = svc.get_dashboard_stats(c["id"])
            if stats:
                summary.append(stats)
        return _json_response(summary)
    except Exception as exc:
        logging.error(f"Dashboard error: {exc}", exc_info=True)
        return _json_response({"error": f"Failed to load dashboard: {exc}"}, 500)


# ---------------------------------------------------------------------------
# AI email generation
# ---------------------------------------------------------------------------

@app.route("/api/phish/ai/generate", methods=["POST", "OPTIONS"])
def ai_generate():
    if request.method == "OPTIONS":
        return "", 200
    role = _get_role()
    if not _can(role, "create_campaign"):
        return _unauthorized() if not role else _forbidden("ai/generate")
    if not _ai_is_configured():
        return _json_response({"error": "Google Gemini is not configured."}, 503)
    try:
        body = request.get_json(force=True)
    except Exception:
        body = {}
    prompt_text = (body.get("prompt") or "").strip()[:2000]
    email_type = (body.get("type") or "custom").strip()
    tone = (body.get("tone") or "professional").strip()
    constraints = (body.get("constraints") or "").strip()[:500]
    if not prompt_text:
        return _json_response({"error": "prompt is required"}, 400)
    try:
        result = _ai_generate_email(
            prompt=prompt_text,
            email_type=email_type,
            tone=tone,
            constraints=constraints,
        )
    except GeminiConfigError as ex:
        return _json_response({"error": str(ex)}, 503)
    except ValueError as ex:
        return _json_response({"error": str(ex)}, 502)
    except Exception as ex:
        logging.error("AI generate error: %s", ex)
        return _json_response({"error": str(ex)}, 502)
    return _json_response(result)


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.route("/api/health", methods=["GET"])
def health_check():
    return _json_response({"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()})


# ---------------------------------------------------------------------------
# Image upload – stores file in static/uploads/ and returns a public URL
# ---------------------------------------------------------------------------

_ALLOWED_IMAGE_EXTS  = {'.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg'}
_MAX_IMAGE_BYTES     = 5 * 1024 * 1024  # 5 MB

@app.route("/api/phish/upload/image", methods=["POST", "OPTIONS"])
def upload_image():
    if request.method == "OPTIONS":
        resp = make_response('', 204)
        resp.headers['Access-Control-Allow-Origin']  = '*'
        resp.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        resp.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-Session-Token'
        return resp

    role = _get_role()
    if not role:
        return _unauthorized()

    file = request.files.get('image')
    if not file or not file.filename:
        return _json_response({'error': 'No file provided'}, 400)

    ext = Path(file.filename).suffix.lower()
    if ext not in _ALLOWED_IMAGE_EXTS:
        return _json_response({'error': f'File type not allowed. Use: {sorted(_ALLOWED_IMAGE_EXTS)}'}, 400)

    data = file.read()
    if len(data) > _MAX_IMAGE_BYTES:
        return _json_response({'error': 'File exceeds 5 MB limit'}, 400)

    filename  = f"{uuid.uuid4().hex}{ext}"
    dest      = _UPLOADS_DIR / filename
    dest.write_bytes(data)

    # Return relative URL — works for both browser preview and CID embedding
    public_url = f"/static/uploads/{filename}"
    return _json_response({'url': public_url})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port, debug=os.environ.get("FLASK_DEBUG", "0") == "1")
