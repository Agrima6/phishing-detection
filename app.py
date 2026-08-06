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
import requests
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
from tenant_service import TenantService
from auth_clerk import auth_clerk_bp, is_clerk_configured

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

app = Flask(__name__, static_folder="static")
app.secret_key = config.SECRET_KEY

# Render sets RENDER=true in every service's environment automatically. In that
# environment the frontend (Vercel) and backend (Render) are different domains,
# so the session cookie must be SameSite=None + Secure or browsers will drop it
# on every cross-origin request. Locally (plain HTTP, same-origin dev) neither
# is needed or possible.
if os.environ.get("RENDER"):
    app.config["SESSION_COOKIE_SAMESITE"] = "None"
    app.config["SESSION_COOKIE_SECURE"] = True

# Register Clerk authentication blueprint
app.register_blueprint(auth_clerk_bp)

logging.basicConfig(level=logging.INFO)

_sendgrid_client = SendGridAPIClient(config.SENDGRID_API_KEY) if config.SENDGRID_API_KEY else None

# Ensure uploads directory exists at startup. Overridable via env var so
# uploads can live on a persistent disk in production (the container
# filesystem otherwise resets on every deploy/restart).
_UPLOADS_DIR = Path(os.environ.get("UPLOADS_DIR", Path(__file__).parent / "static" / "uploads"))
_UPLOADS_DIR.mkdir(parents=True, exist_ok=True)


@app.route("/static/uploads/<path:filename>")
def serve_upload(filename):
    """Explicit route so uploads still serve correctly when UPLOADS_DIR is
    redirected to a persistent disk outside the app's static/ folder."""
    return send_from_directory(_UPLOADS_DIR, filename)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _default_email_config() -> dict:
    """The global .env-configured provider — today's (only) behavior, used
    whenever a campaign has no email_config_id or the id can't be found."""
    return {
        "provider": config.EMAIL_PROVIDER,
        "smtp_host": config.SMTP_HOST, "smtp_port": config.SMTP_PORT,
        "smtp_use_ssl": config.SMTP_USE_SSL,
        "smtp_username": config.SMTP_USERNAME, "smtp_password": config.SMTP_PASSWORD,
        "smtp_from_email": config.SMTP_FROM_EMAIL, "smtp_from_name": config.SMTP_FROM_NAME,
        "sendgrid_api_key": config.SENDGRID_API_KEY,
        "sendgrid_from_email": config.SENDGRID_FROM_EMAIL, "sendgrid_from_name": config.SENDGRID_FROM_NAME,
    }


def _resolve_email_config(email_config_id: str | None, tenant_id: str = "default") -> dict:
    """Resolve which sender profile a campaign should send through.

    Falls back to the global .env config when no profile is selected, the
    referenced profile was deleted, or the tenant settings can't be read —
    a campaign should never fail to send just because of a profile lookup.

    tenant_id must be passed explicitly (not read from the request/session)
    since this runs from the background send-job thread, which has neither.
    """
    cfg = _default_email_config()
    if not email_config_id:
        return cfg
    try:
        raw = TenantService(tenant_id=tenant_id).get_settings_raw()
        match = next((c for c in raw["email_configs"] if c.get("id") == email_config_id), None)
        if not match:
            logging.warning(f"email_config_id {email_config_id} not found – using default gateway")
            return cfg
        cfg["provider"] = match.get("provider", cfg["provider"])
        if cfg["provider"] == "sendgrid":
            cfg["sendgrid_api_key"] = match.get("sendgrid_api_key") or cfg["sendgrid_api_key"]
            cfg["sendgrid_from_email"] = match.get("sendgrid_from_email") or cfg["sendgrid_from_email"]
            cfg["sendgrid_from_name"] = match.get("sendgrid_from_name") or cfg["sendgrid_from_name"]
        else:
            cfg["smtp_host"] = match.get("smtp_host") or cfg["smtp_host"]
            cfg["smtp_port"] = int(match.get("smtp_port") or cfg["smtp_port"])
            cfg["smtp_use_ssl"] = cfg["smtp_port"] == 465
            cfg["smtp_username"] = match.get("smtp_username") or cfg["smtp_username"]
            cfg["smtp_password"] = match.get("smtp_password") or cfg["smtp_password"]
            cfg["smtp_from_email"] = match.get("smtp_from_email") or cfg["smtp_from_email"]
            cfg["smtp_from_name"] = match.get("smtp_from_name") or cfg["smtp_from_name"]
    except Exception as exc:
        logging.error(f"Email config resolution failed for {email_config_id}: {exc}", exc_info=True)
    return cfg


def _send_via_sendgrid(to_email: str, subject: str, body_html: str, sender_display_name: str,
                       cfg: dict) -> None:
    """Send via SendGrid HTTP API (port 443 – firewall-safe)."""
    message = Mail(
        from_email=From(cfg["sendgrid_from_email"], sender_display_name),
        to_emails=To(to_email),
        subject=Subject(subject),
        html_content=HtmlContent(body_html),
    )
    api_key = cfg["sendgrid_api_key"]
    if not api_key:
        raise RuntimeError("SendGrid is not configured (missing SENDGRID_API_KEY)")
    client = SendGridAPIClient(api_key) if api_key != config.SENDGRID_API_KEY else _sendgrid_client
    if client is None:
        raise RuntimeError("SendGrid is not configured (missing SENDGRID_API_KEY)")
    response = client.send(message)
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
def _smtp_connection(cfg: dict):
    """Open a single authenticated SMTP connection with retry (reuse for batch sends)."""
    last_err = None
    for attempt in range(3):
        try:
            if cfg["smtp_use_ssl"]:
                server = smtplib.SMTP_SSL(cfg["smtp_host"], cfg["smtp_port"], timeout=30)
            else:
                server = smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"], timeout=30)
                server.ehlo()
                server.starttls()
                server.ehlo()
            server.login(cfg["smtp_username"], cfg["smtp_password"])
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
    cfg = _resolve_email_config(campaign.get("email_config_id"), tenant_id=campaign.get("tenant_id", "default"))

    try:
        with _smtp_connection(cfg) as conn:
            smtp_conn = conn
            for i, r in enumerate(recipients):
                try:
                    _dispatch_single_email(svc, campaign, r, cfg, _conn=smtp_conn)
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
            _dispatch_single_email(svc, campaign, r, cfg)  # individual connection
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


def _run_send_job(campaign_id: str, label: str, do_validate: bool, tenant_id: str = "default") -> None:
    """Worker that performs validation (optional) + the actual SMTP send.

    Runs in a background thread so the HTTP handler can return immediately -
    there's no Flask request/session here, so the caller must pass the
    already-verified tenant_id explicitly rather than this reading it from
    a request context that doesn't exist.

    Progress + final result are written to _send_jobs[campaign_id].
    """
    try:
        svc = PhishingCampaignService(tenant_id=tenant_id)
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


def _start_send_job(campaign_id: str, label: str, queued: int, do_validate: bool, tenant_id: str = "default") -> bool:
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
        args=(campaign_id, label, do_validate, tenant_id),
        name=f"send-{campaign_id[:8]}",
        daemon=True,
    )
    t.start()
    return True


# ---------------------------------------------------------------------------
# Scheduled sends – a lightweight poller checks every 20s for draft campaigns
# whose scheduled_at has arrived and launches them the same way the manual
# "Deploy" button does.
# ---------------------------------------------------------------------------

def _scheduler_loop():
    while True:
        try:
            # No Flask request context exists in this background thread, so
            # _get_tenant_id() would crash here - this instance's tenant_id
            # is unused anyway since list_due_scheduled_campaigns/
            # list_recipients/set_scheduled_at all operate across every
            # tenant or take campaign_id directly, never self.tenant_id.
            svc = PhishingCampaignService()
            for campaign in svc.list_due_scheduled_campaigns():
                recipients_list = svc.list_recipients(campaign["id"])
                to_send = [r for r in recipients_list if r.get("status") == "pending"]
                svc.set_scheduled_at(campaign["id"], None)
                if not to_send:
                    continue
                started = _start_send_job(campaign["id"], label="Scheduled Send", queued=len(to_send),
                                           do_validate=True, tenant_id=campaign["tenant_id"])
                if started:
                    _log_audit("CAMPAIGN", f"Scheduled campaign \"{campaign['name']}\" launched to {len(to_send)} recipient(s)")
        except Exception:
            logging.exception("Scheduled-send poller iteration failed")
        time.sleep(20)


def _start_scheduler():
    # Flask's debug reloader runs this module twice in a parent watcher
    # process and a child worker process; only the child (which actually
    # serves requests) should run the poller, or scheduled sends would fire
    # twice.
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    if debug_mode and os.environ.get("WERKZEUG_RUN_MAIN") != "true":
        return
    threading.Thread(target=_scheduler_loop, name="campaign-scheduler", daemon=True).start()


_start_scheduler()


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

        cid = f"img{counter[0]}@phishshield"
        counter[0] += 1
        part = MIMEImage(img_data, _subtype=subtype)
        part.add_header("Content-ID", f"<{cid}>")
        part.add_header("Content-Disposition", "inline")
        parts.append(part)
        return f"{prefix}cid:{cid}{suffix}"

    updated = _IMG_SRC_RE.sub(_repl, body_html)
    return updated, parts


def _send_via_smtp(to_email: str, subject: str, body_html: str, sender_display_name: str,
                   cfg: dict, _conn: smtplib.SMTP | None = None) -> None:
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
    msg["From"] = formataddr((sender_display_name, cfg["smtp_from_email"]))
    msg["To"] = to_email

    if _conn is not None:
        _conn.send_message(msg)
    elif cfg["smtp_use_ssl"]:                       # port 465 – Gmail SSL
        with smtplib.SMTP_SSL(cfg["smtp_host"], cfg["smtp_port"], timeout=30) as s:
            s.login(cfg["smtp_username"], cfg["smtp_password"])
            s.send_message(msg)
    else:                                           # port 587 – STARTTLS
        with smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"], timeout=30) as s:
            s.ehlo()
            s.starttls()
            s.ehlo()
            s.login(cfg["smtp_username"], cfg["smtp_password"])
            s.send_message(msg)


def _send_email(to_email: str, subject: str, body_html: str, sender_display_name: str,
                cfg: dict, _conn: smtplib.SMTP | None = None) -> None:
    """Route to the configured email provider."""
    if cfg["provider"] == 'sendgrid':
        _send_via_sendgrid(to_email, subject, body_html, sender_display_name, cfg)
    else:  # gmail / outlook
        _send_via_smtp(to_email, subject, body_html, sender_display_name, cfg, _conn=_conn)


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

# Wildcard origins can't be combined with credentialed requests (cookies), which
# the Clerk-backed session flow requires, so allow-list specific frontend origins.
# Add production frontend URLs via the ALLOWED_ORIGINS env var (comma-separated).
_ALLOWED_ORIGINS = {"http://localhost:3000"} | {
    o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "").split(",") if o.strip()
}


@app.after_request
def add_cors_headers(response):
    origin = request.headers.get("Origin")
    if origin in _ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Admin-Key, Authorization, X-Switch-Tenant"
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
    "super_admin":     {"dashboard", "view_campaigns", "create_campaign", "view_recipients", "add_recipients", "send", "report", "manage_users",
                         "manage_employees", "manage_templates", "manage_settings", "view_audit_logs", "manage_tenants"},
    "admin":           {"dashboard", "view_campaigns", "create_campaign", "view_recipients", "add_recipients", "send", "report", "manage_users",
                         "manage_employees", "manage_templates", "manage_settings", "view_audit_logs"},
    "operator":        {"dashboard", "view_campaigns", "create_campaign", "view_recipients", "add_recipients", "send", "report",
                         "manage_employees", "manage_templates", "view_audit_logs"},
    "auditor":         {"dashboard", "view_campaigns", "view_recipients", "report", "view_audit_logs"},
    "template_author": {"view_campaigns", "create_campaign", "manage_templates"},
}

_ROLE_LABELS = {
    "super_admin": "Super Admin",
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
            "label": _ROLE_LABELS.get(role, role),
            "tenant_id": user.get("tenant_id") or "default"}


def _get_role() -> str | None:
    info = _get_session_info()
    return info["role"] if info else None


def _get_tenant_id() -> str:
    """Which company's data the current admin should see. Super Admin routes
    that operate across all tenants never call this - everything else does,
    including passing it into PhishingCampaignService/TenantService so every
    query is scoped automatically."""
    info = _get_session_info()
    return info["tenant_id"] if info else "default"


def _can(role: str | None, permission: str) -> bool:
    return bool(role and permission in _ROLE_PERMISSIONS.get(role, set()))


def _json_response(data, status_code: int = 200):
    return make_response(jsonify(data), status_code)


def _unauthorized():
    return _json_response({"error": "Unauthorized – provide a valid X-Admin-Key header"}, 401)


def _forbidden(permission: str):
    return _json_response({"error": f"Forbidden – your role does not allow '{permission}'"}, 403)


def _log_audit(category: str, message: str) -> None:
    # Best-effort – a logging failure should never break the action it's recording.
    try:
        info = _get_session_info()
        actor = info["username"] if info else "system"
        tenant_id = info["tenant_id"] if info else "default"
        TenantService(tenant_id=tenant_id).create_audit_log(
            actor=actor, category=category, message=message,
            ip_address=request.remote_addr or "",
        )
    except Exception as exc:
        logging.error(f"Audit log write failed: {exc}", exc_info=True)


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
                smtp.ehlo("phishshield.local")
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
                           email_cfg: dict | None = None, _conn: smtplib.SMTP | None = None) -> None:
    email_cfg = email_cfg or _resolve_email_config(campaign.get("email_config_id"), tenant_id=campaign.get("tenant_id", "default"))
    phishing_cfg = config.get_phishing_config()
    base_url = phishing_cfg["base_url"].rstrip("/")
    tracking_pixel_url = f"{base_url}/api/track/open/{recipient['tracking_token']}"

    github_pages_url = phishing_cfg.get("github_pages_url", "").rstrip("/")
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
                cfg=email_cfg,
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
        svc = PhishingCampaignService(tenant_id=_get_tenant_id())
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
        email_config_id = (body.get("email_config_id") or "").strip() or None
        if not name or not subject or not body_html:
            return _json_response({"error": "name, subject, and body_html are required"}, 400)
        campaign = svc.create_campaign(name, subject, body_html, sender_name, redirect_url, email_config_id)
        _log_audit("CAMPAIGN", f"Campaign \"{name}\" created")
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
        svc = PhishingCampaignService(tenant_id=_get_tenant_id())
        existing = svc.get_campaign(campaign_id)
        ok = svc.delete_campaign(campaign_id)
        if not ok:
            return _json_response({"error": "Campaign not found"}, 404)
        _log_audit("CAMPAIGN", f"Campaign \"{existing['name'] if existing else campaign_id}\" deleted")
        return _json_response({"message": "Campaign deleted"})
    if not _can(role, "view_campaigns"):
        return _unauthorized() if not role else _forbidden("view_campaigns")
    svc = PhishingCampaignService(tenant_id=_get_tenant_id())
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
    svc = PhishingCampaignService(tenant_id=_get_tenant_id())
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
    if created:
        campaign = svc.get_campaign(campaign_id)
        campaign_label = campaign["name"] if campaign else campaign_id
        _log_audit("CAMPAIGN", f"{len(created)} recipient(s) added to campaign \"{campaign_label}\"")
    return _json_response(result, 201)


@app.route("/api/phish/campaigns/<campaign_id>/recipients/<recipient_id>", methods=["DELETE", "OPTIONS"])
def delete_recipient(campaign_id, recipient_id):
    if request.method == "OPTIONS":
        return "", 200
    role = _get_role()
    if not _can(role, "add_recipients"):
        return _unauthorized() if not role else _forbidden("add_recipients")
    svc = PhishingCampaignService(tenant_id=_get_tenant_id())
    target = next((r for r in svc.list_recipients(campaign_id) if r["id"] == recipient_id), None)
    ok = svc.delete_recipient(recipient_id)
    if not ok:
        return _json_response({"error": "Recipient not found"}, 404)
    if target:
        _log_audit("CAMPAIGN", f"Recipient \"{target['email']}\" removed from campaign")
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
    svc = PhishingCampaignService(tenant_id=_get_tenant_id())
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
    svc = PhishingCampaignService(tenant_id=_get_tenant_id())
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
    _log_audit("CAMPAIGN", f"Campaign \"{campaign['name']}\" resent to {queued} recipient(s)")
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
    svc = PhishingCampaignService(tenant_id=_get_tenant_id())
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
    _log_audit("CAMPAIGN", f"Campaign \"{campaign['name']}\" launched to {len(to_send)} recipient(s)")
    return _json_response({
        "queued": len(to_send),
        "campaign_id": campaign_id,
        "state": "queued",
        "message": f"Send queued for {len(to_send)} recipient(s). Running in background."
    }, 202)


@app.route("/api/phish/campaigns/<campaign_id>/schedule", methods=["POST", "OPTIONS"])
def schedule_campaign(campaign_id):
    """Set (or clear, with scheduled_at: null) a future send time for a draft
    campaign. A background poller (_scheduler_loop) launches it automatically
    once that time arrives."""
    if request.method == "OPTIONS":
        return "", 200
    role = _get_role()
    if not _can(role, "send"):
        return _unauthorized() if not role else _forbidden("send")
    svc = PhishingCampaignService(tenant_id=_get_tenant_id())
    campaign = svc.get_campaign(campaign_id)
    if not campaign:
        return _json_response({"error": "Campaign not found"}, 404)
    body = request.get_json(force=True, silent=True) or {}
    scheduled_at = body.get("scheduled_at")
    if scheduled_at:
        try:
            parsed = datetime.fromisoformat(str(scheduled_at).replace("Z", "+00:00"))
        except ValueError:
            return _json_response({"error": "scheduled_at must be a valid ISO 8601 datetime"}, 400)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        if parsed <= datetime.now(timezone.utc):
            return _json_response({"error": "scheduled_at must be in the future"}, 400)
        svc.set_scheduled_at(campaign_id, parsed.isoformat())
        _log_audit("CAMPAIGN", f"Campaign \"{campaign['name']}\" scheduled for {parsed.isoformat()}")
        return _json_response({"scheduled_at": parsed.isoformat()})
    svc.set_scheduled_at(campaign_id, None)
    _log_audit("CAMPAIGN", f"Removed schedule for campaign \"{campaign['name']}\"")
    return _json_response({"scheduled_at": None})


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
    svc = PhishingCampaignService(tenant_id=_get_tenant_id())
    campaign = svc.get_campaign(campaign_id)
    if not campaign:
        return _json_response({"error": "Campaign not found"}, 404)
    cleared = svc.clear_failed_recipients(campaign_id)
    if cleared == 0:
        return _json_response({"message": "No failed recipients to resend"}, 200)
    started = _start_send_job(campaign_id, label="ResendFailed", queued=cleared, do_validate=True)
    if not started:
        return _json_response({"error": "A send is already running for this campaign"}, 409)
    _log_audit("CAMPAIGN", f"Campaign \"{campaign['name']}\" resent to {cleared} previously-failed recipient(s)")
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
    svc = PhishingCampaignService(tenant_id=_get_tenant_id())
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
    svc = PhishingCampaignService(tenant_id=_get_tenant_id())
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
        svc = PhishingCampaignService(tenant_id=_get_tenant_id())
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
        svc = PhishingCampaignService(tenant_id=_get_tenant_id())
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
            svc = PhishingCampaignService(tenant_id=_get_tenant_id())
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
        svc = PhishingCampaignService(tenant_id=_get_tenant_id())
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
    svc = PhishingCampaignService(tenant_id=_get_tenant_id())
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
    svc = PhishingCampaignService(tenant_id=_get_tenant_id())
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
        svc = PhishingCampaignService(tenant_id=_get_tenant_id())
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


@app.route("/api/phish/analytics/overview", methods=["GET", "OPTIONS"])
def analytics_overview():
    if request.method == "OPTIONS":
        return "", 200
    role = _get_role()
    if not _can(role, "dashboard"):
        return _unauthorized() if not role else _forbidden("dashboard")
    try:
        svc = TenantService(tenant_id=_get_tenant_id())
        return _json_response({
            "department_rates": svc.get_department_click_rates(),
            "recent_events": svc.get_recent_risk_events(limit=5),
        })
    except Exception as exc:
        logging.error(f"Analytics overview error: {exc}", exc_info=True)
        return _json_response({"error": f"Failed to load analytics: {exc}"}, 500)


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
# Chatbot – "Shieldy", a small in-app assistant powered by the Gemini
# Generative Language API (simple API-key auth, distinct from the Vertex AI
# service-account setup gemini_service.py uses for AI email generation).
# ---------------------------------------------------------------------------

_CHATBOT_SYSTEM_PROMPT = (
    "You are Shieldy, the friendly built-in assistant for Workmate Shield, a phishing-simulation "
    "and security-awareness platform. You help admins understand how to use the product: creating "
    "phishing simulation campaigns, managing the employee directory, reading risk analytics and "
    "reports, scheduling sends, and general phishing/security-awareness best practices. Keep replies "
    "short (2-4 sentences), warm, and a little playful, using at most one emoji per reply. If asked "
    "something totally unrelated to the product or security awareness, gently redirect back on-topic."
)
_CHATBOT_MODEL = "gemini-2.0-flash"


@app.route("/api/chatbot/message", methods=["POST", "OPTIONS"])
def chatbot_message():
    if request.method == "OPTIONS":
        return "", 200
    role = _get_role()
    if not role:
        return _unauthorized()
    if not config.GEMINI_CHATBOT_API_KEY:
        return _json_response({"error": "Chatbot is not configured on this server"}, 503)

    body = request.get_json(force=True, silent=True) or {}
    message = (body.get("message") or "").strip()
    history = body.get("history") or []  # [{role: "user"|"model", text: str}, ...]
    if not message:
        return _json_response({"error": "message is required"}, 400)

    contents = [
        {"role": "user", "parts": [{"text": _CHATBOT_SYSTEM_PROMPT}]},
        {"role": "model", "parts": [{"text": "Got it — I'm Shieldy! Ready to help. 🛡️"}]},
    ]
    for turn in history[-10:]:
        turn_role = "model" if turn.get("role") == "model" else "user"
        text = (turn.get("text") or "").strip()
        if text:
            contents.append({"role": turn_role, "parts": [{"text": text}]})
    contents.append({"role": "user", "parts": [{"text": message}]})

    try:
        resp = requests.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{_CHATBOT_MODEL}:generateContent",
            params={"key": config.GEMINI_CHATBOT_API_KEY},
            json={"contents": contents, "generationConfig": {"maxOutputTokens": 300, "temperature": 0.8}},
            timeout=20,
        )
        data = resp.json()
        if resp.status_code >= 400:
            err_msg = data.get("error", {}).get("message", "Unknown error")
            logging.warning(f"Chatbot Gemini call failed: {err_msg}")
            return _json_response({
                "reply": "I'm having trouble reaching my brain right now (the AI service reported an error). "
                         "Try again in a moment! 🛡️",
                "error_detail": err_msg,
            }, 200)
        reply = (
            data.get("candidates", [{}])[0]
                .get("content", {})
                .get("parts", [{}])[0]
                .get("text", "")
        ).strip() or "Hmm, I didn't quite catch that — could you rephrase?"
        return _json_response({"reply": reply})
    except Exception as exc:
        logging.error(f"Chatbot call failed: {exc}", exc_info=True)
        return _json_response({
            "reply": "I'm briefly offline — please try again shortly! 🛡️",
            "error_detail": str(exc),
        }, 200)


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
# Employees
# ---------------------------------------------------------------------------

@app.route("/api/phish/employees", methods=["GET", "POST", "OPTIONS"])
def employees():
    if request.method == "OPTIONS":
        return "", 200
    role = _get_role()
    if not _can(role, "manage_employees"):
        return _unauthorized() if not role else _forbidden("manage_employees")
    try:
        svc = TenantService(tenant_id=_get_tenant_id())
        if request.method == "GET":
            return _json_response(svc.list_employees())
        body = request.get_json(force=True, silent=True) or {}
        name = (body.get("name") or "").strip()
        email = (body.get("email") or "").strip()
        if not name or not email:
            return _json_response({"error": "Name and email are required"}, 400)
        employee = svc.create_employee(
            name=name, email=email,
            department=(body.get("department") or "").strip(),
            manager=(body.get("manager") or "").strip(),
            risk_rating=(body.get("riskRating") or "low"),
        )
        _log_audit("EMPLOYEE", f"Employee \"{name}\" ({email}) added")
        return _json_response(employee, 201)
    except Exception as exc:
        if "unique" in str(exc).lower():
            return _json_response({"error": "An employee with this email already exists"}, 409)
        logging.error(f"Employees error: {exc}", exc_info=True)
        return _json_response({"error": f"Server error: {exc}"}, 500)


@app.route("/api/phish/employees/<employee_id>", methods=["PUT", "DELETE", "OPTIONS"])
def employee_detail(employee_id):
    if request.method == "OPTIONS":
        return "", 200
    role = _get_role()
    if not _can(role, "manage_employees"):
        return _unauthorized() if not role else _forbidden("manage_employees")
    try:
        svc = TenantService(tenant_id=_get_tenant_id())
        if request.method == "DELETE":
            existing = svc.get_employee(employee_id)
            deleted = svc.delete_employee(employee_id)
            if not deleted:
                return _json_response({"error": "Employee not found"}, 404)
            _log_audit("EMPLOYEE", f"Employee \"{existing['name'] if existing else employee_id}\" deleted")
            return _json_response({"message": "Employee deleted"})
        body = request.get_json(force=True, silent=True) or {}
        updated = svc.update_employee(employee_id, body)
        if not updated:
            return _json_response({"error": "Employee not found"}, 404)
        _log_audit("EMPLOYEE", f"Employee \"{updated['name']}\" updated")
        return _json_response(updated)
    except Exception as exc:
        logging.error(f"Employee detail error: {exc}", exc_info=True)
        return _json_response({"error": f"Server error: {exc}"}, 500)


@app.route("/api/phish/employees/import", methods=["POST", "OPTIONS"])
def import_employees():
    if request.method == "OPTIONS":
        return "", 200
    role = _get_role()
    if not _can(role, "manage_employees"):
        return _unauthorized() if not role else _forbidden("manage_employees")
    file = request.files.get("file")
    if not file or not file.filename:
        return _json_response({"error": "No file provided"}, 400)
    try:
        result = TenantService(tenant_id=_get_tenant_id()).import_employees_csv(file.read())
        _log_audit(
            "EMPLOYEE",
            f"CSV import: {result['success_count']} added, "
            f"{result['duplicate_count']} duplicates, {result['error_count']} errors",
        )
        return _json_response(result)
    except Exception as exc:
        logging.error(f"Employee import error: {exc}", exc_info=True)
        return _json_response({"error": f"Server error: {exc}"}, 500)


# ---------------------------------------------------------------------------
# Phishing templates
# ---------------------------------------------------------------------------

@app.route("/api/phish/templates", methods=["GET", "POST", "OPTIONS"])
def templates():
    if request.method == "OPTIONS":
        return "", 200
    role = _get_role()
    if request.method == "GET":
        if not _can(role, "view_campaigns"):
            return _unauthorized() if not role else _forbidden("view_campaigns")
    else:
        if not _can(role, "manage_templates"):
            return _unauthorized() if not role else _forbidden("manage_templates")
    try:
        svc = TenantService(tenant_id=_get_tenant_id())
        if request.method == "GET":
            return _json_response(svc.list_templates())
        body = request.get_json(force=True, silent=True) or {}
        name = (body.get("name") or "").strip()
        subject = (body.get("subject") or "").strip()
        template_body = (body.get("body") or "").strip()
        category = (body.get("category") or "").strip()
        if not name or not subject or not template_body or not category:
            return _json_response({"error": "Name, category, subject, and body are required"}, 400)
        template = svc.create_template(
            name=name, category=category, subject=subject, body=template_body,
            description=(body.get("description") or ""),
            thumbnail=(body.get("thumbnail") or ""),
        )
        _log_audit("CAMPAIGN", f"Template \"{name}\" created")
        return _json_response(template, 201)
    except Exception as exc:
        logging.error(f"Templates error: {exc}", exc_info=True)
        return _json_response({"error": f"Server error: {exc}"}, 500)


@app.route("/api/phish/templates/<template_id>", methods=["DELETE", "OPTIONS"])
def template_detail(template_id):
    if request.method == "OPTIONS":
        return "", 200
    role = _get_role()
    if not _can(role, "manage_templates"):
        return _unauthorized() if not role else _forbidden("manage_templates")
    try:
        svc = TenantService(tenant_id=_get_tenant_id())
        existing = next((t for t in svc.list_templates() if (t.get("id") == template_id)), None)
        deleted = svc.delete_template(template_id)
        if not deleted:
            return _json_response({"error": "Template not found or is a global template"}, 404)
        _log_audit("CAMPAIGN", f"Template \"{existing['name'] if existing else template_id}\" deleted")
        return _json_response({"message": "Template deleted"})
    except Exception as exc:
        logging.error(f"Template detail error: {exc}", exc_info=True)
        return _json_response({"error": f"Server error: {exc}"}, 500)


# ---------------------------------------------------------------------------
# Audit logs
# ---------------------------------------------------------------------------

@app.route("/api/phish/audit-logs", methods=["GET", "POST", "OPTIONS"])
def audit_logs():
    if request.method == "OPTIONS":
        return "", 200
    role = _get_role()
    if not _can(role, "view_audit_logs"):
        return _unauthorized() if not role else _forbidden("view_audit_logs")
    try:
        svc = TenantService(tenant_id=_get_tenant_id())
        if request.method == "GET":
            return _json_response(svc.list_audit_logs())
        body = request.get_json(force=True, silent=True) or {}
        actor = (body.get("actor") or "").strip()
        message = (body.get("message") or "").strip()
        if not actor or not message:
            return _json_response({"error": "Actor and message are required"}, 400)
        log = svc.create_audit_log(
            actor=actor, category=(body.get("category") or "SECURITY"),
            message=message, ip_address=(body.get("ipAddress") or request.remote_addr or ""),
        )
        return _json_response(log, 201)
    except Exception as exc:
        logging.error(f"Audit logs error: {exc}", exc_info=True)
        return _json_response({"error": f"Server error: {exc}"}, 500)


# ---------------------------------------------------------------------------
# Tenant settings + branding
# ---------------------------------------------------------------------------

@app.route("/api/tenant/settings", methods=["GET", "POST", "OPTIONS"])
def tenant_settings():
    if request.method == "OPTIONS":
        return "", 200
    role = _get_role()
    if request.method == "GET":
        if not role:
            return _unauthorized()
    else:
        if not _can(role, "manage_settings"):
            return _unauthorized() if not role else _forbidden("manage_settings")
    try:
        svc = TenantService(tenant_id=_get_tenant_id())
        if request.method == "GET":
            return _json_response(svc.to_frontend_shape())
        body = request.get_json(force=True, silent=True) or {}
        raw = svc.save_settings(body)
        sso = body.get("sso_config") or {}
        if sso.get("client_id") or sso.get("client_secret"):
            _log_audit("SSO_CONFIG", "Microsoft Entra ID (OIDC) configuration updated")
        elif body.get("email_configs"):
            _log_audit("SMTP", "Tenant email sender configuration updated")
        else:
            _log_audit("SECURITY", "Tenant branding settings updated")
        return _json_response(svc.to_frontend_shape(raw))
    except Exception as exc:
        logging.error(f"Tenant settings error: {exc}", exc_info=True)
        return _json_response({"error": f"Server error: {exc}"}, 500)


@app.route("/api/tenant/settings/test-email", methods=["POST", "OPTIONS"])
def test_email_config():
    if request.method == "OPTIONS":
        return "", 200
    role = _get_role()
    if not _can(role, "manage_settings"):
        return _unauthorized() if not role else _forbidden("manage_settings")
    body = request.get_json(force=True, silent=True) or {}
    cfg = body.get("config") or {}
    recipient = (body.get("recipient") or "").strip()
    if not recipient:
        return _json_response({"success": False, "error": "Recipient email is required"}, 400)
    try:
        provider = cfg.get("provider", "smtp")
        subject = "PhishShield test email"
        body_html = "<p>This is a test email from your PhishShield tenant settings.</p>"
        if provider == "sendgrid":
            api_key = cfg.get("sendgrid_api_key")
            if not api_key:
                return _json_response({"success": False, "error": "SendGrid API key not configured"}, 400)
            mail = Mail(
                from_email=From(cfg.get("sendgrid_from_email", ""), cfg.get("sendgrid_from_name", "")),
                to_emails=To(recipient),
                subject=Subject(subject),
                html_content=HtmlContent(body_html),
            )
            SendGridAPIClient(api_key).send(mail)
        else:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = formataddr((cfg.get("smtp_from_name", ""), cfg.get("smtp_from_email", "")))
            msg["To"] = recipient
            msg.attach(MIMEText(body_html, "html"))
            host = cfg.get("smtp_host")
            port = int(cfg.get("smtp_port") or 465)
            if not host:
                return _json_response({"success": False, "error": "SMTP host not configured"}, 400)
            if port == 465:
                with smtplib.SMTP_SSL(host, port, timeout=15) as s:
                    s.login(cfg.get("smtp_username", ""), cfg.get("smtp_password", ""))
                    s.send_message(msg)
            else:
                with smtplib.SMTP(host, port, timeout=15) as s:
                    s.starttls()
                    s.login(cfg.get("smtp_username", ""), cfg.get("smtp_password", ""))
                    s.send_message(msg)
        return _json_response({"success": True, "message": f"Test email sent to {recipient}"})
    except Exception as exc:
        logging.error(f"Test email error: {exc}", exc_info=True)
        return _json_response({"success": False, "error": str(exc)}, 200)


_CLERK_API_BASE = "https://api.clerk.com/v1"


def _clerk_headers() -> dict:
    return {"Authorization": f"Bearer {config.CLERK_SECRET_KEY}", "Content-Type": "application/json"}


@app.route("/api/admin/allowlist", methods=["GET", "POST", "OPTIONS"])
def admin_allowlist():
    """Manage who is allowed to create an account at all. Clerk's own
    allowlist restriction (enabled separately) rejects sign-up for any email
    not added here first - this is how a Super Admin controls who at a
    customer company can self-register, without building a custom invite
    flow from scratch."""
    if request.method == "OPTIONS":
        return "", 200
    role = _get_role()
    if not _can(role, "manage_users"):
        return _unauthorized() if not role else _forbidden("manage_users")
    if not config.CLERK_SECRET_KEY:
        return _json_response({"error": "Clerk is not configured on this server"}, 500)

    if request.method == "GET":
        resp = requests.get(f"{_CLERK_API_BASE}/allowlist_identifiers", headers=_clerk_headers(), timeout=15)
        return _json_response(resp.json(), resp.status_code)

    body = request.get_json(force=True, silent=True) or {}
    email = (body.get("email") or "").strip().lower()
    if not email or "@" not in email:
        return _json_response({"error": "A valid email is required"}, 400)
    resp = requests.post(
        f"{_CLERK_API_BASE}/allowlist_identifiers",
        headers=_clerk_headers(),
        json={"identifier": email, "notify": True},
        timeout=15,
    )
    if resp.status_code >= 400:
        return _json_response(resp.json(), resp.status_code)
    _log_audit("SECURITY", f"Allowlisted \"{email}\" for account sign-up")
    return _json_response(resp.json(), resp.status_code)


@app.route("/api/admin/allowlist/<identifier_id>", methods=["DELETE", "OPTIONS"])
def admin_allowlist_delete(identifier_id):
    if request.method == "OPTIONS":
        return "", 200
    role = _get_role()
    if not _can(role, "manage_users"):
        return _unauthorized() if not role else _forbidden("manage_users")
    if not config.CLERK_SECRET_KEY:
        return _json_response({"error": "Clerk is not configured on this server"}, 500)
    resp = requests.delete(
        f"{_CLERK_API_BASE}/allowlist_identifiers/{identifier_id}", headers=_clerk_headers(), timeout=15
    )
    if resp.status_code < 400:
        _log_audit("SECURITY", f"Removed allowlist entry {identifier_id}")
    return _json_response(resp.json() if resp.content else {"deleted": True}, resp.status_code)


@app.route("/api/admin/tenants", methods=["GET", "POST", "OPTIONS"])
def admin_tenants():
    """Super Admin's company registry: onboard a new client company (creates
    an isolated tenant_id + invites its first admin via Clerk, pre-tagged
    with that tenant_id so they land in the right company's data on their
    first login) and list existing ones."""
    if request.method == "OPTIONS":
        return "", 200
    role = _get_role()
    if not _can(role, "manage_tenants"):
        return _unauthorized() if not role else _forbidden("manage_tenants")
    svc = TenantService()  # registry methods operate across all tenants regardless of constructor arg

    if request.method == "GET":
        return _json_response(svc.list_tenants())

    body = request.get_json(force=True, silent=True) or {}
    company_name = (body.get("company_name") or "").strip()
    contact_email = (body.get("contact_email") or "").strip().lower()
    admin_email = (body.get("admin_email") or contact_email).strip().lower()
    contact_mobile = (body.get("contact_mobile") or "").strip()
    designation = (body.get("designation") or "").strip()
    primary_color = (body.get("primary_color") or "#7a1220").strip()
    if not company_name or not contact_email or not admin_email:
        return _json_response({"error": "Company name, contact email, and admin email are required"}, 400)

    tenant = svc.create_tenant(
        company_name=company_name, contact_email=contact_email, admin_email=admin_email,
        contact_mobile=contact_mobile, designation=designation, primary_color=primary_color,
    )

    invite_warning = None
    if config.CLERK_SECRET_KEY:
        resp = requests.post(
            f"{_CLERK_API_BASE}/invitations",
            headers=_clerk_headers(),
            json={
                "email_address": admin_email,
                "public_metadata": {"role": "admin", "tenant_id": tenant["id"]},
                "notify": True,
                "ignore_existing": True,
                "redirect_url": f"{config.FRONTEND_URL}/auth/welcome",
            },
            timeout=15,
        )
        if resp.status_code >= 400:
            invite_warning = f"Company created, but the invite email failed: {resp.json().get('errors', resp.text)}"
    else:
        invite_warning = "Company created, but Clerk is not configured on this server so no invite was sent."

    _log_audit("TENANT", f"Onboarded company \"{company_name}\" (admin: {admin_email})")
    result = dict(tenant)
    if invite_warning:
        result["invite_warning"] = invite_warning
    return _json_response(result, 201)


@app.route("/api/admin/tenants/<tenant_id>", methods=["PUT", "DELETE", "OPTIONS"])
def admin_tenant_detail(tenant_id):
    if request.method == "OPTIONS":
        return "", 200
    role = _get_role()
    if not _can(role, "manage_tenants"):
        return _unauthorized() if not role else _forbidden("manage_tenants")
    if tenant_id == "default":
        return _json_response({"error": "The default tenant can't be edited or deleted here"}, 400)
    svc = TenantService()

    if request.method == "DELETE":
        deleted = svc.delete_tenant(tenant_id)
        if not deleted:
            return _json_response({"error": "Company not found"}, 404)
        _log_audit("TENANT", f"Deleted company {tenant_id} and all of its data")
        return _json_response({"message": "Company deleted"})

    body = request.get_json(force=True, silent=True) or {}
    updates = {}
    for key in ("company_name", "contact_email", "contact_mobile", "designation", "admin_email", "primary_color", "status"):
        if key in body:
            updates[key] = body[key]
    tenant = svc.update_tenant(tenant_id, updates)
    if not tenant:
        return _json_response({"error": "Company not found"}, 404)
    _log_audit("TENANT", f"Updated company \"{tenant['company_name']}\"")
    return _json_response(tenant)


@app.route("/api/auth/branding", methods=["GET", "OPTIONS"])
def branding():
    if request.method == "OPTIONS":
        return "", 200
    try:
        raw = TenantService(tenant_id=_get_tenant_id()).get_settings_raw()
        return _json_response({
            "tenant_id": "default",
            "tenant_name": raw["name"],
            "logo_url": raw["logo_url"],
            "primary_color": raw["primary_color"],
            "sso_configured": bool(raw["sso_client_id"]),
        })
    except Exception as exc:
        logging.error(f"Branding error: {exc}", exc_info=True)
        return _json_response({"error": f"Server error: {exc}"}, 500)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    # threaded=True: the SPA frontend fires several API calls in parallel on
    # page load, which the default single-threaded dev server serializes and
    # frequently drops (net::ERR_FAILED) under that load.
    app.run(host="0.0.0.0", port=port, debug=os.environ.get("FLASK_DEBUG", "0") == "1", threaded=True)
