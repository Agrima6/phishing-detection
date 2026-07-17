"""
Phishing Campaign Service – Azure SQL Database
Campaigns, recipients, and open-events are stored in Azure SQL
(phising-nonprod.database.windows.net).
"""

import csv
import hashlib
import io
import json
import logging
import os
import re
import secrets
import threading
import uuid
from datetime import datetime, timezone, timedelta

import pyodbc

from config import config

# ---------------------------------------------------------------------------
# Azure SQL connection
# ---------------------------------------------------------------------------

_db_lock = threading.Lock()
_db_initialized = False
_db_init_guard = threading.Lock()

# Enable ODBC driver-level connection pooling – reuses TCP/TLS connections
pyodbc.pooling = True

_conn_str_cached: str | None = None


def _get_odbc_driver() -> str:
    """Return the best available MSSQL ODBC driver name."""
    preferred = [
        "ODBC Driver 18 for SQL Server",
        "ODBC Driver 17 for SQL Server",
        "ODBC Driver 13 for SQL Server",
        "SQL Server Native Client 11.0",
        "SQL Server",
    ]
    available = pyodbc.drivers()
    for d in preferred:
        if d in available:
            return f"{{{d}}}"
    raise RuntimeError(
        f"No MSSQL ODBC driver found. Install 'ODBC Driver 18 for SQL Server' from "
        f"https://aka.ms/odbc18 . Available drivers: {available}"
    )


def _get_conn() -> pyodbc.Connection:
    """Return a pooled Azure SQL connection using config credentials."""
    global _conn_str_cached
    if _conn_str_cached is None:
        server   = config.SQL_SERVER
        database = config.SQL_DATABASE
        username = config.SQL_USERNAME
        password = config.SQL_PASSWORD
        driver   = _get_odbc_driver()
        is_legacy = "ODBC Driver" not in driver
        # Local dev override: self-signed certs (e.g. a local SQL Server container) need
        # TrustServerCertificate=yes. Never set this against a real Azure SQL server.
        trust_cert = os.environ.get("SQL_TRUST_SERVER_CERT", "no").lower() == "yes"
        enc_opts = f"Encrypt=yes;TrustServerCertificate={'yes' if (is_legacy or trust_cert) else 'no'};"
        auth_opts = "" if is_legacy else "Authentication=SqlPassword;"
        _conn_str_cached = (
            f"DRIVER={driver};"
            f"SERVER={server};"
            f"DATABASE={database};"
            f"UID={username};"
            f"PWD={password};"
            f"{enc_opts}"
            f"{auth_opts}"
            "Connection Timeout=30;"
        )
    return pyodbc.connect(_conn_str_cached, autocommit=False)


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    if salt is None:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000)
    return key.hex(), salt


def _verify_password(password: str, stored_hash: str, salt: str) -> bool:
    computed, _ = _hash_password(password, salt)
    return secrets.compare_digest(computed, stored_hash)


def _row_to_dict(cursor, row) -> dict:
    """Convert pyodbc row to dict using column names from cursor description."""
    return {col[0]: val for col, val in zip(cursor.description, row)}


def _fetchone_dict(cursor) -> dict | None:
    row = cursor.fetchone()
    if row is None:
        return None
    return _row_to_dict(cursor, row)


def _fetchall_dict(cursor) -> list[dict]:
    rows = cursor.fetchall()
    return [_row_to_dict(cursor, r) for r in rows]


def _is_duplicate_key_error(exc: Exception) -> bool:
    msg = str(exc).lower()
    return ("2627" in msg) or ("2601" in msg) or ("duplicate key" in msg) or ("unique key" in msg)


# ---------------------------------------------------------------------------
# Schema initialisation
# ---------------------------------------------------------------------------

def _init_db():
    """Create tables if they don't already exist (idempotent)."""
    ddl_statements = [
        """
        IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'campaigns')
        CREATE TABLE campaigns (
            id               NVARCHAR(36)  NOT NULL PRIMARY KEY,
            name             NVARCHAR(255) NOT NULL,
            subject          NVARCHAR(500) NOT NULL,
            body_html        NVARCHAR(MAX) NOT NULL,
            sender_name      NVARCHAR(255) NOT NULL DEFAULT 'Security Team',
            redirect_url     NVARCHAR(500) NOT NULL DEFAULT '',
            status           NVARCHAR(50)  NOT NULL DEFAULT 'draft',
            created_at       NVARCHAR(50)  NOT NULL,
            updated_at       NVARCHAR(50)  NOT NULL,
            total_sent       INT           NOT NULL DEFAULT 0,
            total_opened     INT           NOT NULL DEFAULT 0,
            total_clicked    INT           NOT NULL DEFAULT 0,
            total_failed     INT           NOT NULL DEFAULT 0,
            total_duplicates INT           NOT NULL DEFAULT 0
        )
        """,
        """
        IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'recipients')
        CREATE TABLE recipients (
            id             NVARCHAR(36)  NOT NULL PRIMARY KEY,
            campaign_id    NVARCHAR(36)  NOT NULL,
            email          NVARCHAR(255) NOT NULL,
            name           NVARCHAR(255) NOT NULL,
            tracking_token NVARCHAR(100) NOT NULL UNIQUE,
            status         NVARCHAR(50)  NOT NULL DEFAULT 'pending',
            sent_at        NVARCHAR(50)  NULL,
            opened_at      NVARCHAR(50)  NULL,
            open_count     INT           NOT NULL DEFAULT 0,
            click_count    INT           NOT NULL DEFAULT 0,
            clicked_at     NVARCHAR(50)  NULL,
            failed_at      NVARCHAR(50)  NULL,
            fail_reason    NVARCHAR(500) NULL,
            send_count     INT           NOT NULL DEFAULT 0,
            created_at     NVARCHAR(50)  NOT NULL,
            CONSTRAINT UQ_recipients_campaign_email UNIQUE (campaign_id, email)
        )
        """,
        """
        IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'events')
        CREATE TABLE events (
            id          NVARCHAR(36)  NOT NULL PRIMARY KEY,
            campaign_id NVARCHAR(36)  NOT NULL,
            email       NVARCHAR(255) NOT NULL,
            event_type  NVARCHAR(50)  NOT NULL,
            token       NVARCHAR(100) NOT NULL,
            occurred_at NVARCHAR(50)  NOT NULL
        )
        """,
        """
        IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'users')
        CREATE TABLE users (
            id            NVARCHAR(36)  NOT NULL PRIMARY KEY,
            username      NVARCHAR(255) NOT NULL UNIQUE,
            password_hash NVARCHAR(255) NOT NULL,
            salt          NVARCHAR(64)  NOT NULL,
            role          NVARCHAR(50)  NOT NULL DEFAULT 'auditor',
            created_by    NVARCHAR(255) NOT NULL DEFAULT 'system',
            created_at    NVARCHAR(50)  NOT NULL,
            is_active     INT           NOT NULL DEFAULT 1
        )
        """,
        """
        IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'sessions')
        CREATE TABLE sessions (
            token       NVARCHAR(100) NOT NULL PRIMARY KEY,
            user_id     NVARCHAR(36)  NOT NULL,
            username    NVARCHAR(255) NOT NULL,
            role        NVARCHAR(50)  NOT NULL,
            created_at  NVARCHAR(50)  NOT NULL,
            expires_at  NVARCHAR(50)  NOT NULL
        )
        """,
    ]
    # Indexes for performance – idempotent (IF NOT EXISTS)
    index_statements = [
        # recipients: fast lookup by campaign_id (list_recipients, dashboard stats, delete)
        """IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_recipients_campaign_id' AND object_id = OBJECT_ID('recipients'))
           CREATE NONCLUSTERED INDEX IX_recipients_campaign_id ON recipients (campaign_id) INCLUDE (status, click_count)""",
        # recipients: fast lookup by campaign + status (dashboard COUNT queries)
        """IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_recipients_campaign_status' AND object_id = OBJECT_ID('recipients'))
           CREATE NONCLUSTERED INDEX IX_recipients_campaign_status ON recipients (campaign_id, status)""",
        # events: fast lookup/delete by campaign_id
        """IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_events_campaign_id' AND object_id = OBJECT_ID('events'))
           CREATE NONCLUSTERED INDEX IX_events_campaign_id ON events (campaign_id)""",
        # events: fast delete by token
        """IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_events_token' AND object_id = OBJECT_ID('events'))
           CREATE NONCLUSTERED INDEX IX_events_token ON events (token)""",
        # events: fast delete by campaign + event_type (clear_failed_recipients)
        """IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_events_campaign_type' AND object_id = OBJECT_ID('events'))
           CREATE NONCLUSTERED INDEX IX_events_campaign_type ON events (campaign_id, event_type)""",
        # users: fast lookup by username + is_active (authenticate_user)
        """IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_users_username_active' AND object_id = OBJECT_ID('users'))
           CREATE NONCLUSTERED INDEX IX_users_username_active ON users (username, is_active)""",
    ]

    # Online schema upgrades for recipient device metadata (idempotent)
    alter_statements = [
        """IF COL_LENGTH('recipients', 'opened_device_type') IS NULL ALTER TABLE recipients ADD opened_device_type NVARCHAR(30) NULL""",
        """IF COL_LENGTH('recipients', 'opened_os') IS NULL ALTER TABLE recipients ADD opened_os NVARCHAR(30) NULL""",
        """IF COL_LENGTH('recipients', 'opened_ip') IS NULL ALTER TABLE recipients ADD opened_ip NVARCHAR(64) NULL""",
        """IF COL_LENGTH('recipients', 'opened_ua') IS NULL ALTER TABLE recipients ADD opened_ua NVARCHAR(300) NULL""",
        """IF COL_LENGTH('recipients', 'clicked_device_type') IS NULL ALTER TABLE recipients ADD clicked_device_type NVARCHAR(30) NULL""",
        """IF COL_LENGTH('recipients', 'clicked_os') IS NULL ALTER TABLE recipients ADD clicked_os NVARCHAR(30) NULL""",
        """IF COL_LENGTH('recipients', 'clicked_ip') IS NULL ALTER TABLE recipients ADD clicked_ip NVARCHAR(64) NULL""",
        """IF COL_LENGTH('recipients', 'clicked_ua') IS NULL ALTER TABLE recipients ADD clicked_ua NVARCHAR(300) NULL""",
    ]

    with _db_lock:
        conn = _get_conn()
        cursor = conn.cursor()
        for ddl in ddl_statements:
            cursor.execute(ddl)
        for alter in alter_statements:
            cursor.execute(alter)
        for idx in index_statements:
            cursor.execute(idx)
        conn.commit()
        conn.close()
    logging.info("Azure SQL schema initialised.")


def _seed_default_admin():
    """Create the initial admin user if no users exist yet."""
    username = getattr(config, 'PHISHING_ADMIN_USERNAME', None) or 'admin'
    password = getattr(config, 'PHISHING_ADMIN_PASSWORD', None) or 'Admin@123'
    with _db_lock:
        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]
        if count == 0:
            password_hash, salt = _hash_password(password)
            cursor.execute(
                """INSERT INTO users (id, username, password_hash, salt, role, created_by, created_at, is_active)
                   VALUES (?, ?, ?, ?, 'admin', 'system', ?, 1)""",
                (str(uuid.uuid4()), username, password_hash, salt, _utcnow_iso()),
            )
            conn.commit()
            logging.info(f"\U0001f510 Default admin user '{username}' created in Azure SQL.")
        conn.close()


# DB is initialised lazily on first use – not at import time.
# This prevents a DB connection failure from crashing func start and
# blocking all 0 functions from loading.
def _ensure_db_ready():
    global _db_initialized
    if _db_initialized:
        return
    # Guard first-time init so concurrent requests don't run init twice.
    with _db_init_guard:
        if _db_initialized:
            return
        _init_db()
        _seed_default_admin()
        _db_initialized = True


class PhishingCampaignService:
    """Service layer for the phishing-awareness dashboard (Azure SQL backend)."""

    def __init__(self):
        _ensure_db_ready()  # lazy init – safe to call multiple times
        cfg = config.get_phishing_config()
        self._base_url = cfg["base_url"].rstrip("/")

    # ------------------------------------------------------------------
    # Campaign CRUD
    # ------------------------------------------------------------------

    def create_campaign(self, name: str, subject: str, body_html: str,
                        sender_name: str = "Security Team",
                        redirect_url: str = "") -> dict:
        campaign_id = str(uuid.uuid4())
        now = _utcnow_iso()
        row = {
            "id": campaign_id, "name": name, "subject": subject,
            "body_html": body_html, "sender_name": sender_name,
            "redirect_url": redirect_url,
            "status": "draft", "created_at": now, "updated_at": now,
            "total_sent": 0, "total_opened": 0, "total_clicked": 0,
            "total_failed": 0, "total_duplicates": 0,
        }
        with _db_lock:
            conn = _get_conn()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO campaigns
                  (id, name, subject, body_html, sender_name, redirect_url, status,
                   created_at, updated_at, total_sent, total_opened, total_clicked,
                   total_failed, total_duplicates)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (row["id"], row["name"], row["subject"], row["body_html"],
                  row["sender_name"], row["redirect_url"], row["status"],
                  row["created_at"], row["updated_at"], 0, 0, 0, 0, 0))
            conn.commit()
            conn.close()
        logging.info(f"Campaign created: {campaign_id} – {name}")
        return row

    def list_campaigns(self) -> list:
        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM campaigns ORDER BY created_at DESC")
        rows = _fetchall_dict(cursor)
        conn.close()
        return rows

    def get_campaign(self, campaign_id: str) -> dict | None:
        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM campaigns WHERE id = ?", (campaign_id,))
        row = _fetchone_dict(cursor)
        conn.close()
        return row

    def update_campaign_stats(self, campaign_id: str,
                              sent_delta: int = 0, opened_delta: int = 0,
                              clicked_delta: int = 0, failed_delta: int = 0,
                              duplicate_delta: int = 0):
        with _db_lock:
            conn = _get_conn()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE campaigns
                SET total_sent       = total_sent       + ?,
                    total_opened     = total_opened     + ?,
                    total_clicked    = total_clicked    + ?,
                    total_failed     = total_failed     + ?,
                    total_duplicates = total_duplicates + ?,
                    updated_at       = ?,
                    status = CASE
                        WHEN status = 'draft' AND ? > 0 THEN 'active'
                        ELSE status
                    END
                WHERE id = ?
            """, (sent_delta, opened_delta, clicked_delta, failed_delta,
                  duplicate_delta, _utcnow_iso(), sent_delta, campaign_id))
            conn.commit()
            conn.close()

    # ------------------------------------------------------------------
    # Recipients
    # ------------------------------------------------------------------

    def add_recipients(self, campaign_id: str, recipients: list[dict]) -> list[dict]:
        """Bulk-insert recipients.

        For large lists (e.g. 4,500 entries) the previous per-row SELECT+INSERT
        loop did 9,000+ WAN round-trips to Azure SQL and routinely exceeded the
        gunicorn worker timeout. This implementation:
          1. Issues ONE batched SELECT to find which emails already exist.
          2. Issues ONE executemany INSERT for all new rows (fast_executemany
             where supported – ODBC Driver 18 ships it).
          3. Falls back to a per-row insert only on the rare unique-constraint
             race so a single bad row never aborts the whole batch.

        Time complexity: O(N) DB calls collapses to O(2) for N recipients.
        """
        if not recipients:
            return []
        now = _utcnow_iso()

        # Normalize and de-duplicate input within this batch (lower-case email).
        seen_in_batch: set[str] = set()
        normalized: list[dict] = []
        for r in recipients:
            email = (r.get("email") or "").strip().lower()
            if not email or email in seen_in_batch:
                continue
            seen_in_batch.add(email)
            normalized.append({"email": email, "name": r.get("name", email)})

        if not normalized:
            return []

        conn = _get_conn()
        cursor = conn.cursor()
        try:
            # ---- Step 1: batched existence check ----
            # SQL Server caps parameter count at ~2100 per query; chunk to 500.
            existing_by_email: dict[str, dict] = {}
            CHUNK = 500
            emails = [r["email"] for r in normalized]
            for i in range(0, len(emails), CHUNK):
                chunk = emails[i:i + CHUNK]
                placeholders = ",".join(["?"] * len(chunk))
                cursor.execute(
                    f"SELECT * FROM recipients WHERE campaign_id = ? "
                    f"AND email IN ({placeholders})",
                    (campaign_id, *chunk),
                )
                for row in _fetchall_dict(cursor):
                    existing_by_email[row["email"].lower()] = row

            # ---- Step 2: build NEW rows for emails not already present ----
            new_rows: list[dict] = []
            created: list[dict] = []
            for r in normalized:
                if r["email"] in existing_by_email:
                    created.append(existing_by_email[r["email"]])
                    continue
                new_rows.append({
                    "id": str(uuid.uuid4()),
                    "campaign_id": campaign_id,
                    "email": r["email"],
                    "name": r["name"],
                    "tracking_token": secrets.token_urlsafe(24),
                    "status": "pending",
                    "sent_at": None,
                    "opened_at": None,
                    "open_count": 0,
                    "click_count": 0,
                    "clicked_at": None,
                    "created_at": now,
                })

            # ---- Step 3: batched INSERT via fast_executemany ----
            if new_rows:
                try:
                    cursor.fast_executemany = True
                except Exception:
                    pass  # not all drivers support it; falls back to regular executemany
                insert_sql = """
                    INSERT INTO recipients
                      (id, campaign_id, email, name, tracking_token, status,
                       sent_at, opened_at, open_count, click_count, clicked_at, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """
                params = [
                    (row["id"], row["campaign_id"], row["email"], row["name"],
                     row["tracking_token"], row["status"],
                     row["sent_at"], row["opened_at"],
                     row["open_count"], row["click_count"],
                     row["clicked_at"], row["created_at"])
                    for row in new_rows
                ]
                try:
                    cursor.executemany(insert_sql, params)
                except Exception as exc:
                    if not _is_duplicate_key_error(exc):
                        raise
                    # Rare race: another worker inserted the same email between
                    # our SELECT and INSERT. Retry the remaining rows one-by-one
                    # so a single duplicate doesn't lose the whole batch.
                    conn.rollback()
                    cursor.fast_executemany = False
                    for row in new_rows:
                        try:
                            cursor.execute(insert_sql,
                                           (row["id"], row["campaign_id"], row["email"], row["name"],
                                            row["tracking_token"], row["status"],
                                            row["sent_at"], row["opened_at"],
                                            row["open_count"], row["click_count"],
                                            row["clicked_at"], row["created_at"]))
                        except Exception as inner:
                            if not _is_duplicate_key_error(inner):
                                raise
                created.extend(new_rows)

            conn.commit()
        finally:
            conn.close()

        return created

    def delete_campaign(self, campaign_id: str) -> bool:
        with _db_lock:
            conn = _get_conn()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM events     WHERE campaign_id = ?", (campaign_id,))
            cursor.execute("DELETE FROM recipients WHERE campaign_id = ?", (campaign_id,))
            cursor.execute("DELETE FROM campaigns  WHERE id = ?", (campaign_id,))
            affected = cursor.rowcount
            conn.commit()
            conn.close()
        return affected > 0

    def delete_recipient(self, recipient_id: str) -> bool:
        with _db_lock:
            conn = _get_conn()
            cursor = conn.cursor()
            cursor.execute("SELECT tracking_token FROM recipients WHERE id = ?", (recipient_id,))
            rec = cursor.fetchone()
            if rec:
                cursor.execute("DELETE FROM events WHERE token = ?", (rec[0],))
            cursor.execute("DELETE FROM recipients WHERE id = ?", (recipient_id,))
            affected = cursor.rowcount
            conn.commit()
            conn.close()
        return affected > 0

    def reset_for_resend(self, campaign_id: str) -> int:
        now = _utcnow_iso()
        with _db_lock:
            conn = _get_conn()
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM recipients WHERE campaign_id = ?", (campaign_id,))
            recs = cursor.fetchall()
            for rec in recs:
                new_token = secrets.token_urlsafe(24)
                cursor.execute("""
                    UPDATE recipients
                    SET status = 'pending', tracking_token = ?,
                        sent_at = NULL, opened_at = NULL, open_count = 0,
                        click_count = 0, clicked_at = NULL,
                        failed_at = NULL, fail_reason = NULL
                    WHERE id = ?
                """, (new_token, rec[0]))
            cursor.execute("""
                UPDATE campaigns
                SET total_sent = 0, total_opened = 0, total_clicked = 0,
                    total_failed = 0,
                    status = 'draft', updated_at = ?
                WHERE id = ?
            """, (now, campaign_id))
            cursor.execute("DELETE FROM events WHERE campaign_id = ?", (campaign_id,))
            conn.commit()
            conn.close()
        return len(recs)

    def get_sent_at_for_token(self, token: str) -> str:
        """Return the ISO sent_at timestamp for a recipient's tracking token,
        or empty string if not found / not yet sent."""
        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT sent_at FROM recipients WHERE tracking_token = ?", (token,))
        row = cursor.fetchone()
        conn.close()
        return (row[0] if row and row[0] else "") or ""

    def list_recipients(self, campaign_id: str) -> list:
        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM recipients WHERE campaign_id = ?", (campaign_id,))
        rows = _fetchall_dict(cursor)
        conn.close()
        return rows

    def mark_opened(self, token: str, *, ip: str = "", user_agent: str = "",
                    device_type: str = "", os_name: str = "") -> bool:
        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM recipients WHERE tracking_token = ?", (token,))
        rec = _fetchone_dict(cursor)
        conn.close()
        if not rec:
            return False
        now = _utcnow_iso()
        first_open = rec["status"] != "opened"
        with _db_lock:
            conn2 = _get_conn()
            c2 = conn2.cursor()
            c2.execute("""
                UPDATE recipients
                SET status            = 'opened',
                    open_count        = open_count + 1,
                    opened_at         = COALESCE(opened_at, ?),
                    opened_device_type= COALESCE(opened_device_type, ?),
                    opened_os         = COALESCE(opened_os, ?),
                    opened_ip         = COALESCE(opened_ip, ?),
                    opened_ua         = COALESCE(opened_ua, ?)
                WHERE tracking_token = ?
            """, (now, device_type[:30], os_name[:30], ip[:64], user_agent[:300], token))
            c2.execute("""
                INSERT INTO events (id, campaign_id, email, event_type, token, occurred_at)
                VALUES (?, ?, ?, 'open', ?, ?)
            """, (str(uuid.uuid4()), rec["campaign_id"], rec["email"], token, now))
            conn2.commit()
            conn2.close()
        if first_open:
            self.update_campaign_stats(rec["campaign_id"], opened_delta=1)
        return True

    def mark_clicked(self, token: str, *, ip: str = "", user_agent: str = "",
                     device_type: str = "", os_name: str = "") -> bool:
        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM recipients WHERE tracking_token = ?", (token,))
        rec = _fetchone_dict(cursor)
        conn.close()
        if not rec:
            return False
        now = _utcnow_iso()
        first_click = (rec.get("click_count") or 0) == 0
        with _db_lock:
            conn2 = _get_conn()
            c2 = conn2.cursor()
            c2.execute("""
                UPDATE recipients
                SET status             = CASE WHEN status != 'opened' THEN 'opened' ELSE status END,
                    click_count        = click_count + 1,
                    clicked_at         = COALESCE(clicked_at, ?),
                    opened_at          = COALESCE(opened_at, ?),
                    open_count         = CASE WHEN opened_at IS NULL THEN open_count + 1 ELSE open_count END,
                    clicked_device_type= COALESCE(clicked_device_type, ?),
                    clicked_os         = COALESCE(clicked_os, ?),
                    clicked_ip         = COALESCE(clicked_ip, ?),
                    clicked_ua         = COALESCE(clicked_ua, ?),
                    opened_device_type = COALESCE(opened_device_type, ?),
                    opened_os          = COALESCE(opened_os, ?),
                    opened_ip          = COALESCE(opened_ip, ?),
                    opened_ua          = COALESCE(opened_ua, ?)
                WHERE tracking_token = ?
            """, (now, now,
                  device_type[:30], os_name[:30], ip[:64], user_agent[:300],
                  device_type[:30], os_name[:30], ip[:64], user_agent[:300],
                  token))
            c2.execute("""
                INSERT INTO events (id, campaign_id, email, event_type, token, occurred_at)
                VALUES (?, ?, ?, 'click', ?, ?)
            """, (str(uuid.uuid4()), rec["campaign_id"], rec["email"], token, now))
            conn2.commit()
            conn2.close()
        if first_click:
            self.update_campaign_stats(rec["campaign_id"], clicked_delta=1)
        return True

    def get_redirect_url_for_token(self, token: str) -> str:
        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT c.redirect_url FROM recipients r
            JOIN campaigns c ON r.campaign_id = c.id
            WHERE r.tracking_token = ?
        """, (token,))
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else ""

    def mark_sent(self, campaign_id: str, email: str):
        now = _utcnow_iso()
        email_lower = email.strip().lower()
        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT send_count FROM recipients WHERE campaign_id = ? AND email = ?",
            (campaign_id, email_lower)
        )
        row = cursor.fetchone()
        conn.close()
        prior_sends = (row[0] if row else 0) or 0
        is_duplicate = prior_sends >= 1
        with _db_lock:
            conn2 = _get_conn()
            c2 = conn2.cursor()
            c2.execute("""
                UPDATE recipients
                SET status = 'sent', sent_at = ?, send_count = send_count + 1
                WHERE campaign_id = ? AND email = ?
            """, (now, campaign_id, email_lower))
            conn2.commit()
            conn2.close()
        self.update_campaign_stats(
            campaign_id,
            sent_delta=1,
            duplicate_delta=(1 if is_duplicate else 0)
        )

    def mark_failed(self, campaign_id: str, email: str, reason: str = "") -> None:
        now = _utcnow_iso()
        with _db_lock:
            conn = _get_conn()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE recipients SET status = 'failed', failed_at = ?, fail_reason = ?
                WHERE campaign_id = ? AND email = ?
            """, (now, reason[:500], campaign_id, email.strip().lower()))
            cursor.execute(
                "SELECT tracking_token FROM recipients WHERE campaign_id = ? AND email = ?",
                (campaign_id, email.strip().lower())
            )
            row = cursor.fetchone()
            token = row[0] if row else ""
            cursor.execute("""
                INSERT INTO events (id, campaign_id, email, event_type, token, occurred_at)
                VALUES (?, ?, ?, 'fail', ?, ?)
            """, (str(uuid.uuid4()), campaign_id, email.strip().lower(), token, now))
            conn.commit()
            conn.close()
        self.update_campaign_stats(campaign_id, failed_delta=1)

    def clear_duplicate_count(self, campaign_id: str) -> int:
        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT total_duplicates FROM campaigns WHERE id = ?", (campaign_id,))
        row = cursor.fetchone()
        conn.close()
        dup_count = (row[0] if row else 0) or 0
        if dup_count == 0:
            return 0
        with _db_lock:
            conn2 = _get_conn()
            c2 = conn2.cursor()
            c2.execute(
                "UPDATE recipients SET send_count = CASE WHEN send_count > 1 THEN 1 ELSE send_count END WHERE campaign_id = ?",
                (campaign_id,)
            )
            c2.execute(
                "UPDATE campaigns SET total_duplicates = 0, updated_at = ? WHERE id = ?",
                (_utcnow_iso(), campaign_id)
            )
            conn2.commit()
            conn2.close()
        return dup_count

    def clear_failed_recipients(self, campaign_id: str) -> int:
        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT COUNT(*) FROM recipients WHERE campaign_id = ? AND status = 'failed'",
            (campaign_id,)
        )
        count = cursor.fetchone()[0]
        conn.close()
        if count == 0:
            return 0
        with _db_lock:
            conn2 = _get_conn()
            c2 = conn2.cursor()
            c2.execute("""
                UPDATE recipients
                SET status = 'pending', failed_at = NULL, fail_reason = NULL
                WHERE campaign_id = ? AND status = 'failed'
            """, (campaign_id,))
            c2.execute(
                "DELETE FROM events WHERE campaign_id = ? AND event_type = 'fail'",
                (campaign_id,)
            )
            c2.execute(
                "UPDATE campaigns SET total_failed = 0, updated_at = ? WHERE id = ?",
                (_utcnow_iso(), campaign_id)
            )
            conn2.commit()
            conn2.close()
        return count

    def _tracking_pixel_url(self, token: str) -> str:
        return f"{self._base_url}/api/track/open/{token}"

    # ------------------------------------------------------------------
    # Reports
    # ------------------------------------------------------------------

    def generate_csv_report(self, campaign_id: str) -> str:
        recipients = self.list_recipients(campaign_id)
        output = io.StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=["email", "name", "status", "sent_at", "opened_at", "open_count",
                         "clicked_at", "click_count", "send_count"],
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(recipients)
        return output.getvalue()

    def get_dashboard_stats(self, campaign_id: str) -> dict:
        campaign = self.get_campaign(campaign_id)
        if not campaign:
            return {}
        conn = _get_conn()
        cursor = conn.cursor()
        # Single query instead of 6 round-trips
        cursor.execute("""
            SELECT
                COUNT(*)                                                          AS total,
                SUM(CASE WHEN status = 'pending'              THEN 1 ELSE 0 END) AS pending,
                SUM(CASE WHEN status = 'opened'               THEN 1 ELSE 0 END) AS opened,
                SUM(CASE WHEN status IN ('sent','opened')     THEN 1 ELSE 0 END) AS sent,
                SUM(CASE WHEN click_count > 0                 THEN 1 ELSE 0 END) AS clicked,
                SUM(CASE WHEN status = 'failed'               THEN 1 ELSE 0 END) AS failed
            FROM recipients WHERE campaign_id = ?
        """, (campaign_id,))
        row = cursor.fetchone()
        conn.close()
        total   = row[0] or 0
        pending = row[1] or 0
        opened  = row[2] or 0
        sent    = row[3] or 0
        clicked = row[4] or 0
        failed  = row[5] or 0
        return {
            "campaign_id":      campaign_id,
            "name":             campaign["name"],
            "subject":          campaign["subject"],
            "status":           campaign["status"],
            "total":            total,
            "pending":          pending,
            "sent":             sent,
            "opened":           opened,
            "clicked":          clicked,
            "failed":           failed,
            "total_clicked":    campaign.get("total_clicked", 0),
            "total_failed":     campaign.get("total_failed", 0),
            "total_duplicates": campaign.get("total_duplicates", 0),
            "open_rate":        round(opened / sent * 100, 1) if sent > 0 else 0,
            "click_rate":       round(clicked / sent * 100, 1) if sent > 0 else 0,
            "created_at":       campaign["created_at"],
        }

    def get_engagement_device_stats(self, campaign_id: str) -> dict:
        """Return open/click device and OS breakdown for campaign analytics UI."""
        conn = _get_conn()
        cursor = conn.cursor()

        def _run_group(query: str) -> list[dict]:
            cursor.execute(query, (campaign_id,))
            rows = cursor.fetchall()
            return [{"label": (r[0] or "Unknown"), "count": int(r[1] or 0)} for r in rows]

        open_by_device = _run_group("""
            SELECT COALESCE(NULLIF(opened_device_type, ''), 'Unknown') AS label, COUNT(*) AS c
            FROM recipients
            WHERE campaign_id = ? AND opened_at IS NOT NULL
            GROUP BY COALESCE(NULLIF(opened_device_type, ''), 'Unknown')
            ORDER BY c DESC
        """)
        open_by_os = _run_group("""
            SELECT COALESCE(NULLIF(opened_os, ''), 'Unknown') AS label, COUNT(*) AS c
            FROM recipients
            WHERE campaign_id = ? AND opened_at IS NOT NULL
            GROUP BY COALESCE(NULLIF(opened_os, ''), 'Unknown')
            ORDER BY c DESC
        """)
        click_by_device = _run_group("""
            SELECT COALESCE(NULLIF(clicked_device_type, ''), 'Unknown') AS label, COUNT(*) AS c
            FROM recipients
            WHERE campaign_id = ? AND clicked_at IS NOT NULL
            GROUP BY COALESCE(NULLIF(clicked_device_type, ''), 'Unknown')
            ORDER BY c DESC
        """)
        click_by_os = _run_group("""
            SELECT COALESCE(NULLIF(clicked_os, ''), 'Unknown') AS label, COUNT(*) AS c
            FROM recipients
            WHERE campaign_id = ? AND clicked_at IS NOT NULL
            GROUP BY COALESCE(NULLIF(clicked_os, ''), 'Unknown')
            ORDER BY c DESC
        """)

        conn.close()
        return {
            "open_by_device": open_by_device,
            "open_by_os": open_by_os,
            "click_by_device": click_by_device,
            "click_by_os": click_by_os,
        }

    # ------------------------------------------------------------------
    # User management
    # ------------------------------------------------------------------

    def create_user(self, username: str, password: str, role: str, created_by: str) -> dict:
        user_id = str(uuid.uuid4())
        now = _utcnow_iso()
        password_hash, salt = _hash_password(password)
        with _db_lock:
            conn = _get_conn()
            cursor = conn.cursor()
            cursor.execute(
                """INSERT INTO users (id, username, password_hash, salt, role, created_by, created_at, is_active)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 1)""",
                (user_id, username.strip(), password_hash, salt, role, created_by, now),
            )
            conn.commit()
            conn.close()
        logging.info(f"\U0001f464 User created: {username} (role={role}, by={created_by})")
        return {"id": user_id, "username": username.strip(), "role": role,
                "created_by": created_by, "created_at": now, "is_active": 1}

    def list_users(self) -> list:
        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, role, created_by, created_at, is_active FROM users ORDER BY created_at DESC"
        )
        rows = _fetchall_dict(cursor)
        conn.close()
        return rows

    def delete_user(self, user_id: str) -> bool:
        with _db_lock:
            conn = _get_conn()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
            affected = cursor.rowcount
            conn.commit()
            conn.close()
        return affected > 0

    def update_user_role(self, user_id: str, role: str) -> bool:
        with _db_lock:
            conn = _get_conn()
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
            affected = cursor.rowcount
            conn.commit()
            conn.close()
        return affected > 0

    def reset_user_password(self, user_id: str, new_password: str) -> bool:
        password_hash, salt = _hash_password(new_password)
        with _db_lock:
            conn = _get_conn()
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET password_hash = ?, salt = ? WHERE id = ?",
                (password_hash, salt, user_id),
            )
            affected = cursor.rowcount
            conn.commit()
            conn.close()
        return affected > 0

    def authenticate_user(self, username: str, password: str) -> dict | None:
        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE username = ? AND is_active = 1",
            (username.strip(),),
        )
        row = _fetchone_dict(cursor)
        conn.close()
        if not row:
            return None
        if not _verify_password(password, row["password_hash"], row["salt"]):
            return None
        return {"id": row["id"], "username": row["username"], "role": row["role"]}

    def create_session(self, user_id: str, username: str, role: str) -> str:
        token = secrets.token_urlsafe(32)
        now = datetime.now(timezone.utc)
        expires = now + timedelta(hours=8)
        with _db_lock:
            conn = _get_conn()
            cursor = conn.cursor()
            cursor.execute(
                """INSERT INTO sessions (token, user_id, username, role, created_at, expires_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (token, user_id, username, role, now.isoformat(), expires.isoformat()),
            )
            conn.commit()
            conn.close()
        return token

    def validate_session(self, token: str) -> dict | None:
        if not token:
            return None
        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM sessions WHERE token = ?", (token,))
        row = _fetchone_dict(cursor)
        conn.close()
        if not row:
            return None
        try:
            expires = datetime.fromisoformat(row["expires_at"])
            if datetime.now(timezone.utc) > expires:
                self.revoke_session(token)
                return None
        except (ValueError, TypeError):
            return None
        return {"role": row["role"], "username": row["username"], "user_id": row["user_id"]}

    def revoke_session(self, token: str) -> None:
        with _db_lock:
            conn = _get_conn()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()
            conn.close()

