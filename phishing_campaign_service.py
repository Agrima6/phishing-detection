"""
Phishing Campaign Service – SQLite (local dev) / Postgres (production)
Campaigns, recipients, and open-events are stored either in a local SQLite
file or, when DATABASE_URL is set, a real Postgres database so data survives
restarts on hosts without persistent disks (e.g. Render's free tier).
"""

import csv
import io
import json
import logging
import os
import re
import secrets
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

try:
    import psycopg2
    import psycopg2.errors
except ImportError:
    psycopg2 = None

from config import config

# ---------------------------------------------------------------------------
# Database connection
# ---------------------------------------------------------------------------

_db_lock = threading.Lock()
_db_initialized = False
_db_init_guard = threading.Lock()

# When set, all data lives in this Postgres database instead of local SQLite.
_DATABASE_URL = os.environ.get("DATABASE_URL", "")

# Overridable so a persistent disk can be mounted elsewhere in production;
# defaults to a file next to this module. Only used when DATABASE_URL isn't
# set. NOTE: on ephemeral filesystems (e.g. Render's free tier) this file -
# and all data in it - is wiped on every redeploy/restart.
_DB_PATH = Path(os.environ.get("SQLITE_DB_PATH", Path(__file__).parent / "data" / "phishing.db"))


def _using_postgres() -> bool:
    return bool(_DATABASE_URL)


class _PGCursorProxy:
    """Translates SQLite-style `?` placeholders to psycopg2-style `%s` so
    every existing call site works unmodified against Postgres."""

    def __init__(self, cursor):
        self._cursor = cursor

    def execute(self, sql, params=()):
        return self._cursor.execute(sql.replace("?", "%s"), params)

    def executemany(self, sql, seq_of_params):
        return self._cursor.executemany(sql.replace("?", "%s"), seq_of_params)

    def __getattr__(self, name):
        return getattr(self._cursor, name)


class _PGConnProxy:
    def __init__(self, conn):
        self._conn = conn

    def cursor(self):
        return _PGCursorProxy(self._conn.cursor())

    def __getattr__(self, name):
        return getattr(self._conn, name)


def _get_conn():
    """Return a DB connection - Postgres if DATABASE_URL is set (production),
    otherwise a local SQLite file (local dev)."""
    if _using_postgres():
        if psycopg2 is None:
            raise RuntimeError("DATABASE_URL is set but psycopg2 is not installed.")
        raw = psycopg2.connect(_DATABASE_URL)
        return _PGConnProxy(raw)
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_DB_PATH), timeout=30, check_same_thread=False)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _row_to_dict(cursor, row) -> dict:
    """Convert a DB row to a dict using column names from cursor description
    (the DB-API 2.0 `.description` format is identical for sqlite3 and
    psycopg2, so this works unmodified against either)."""
    return {col[0]: val for col, val in zip(cursor.description, row)}


def _fetchone_dict(cursor) -> dict | None:
    row = cursor.fetchone()
    if row is None:
        return None
    return _row_to_dict(cursor, row)


def _fetchall_dict(cursor) -> list[dict]:
    rows = cursor.fetchall()
    return [_row_to_dict(cursor, r) for r in rows]


def _table_columns(cursor, table_name: str) -> set:
    """Column names for a table - used by the idempotent schema-upgrade
    checks below, since SQLite and Postgres each need a different query."""
    if _using_postgres():
        cursor.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_name = ?",
            (table_name,),
        )
        return {row[0] for row in cursor.fetchall()}
    return {row[1] for row in cursor.execute(f"PRAGMA table_info({table_name})").fetchall()}


def _is_duplicate_key_error(exc: Exception) -> bool:
    if isinstance(exc, sqlite3.IntegrityError):
        return True
    if psycopg2 is not None and isinstance(exc, psycopg2.errors.UniqueViolation):
        return True
    return "unique constraint" in str(exc).lower()


# ---------------------------------------------------------------------------
# Schema initialisation
# ---------------------------------------------------------------------------

def _init_db():
    """Create tables if they don't already exist (idempotent)."""
    ddl_statements = [
        """
        CREATE TABLE IF NOT EXISTS campaigns (
            id               TEXT    NOT NULL PRIMARY KEY,
            name             TEXT    NOT NULL,
            subject          TEXT    NOT NULL,
            body_html        TEXT    NOT NULL,
            sender_name      TEXT    NOT NULL DEFAULT 'Security Team',
            redirect_url     TEXT    NOT NULL DEFAULT '',
            status           TEXT    NOT NULL DEFAULT 'draft',
            created_at       TEXT    NOT NULL,
            updated_at       TEXT    NOT NULL,
            total_sent       INTEGER NOT NULL DEFAULT 0,
            total_opened     INTEGER NOT NULL DEFAULT 0,
            total_clicked    INTEGER NOT NULL DEFAULT 0,
            total_failed     INTEGER NOT NULL DEFAULT 0,
            total_duplicates INTEGER NOT NULL DEFAULT 0
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS recipients (
            id             TEXT    NOT NULL PRIMARY KEY,
            campaign_id    TEXT    NOT NULL,
            email          TEXT    NOT NULL,
            name           TEXT    NOT NULL,
            tracking_token TEXT    NOT NULL UNIQUE,
            status         TEXT    NOT NULL DEFAULT 'pending',
            sent_at        TEXT,
            opened_at      TEXT,
            open_count     INTEGER NOT NULL DEFAULT 0,
            click_count    INTEGER NOT NULL DEFAULT 0,
            clicked_at     TEXT,
            failed_at      TEXT,
            fail_reason    TEXT,
            send_count     INTEGER NOT NULL DEFAULT 0,
            created_at     TEXT    NOT NULL,
            UNIQUE (campaign_id, email)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS events (
            id          TEXT NOT NULL PRIMARY KEY,
            campaign_id TEXT NOT NULL,
            email       TEXT NOT NULL,
            event_type  TEXT NOT NULL,
            token       TEXT NOT NULL,
            occurred_at TEXT NOT NULL
        )
        """,
    ]
    # Indexes for performance – idempotent (IF NOT EXISTS)
    index_statements = [
        "CREATE INDEX IF NOT EXISTS IX_recipients_campaign_id ON recipients (campaign_id)",
        "CREATE INDEX IF NOT EXISTS IX_recipients_campaign_status ON recipients (campaign_id, status)",
        "CREATE INDEX IF NOT EXISTS IX_events_campaign_id ON events (campaign_id)",
        "CREATE INDEX IF NOT EXISTS IX_events_token ON events (token)",
        "CREATE INDEX IF NOT EXISTS IX_events_campaign_type ON events (campaign_id, event_type)",
    ]

    # Online schema upgrades for recipient device metadata (idempotent).
    # SQLite has no "ADD COLUMN IF NOT EXISTS", so check PRAGMA table_info first.
    device_columns = [
        "opened_device_type", "opened_os", "opened_ip", "opened_ua",
        "clicked_device_type", "clicked_os", "clicked_ip", "clicked_ua",
    ]

    with _db_lock:
        conn = _get_conn()
        cursor = conn.cursor()
        for ddl in ddl_statements:
            cursor.execute(ddl)
        existing_cols = _table_columns(cursor, "recipients")
        for col in device_columns:
            if col not in existing_cols:
                cursor.execute(f"ALTER TABLE recipients ADD COLUMN {col} TEXT")
        existing_campaign_cols = _table_columns(cursor, "campaigns")
        if "email_config_id" not in existing_campaign_cols:
            cursor.execute("ALTER TABLE campaigns ADD COLUMN email_config_id TEXT")
        if "scheduled_at" not in existing_campaign_cols:
            cursor.execute("ALTER TABLE campaigns ADD COLUMN scheduled_at TEXT")
        for idx in index_statements:
            cursor.execute(idx)
        conn.commit()
        conn.close()
    logging.info(f"SQLite schema initialised at {_DB_PATH}.")


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
        _db_initialized = True


class PhishingCampaignService:
    """Service layer for the phishing-awareness dashboard (SQLite backend)."""

    def __init__(self):
        _ensure_db_ready()  # lazy init – safe to call multiple times
        cfg = config.get_phishing_config()
        self._base_url = cfg["base_url"].rstrip("/")

    # ------------------------------------------------------------------
    # Campaign CRUD
    # ------------------------------------------------------------------

    def create_campaign(self, name: str, subject: str, body_html: str,
                        sender_name: str = "Security Team",
                        redirect_url: str = "",
                        email_config_id: str | None = None) -> dict:
        campaign_id = str(uuid.uuid4())
        now = _utcnow_iso()
        row = {
            "id": campaign_id, "name": name, "subject": subject,
            "body_html": body_html, "sender_name": sender_name,
            "redirect_url": redirect_url, "email_config_id": email_config_id,
            "status": "draft", "created_at": now, "updated_at": now,
            "total_sent": 0, "total_opened": 0, "total_clicked": 0,
            "total_failed": 0, "total_duplicates": 0,
        }
        with _db_lock:
            conn = _get_conn()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO campaigns
                  (id, name, subject, body_html, sender_name, redirect_url, email_config_id, status,
                   created_at, updated_at, total_sent, total_opened, total_clicked,
                   total_failed, total_duplicates)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (row["id"], row["name"], row["subject"], row["body_html"],
                  row["sender_name"], row["redirect_url"], row["email_config_id"], row["status"],
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

    def set_scheduled_at(self, campaign_id: str, scheduled_at: str | None) -> None:
        with _db_lock:
            conn = _get_conn()
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE campaigns SET scheduled_at = ?, updated_at = ? WHERE id = ?",
                (scheduled_at, _utcnow_iso(), campaign_id),
            )
            conn.commit()
            conn.close()

    def list_due_scheduled_campaigns(self) -> list:
        """Draft campaigns whose scheduled send time has arrived."""
        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM campaigns WHERE status = 'draft' AND scheduled_at IS NOT NULL AND scheduled_at <= ?",
            (_utcnow_iso(),),
        )
        rows = _fetchall_dict(cursor)
        conn.close()
        return rows

    def update_campaign_stats(self, campaign_id: str,
                              sent_delta: int = 0, opened_delta: int = 0,
                              clicked_delta: int = 0, failed_delta: int = 0,
                              duplicate_delta: int = 0):
        with _db_lock:
            conn = _get_conn()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE campaigns
                SET total_sent       = MAX(0, total_sent       + ?),
                    total_opened     = MAX(0, total_opened     + ?),
                    total_clicked    = MAX(0, total_clicked    + ?),
                    total_failed     = MAX(0, total_failed     + ?),
                    total_duplicates = MAX(0, total_duplicates + ?),
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

        For large lists (e.g. 4,500 entries) a naive per-row SELECT+INSERT loop
        does 9,000+ round-trips and can exceed the gunicorn worker timeout.
        This implementation:
          1. Issues ONE batched SELECT to find which emails already exist.
          2. Issues ONE executemany INSERT for all new rows.
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
            # Chunk to keep well under SQLite's bound-parameter limit per query.
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

            # ---- Step 3: batched INSERT via executemany ----
            if new_rows:
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
            cursor.execute("SELECT * FROM recipients WHERE id = ?", (recipient_id,))
            rec = _fetchone_dict(cursor)
            if rec:
                cursor.execute("DELETE FROM events WHERE token = ?", (rec["tracking_token"],))
            cursor.execute("DELETE FROM recipients WHERE id = ?", (recipient_id,))
            affected = cursor.rowcount
            conn.commit()
            conn.close()
        if rec and affected:
            self.update_campaign_stats(
                rec["campaign_id"],
                sent_delta=-1 if rec["status"] in ("sent", "opened", "failed") else 0,
                opened_delta=-1 if rec["status"] == "opened" else 0,
                clicked_delta=-1 if (rec.get("click_count") or 0) > 0 else 0,
                failed_delta=-1 if rec["status"] == "failed" else 0,
            )
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

