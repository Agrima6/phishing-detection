"""
Tenant Service – SQLite

Employees, phishing templates, audit logs, and single-row tenant settings.
Mirrors the connection/init pattern used by phishing_campaign_service.py and
shares the same SQLite file.
"""

import csv
import io
import json
import logging
import threading
import uuid
from datetime import datetime, timezone

from config import config
from default_templates import build_default_templates
from phishing_campaign_service import _get_conn, _fetchone_dict, _fetchall_dict

_db_lock = threading.Lock()
_db_initialized = False
_db_init_guard = threading.Lock()


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _init_db():
    ddl_statements = [
        """
        CREATE TABLE IF NOT EXISTS employees (
            id                 TEXT    NOT NULL PRIMARY KEY,
            name               TEXT    NOT NULL,
            email              TEXT    NOT NULL UNIQUE,
            department         TEXT    NOT NULL DEFAULT '',
            manager            TEXT    NOT NULL DEFAULT '',
            risk_rating        TEXT    NOT NULL DEFAULT 'low',
            hits_count         INTEGER NOT NULL DEFAULT 0,
            total_simulations  INTEGER NOT NULL DEFAULT 0,
            created_at         TEXT    NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS templates (
            id          TEXT    NOT NULL PRIMARY KEY,
            name        TEXT    NOT NULL,
            category    TEXT    NOT NULL,
            subject     TEXT    NOT NULL,
            body        TEXT    NOT NULL,
            description TEXT    NOT NULL DEFAULT '',
            thumbnail   TEXT    NOT NULL DEFAULT '',
            is_global   INTEGER NOT NULL DEFAULT 0,
            created_at  TEXT    NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id         TEXT NOT NULL PRIMARY KEY,
            actor      TEXT NOT NULL,
            category   TEXT NOT NULL DEFAULT 'SECURITY',
            message    TEXT NOT NULL,
            ip_address TEXT NOT NULL DEFAULT '',
            timestamp  TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS tenant_settings (
            id                INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
            name              TEXT    NOT NULL DEFAULT 'Default Company',
            domains           TEXT    NOT NULL DEFAULT '[]',
            primary_color     TEXT    NOT NULL DEFAULT '#7a1220',
            logo_url          TEXT    NOT NULL DEFAULT '',
            sso_client_id     TEXT    NOT NULL DEFAULT '',
            sso_tenant_id     TEXT    NOT NULL DEFAULT '',
            sso_client_secret TEXT    NOT NULL DEFAULT '',
            email_configs     TEXT    NOT NULL DEFAULT '[]'
        )
        """,
    ]
    index_statements = [
        "CREATE INDEX IF NOT EXISTS IX_employees_email ON employees (email)",
        "CREATE INDEX IF NOT EXISTS IX_audit_logs_timestamp ON audit_logs (timestamp)",
    ]

    with _db_lock:
        conn = _get_conn()
        cursor = conn.cursor()
        for ddl in ddl_statements:
            cursor.execute(ddl)
        for idx in index_statements:
            cursor.execute(idx)
        # Seed the single settings row if absent.
        cursor.execute("SELECT COUNT(*) FROM tenant_settings WHERE id = 1")
        if cursor.fetchone()[0] == 0:
            cursor.execute(
                "INSERT INTO tenant_settings (id, name, domains, primary_color, logo_url, "
                "sso_client_id, sso_tenant_id, sso_client_secret, email_configs) "
                "VALUES (1, 'Default Company', '[]', '#7a1220', '', '', '', '', '[]')"
            )

        # Seed the default global template library, visible to every account,
        # so a fresh tenant/database always has a realistic set to choose
        # from out of the box. Each is checked by name so re-running this on
        # an existing database only inserts the ones that are still missing.
        base_url = config.PHISHING_BASE_URL.rstrip("/")
        banner_url = f"{base_url}/static/uploads/16372ba6a4954ea1a7aaa08b674f31bb.svg"
        for tmpl in build_default_templates(banner_url):
            cursor.execute("SELECT COUNT(*) FROM templates WHERE name = ?", (tmpl["name"],))
            if cursor.fetchone()[0] == 0:
                cursor.execute(
                    "INSERT INTO templates (id, name, category, subject, body, description, "
                    "thumbnail, is_global, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        str(uuid.uuid4()),
                        tmpl["name"],
                        tmpl["category"],
                        tmpl["subject"],
                        tmpl["body"],
                        tmpl["description"],
                        tmpl["thumbnail"],
                        1,
                        _utcnow_iso(),
                    ),
                )

        conn.commit()
        conn.close()
    logging.info("Tenant service SQLite schema initialised.")


def _ensure_db_ready():
    global _db_initialized
    if _db_initialized:
        return
    with _db_init_guard:
        if _db_initialized:
            return
        _init_db()
        _db_initialized = True


class TenantService:
    """Employees, templates, audit logs, and tenant settings (single tenant)."""

    def __init__(self):
        _ensure_db_ready()

    # ------------------------------------------------------------------
    # Employees
    # ------------------------------------------------------------------

    def list_employees(self) -> list[dict]:
        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT e.*,
                   COUNT(r.id) AS total_simulations,
                   SUM(CASE WHEN r.click_count > 0 THEN 1 ELSE 0 END) AS hits_count
            FROM employees e
            LEFT JOIN recipients r ON r.email = e.email
            GROUP BY e.id
            ORDER BY e.created_at DESC
        """)
        rows = _fetchall_dict(cursor)
        conn.close()
        for row in rows:
            row["total_simulations"] = row["total_simulations"] or 0
            row["hits_count"] = row["hits_count"] or 0
            if row["total_simulations"] > 0:
                click_rate = row["hits_count"] / row["total_simulations"]
                if click_rate >= 0.5:
                    row["risk_rating"] = "high"
                elif click_rate > 0:
                    row["risk_rating"] = "medium"
                else:
                    row["risk_rating"] = "low"
        return rows

    def create_employee(self, name: str, email: str, department: str = "",
                         manager: str = "", risk_rating: str = "low") -> dict:
        row = {
            "id": str(uuid.uuid4()), "name": name, "email": email,
            "department": department, "manager": manager,
            "risk_rating": risk_rating, "hits_count": 0,
            "total_simulations": 0, "created_at": _utcnow_iso(),
        }
        with _db_lock:
            conn = _get_conn()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO employees
                  (id, name, email, department, manager, risk_rating,
                   hits_count, total_simulations, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (row["id"], row["name"], row["email"], row["department"],
                  row["manager"], row["risk_rating"], 0, 0, row["created_at"]))
            conn.commit()
            conn.close()
        return row

    def update_employee(self, employee_id: str, data: dict) -> dict | None:
        allowed = {"name", "email", "department", "manager", "risk_rating",
                   "hits_count", "total_simulations"}
        fields = {k: v for k, v in data.items() if k in allowed}
        if not fields:
            return self.get_employee(employee_id)
        set_clause = ", ".join(f"{k} = ?" for k in fields)
        with _db_lock:
            conn = _get_conn()
            cursor = conn.cursor()
            cursor.execute(
                f"UPDATE employees SET {set_clause} WHERE id = ?",
                (*fields.values(), employee_id),
            )
            conn.commit()
            conn.close()
        return self.get_employee(employee_id)

    def get_employee(self, employee_id: str) -> dict | None:
        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM employees WHERE id = ?", (employee_id,))
        row = _fetchone_dict(cursor)
        conn.close()
        return row

    def delete_employee(self, employee_id: str) -> bool:
        with _db_lock:
            conn = _get_conn()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM employees WHERE id = ?", (employee_id,))
            deleted = cursor.rowcount > 0
            conn.commit()
            conn.close()
        return deleted

    def import_employees_csv(self, file_bytes: bytes) -> dict:
        text = file_bytes.decode("utf-8-sig", errors="replace")
        reader = csv.DictReader(io.StringIO(text))
        success_count = 0
        duplicate_count = 0
        error_count = 0
        errors: list[str] = []

        for i, raw_row in enumerate(reader, start=2):  # header is row 1
            row = {(k or "").strip().lower(): (v or "").strip() for k, v in raw_row.items()}
            name = row.get("name", "")
            email = row.get("email", "")
            if not name or not email:
                error_count += 1
                errors.append(f"Row {i}: missing name or email")
                continue
            try:
                self.create_employee(
                    name=name, email=email,
                    department=row.get("department", ""),
                    manager=row.get("manager", ""),
                )
                success_count += 1
            except Exception as exc:
                if "unique" in str(exc).lower():
                    duplicate_count += 1
                else:
                    error_count += 1
                    errors.append(f"Row {i}: {exc}")

        return {
            "success_count": success_count,
            "duplicate_count": duplicate_count,
            "error_count": error_count,
            "errors": errors,
        }

    # ------------------------------------------------------------------
    # Templates
    # ------------------------------------------------------------------

    def list_templates(self) -> list[dict]:
        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM templates ORDER BY created_at DESC")
        rows = _fetchall_dict(cursor)
        conn.close()
        for row in rows:
            row["is_global"] = bool(row["is_global"])
        return rows

    def create_template(self, name: str, category: str, subject: str, body: str,
                         description: str = "", thumbnail: str = "") -> dict:
        row = {
            "id": str(uuid.uuid4()), "name": name, "category": category,
            "subject": subject, "body": body, "description": description,
            "thumbnail": thumbnail, "is_global": False,
            "created_at": _utcnow_iso(),
        }
        with _db_lock:
            conn = _get_conn()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO templates
                  (id, name, category, subject, body, description, thumbnail,
                   is_global, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)
            """, (row["id"], row["name"], row["category"], row["subject"],
                  row["body"], row["description"], row["thumbnail"], row["created_at"]))
            conn.commit()
            conn.close()
        return row

    def delete_template(self, template_id: str) -> bool:
        with _db_lock:
            conn = _get_conn()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM templates WHERE id = ? AND is_global = 0", (template_id,))
            deleted = cursor.rowcount > 0
            conn.commit()
            conn.close()
        return deleted

    # ------------------------------------------------------------------
    # Audit logs
    # ------------------------------------------------------------------

    def list_audit_logs(self) -> list[dict]:
        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 500")
        rows = _fetchall_dict(cursor)
        conn.close()
        return [
            {
                "id": r["id"], "actor": r["actor"], "category": r["category"],
                "message": r["message"], "ipAddress": r["ip_address"],
                "timestamp": r["timestamp"],
            }
            for r in rows
        ]

    def create_audit_log(self, actor: str, category: str, message: str,
                          ip_address: str = "") -> dict:
        row = {
            "id": str(uuid.uuid4()), "actor": actor, "category": category,
            "message": message, "ip_address": ip_address,
            "timestamp": _utcnow_iso(),
        }
        with _db_lock:
            conn = _get_conn()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO audit_logs (id, actor, category, message, ip_address, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (row["id"], row["actor"], row["category"], row["message"],
                  row["ip_address"], row["timestamp"]))
            conn.commit()
            conn.close()
        return {
            "id": row["id"], "actor": row["actor"], "category": row["category"],
            "message": row["message"], "ipAddress": row["ip_address"],
            "timestamp": row["timestamp"],
        }

    # ------------------------------------------------------------------
    # Tenant settings (single row, id=1)
    # ------------------------------------------------------------------

    def get_settings_raw(self) -> dict:
        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM tenant_settings WHERE id = 1")
        row = _fetchone_dict(cursor)
        conn.close()
        row["domains"] = json.loads(row["domains"] or "[]")
        row["email_configs"] = json.loads(row["email_configs"] or "[]")
        return row

    def save_settings(self, data: dict) -> dict:
        current = self.get_settings_raw()

        name = data.get("name", current["name"])
        domains = data.get("domains", current["domains"])
        branding = data.get("branding", {})
        primary_color = branding.get("primary_color", current["primary_color"])
        logo_url = branding.get("logo_url", current["logo_url"])

        sso = data.get("sso_config", {})
        sso_client_id = sso.get("client_id", current["sso_client_id"])
        sso_tenant_id = sso.get("tenant_id", current["sso_tenant_id"])
        # Secret only overwritten when a new non-empty value is actually sent.
        sso_client_secret = sso.get("client_secret") or current["sso_client_secret"]

        incoming_configs = data.get("email_configs", current["email_configs"])
        existing_by_id = {c["id"]: c for c in current["email_configs"] if c.get("id")}
        merged_configs = []
        for cfg in incoming_configs:
            existing = existing_by_id.get(cfg.get("id"), {})
            merged = dict(cfg)
            if not merged.get("smtp_password"):
                merged["smtp_password"] = existing.get("smtp_password", "")
            if not merged.get("sendgrid_api_key"):
                merged["sendgrid_api_key"] = existing.get("sendgrid_api_key", "")
            merged_configs.append(merged)

        with _db_lock:
            conn = _get_conn()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE tenant_settings
                SET name = ?, domains = ?, primary_color = ?, logo_url = ?,
                    sso_client_id = ?, sso_tenant_id = ?, sso_client_secret = ?,
                    email_configs = ?
                WHERE id = 1
            """, (name, json.dumps(domains), primary_color, logo_url,
                  sso_client_id, sso_tenant_id, sso_client_secret,
                  json.dumps(merged_configs)))
            conn.commit()
            conn.close()
        return self.get_settings_raw()

    def to_frontend_shape(self, raw: dict | None = None) -> dict:
        raw = raw or self.get_settings_raw()
        email_configs = []
        for cfg in raw["email_configs"]:
            email_configs.append({
                "id": cfg.get("id"),
                "name": cfg.get("name", ""),
                "provider": cfg.get("provider", "smtp"),
                "smtp_host": cfg.get("smtp_host", ""),
                "smtp_port": cfg.get("smtp_port", 465),
                "smtp_username": cfg.get("smtp_username", ""),
                "sendgrid_from_email": cfg.get("sendgrid_from_email", ""),
                "sendgrid_from_name": cfg.get("sendgrid_from_name", ""),
                "smtp_from_email": cfg.get("smtp_from_email", ""),
                "smtp_from_name": cfg.get("smtp_from_name", ""),
                "sendgrid_api_key_configured": bool(cfg.get("sendgrid_api_key")),
                "smtp_password_configured": bool(cfg.get("smtp_password")),
            })
        return {
            "tenant_id": "default",
            "name": raw["name"],
            "domains": raw["domains"],
            "branding": {
                "primary_color": raw["primary_color"],
                "logo_url": raw["logo_url"],
            },
            "sso_config": {
                "client_id": raw["sso_client_id"],
                "tenant_id": raw["sso_tenant_id"],
            },
            "email_configs": email_configs,
        }

    # ------------------------------------------------------------------
    # Dashboard analytics – joins employees with the campaigns/recipients
    # tables (phishing_campaign_service.py), which share this same SQLite file.
    # ------------------------------------------------------------------

    def get_department_click_rates(self) -> list[dict]:
        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT e.department AS department,
                   COUNT(r.id) AS total_recipients,
                   SUM(CASE WHEN r.click_count > 0 THEN 1 ELSE 0 END) AS clicked_count
            FROM employees e
            JOIN recipients r ON r.email = e.email
            WHERE e.department != ''
            GROUP BY e.department
            ORDER BY clicked_count DESC
        """)
        rows = _fetchall_dict(cursor)
        conn.close()
        return [
            {
                "department": r["department"],
                "rate": round((r["clicked_count"] / r["total_recipients"]) * 100) if r["total_recipients"] else 0,
                "total_recipients": r["total_recipients"],
            }
            for r in rows
        ]

    def get_recent_risk_events(self, limit: int = 5) -> list[dict]:
        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT r.name AS recipient_name, r.email AS recipient_email,
                   c.name AS campaign_name, r.clicked_at, r.opened_at, r.sent_at
            FROM recipients r
            JOIN campaigns c ON c.id = r.campaign_id
            WHERE r.clicked_at IS NOT NULL OR r.opened_at IS NOT NULL
            ORDER BY COALESCE(r.clicked_at, r.opened_at) DESC
            LIMIT ?
        """, (limit,))
        rows = _fetchall_dict(cursor)
        conn.close()
        events = []
        for r in rows:
            if r["clicked_at"]:
                status, timestamp = "Clicked Link", r["clicked_at"]
            else:
                status, timestamp = "Opened Email", r["opened_at"]
            events.append({
                "name": r["recipient_name"] or r["recipient_email"],
                "campaign": r["campaign_name"],
                "status": status,
                "timestamp": timestamp,
            })
        return events
