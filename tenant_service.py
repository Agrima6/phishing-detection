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
from phishing_campaign_service import _get_conn, _fetchone_dict, _fetchall_dict, _table_columns

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
            theme       TEXT    NOT NULL DEFAULT '',
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
        """
        CREATE TABLE IF NOT EXISTS tenants (
            id             TEXT    NOT NULL PRIMARY KEY,
            company_name   TEXT    NOT NULL,
            contact_name   TEXT    NOT NULL DEFAULT '',
            contact_email  TEXT    NOT NULL,
            contact_mobile TEXT    NOT NULL DEFAULT '',
            designation    TEXT    NOT NULL DEFAULT '',
            admin_email    TEXT    NOT NULL,
            primary_color  TEXT    NOT NULL DEFAULT '#7a1220',
            status         TEXT    NOT NULL DEFAULT 'active',
            created_at     TEXT    NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS chatbot_leads (
            id         TEXT NOT NULL PRIMARY KEY,
            name       TEXT NOT NULL,
            phone      TEXT NOT NULL DEFAULT '',
            email      TEXT NOT NULL DEFAULT '',
            message    TEXT NOT NULL,
            created_at TEXT NOT NULL
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

        # Multi-tenant isolation columns (idempotent). Existing rows default
        # to the 'default' tenant so the original single-tenant deployment
        # keeps working unchanged.
        employee_cols = _table_columns(cursor, "employees")
        if "tenant_id" not in employee_cols:
            cursor.execute("ALTER TABLE employees ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'")
            cursor.execute("CREATE INDEX IF NOT EXISTS IX_employees_tenant_id ON employees (tenant_id)")
        template_cols = _table_columns(cursor, "templates")
        if "tenant_id" not in template_cols:
            cursor.execute("ALTER TABLE templates ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'")
        if "theme" not in template_cols:
            cursor.execute("ALTER TABLE templates ADD COLUMN theme TEXT NOT NULL DEFAULT ''")
        audit_cols = _table_columns(cursor, "audit_logs")
        if "tenant_id" not in audit_cols:
            cursor.execute("ALTER TABLE audit_logs ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'")
            cursor.execute("CREATE INDEX IF NOT EXISTS IX_audit_logs_tenant_id ON audit_logs (tenant_id)")
        tenants_cols = _table_columns(cursor, "tenants")
        if "contact_name" not in tenants_cols:
            cursor.execute("ALTER TABLE tenants ADD COLUMN contact_name TEXT NOT NULL DEFAULT ''")

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
                    "INSERT INTO templates (id, name, category, theme, subject, body, description, "
                    "thumbnail, is_global, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        str(uuid.uuid4()),
                        tmpl["name"],
                        tmpl["category"],
                        tmpl.get("theme", ""),
                        tmpl["subject"],
                        tmpl["body"],
                        tmpl["description"],
                        tmpl["thumbnail"],
                        1,
                        _utcnow_iso(),
                    ),
                )
            elif tmpl.get("theme"):
                # Backfill theme on pre-existing global templates seeded before
                # the theme column existed, without touching any tenant's own
                # custom (non-global) templates that happen to share a name.
                cursor.execute(
                    "UPDATE templates SET theme = ? WHERE name = ? AND is_global = 1 AND (theme IS NULL OR theme = '')",
                    (tmpl["theme"], tmpl["name"]),
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


# ---------------------------------------------------------------------------
# Chatbot leads - not tenant-scoped, since these come from the "Shieldy"
# widget before a visitor is necessarily associated with any company.
# ---------------------------------------------------------------------------

def save_chatbot_lead(name: str, phone: str, email: str, message: str) -> dict:
    _ensure_db_ready()
    row = {
        "id": str(uuid.uuid4()), "name": name, "phone": phone,
        "email": email, "message": message, "created_at": _utcnow_iso(),
    }
    with _db_lock:
        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO chatbot_leads (id, name, phone, email, message, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (row["id"], row["name"], row["phone"], row["email"], row["message"], row["created_at"]),
        )
        conn.commit()
        conn.close()
    return row


def list_chatbot_leads() -> list[dict]:
    _ensure_db_ready()
    conn = _get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM chatbot_leads ORDER BY created_at DESC LIMIT 500")
    rows = _fetchall_dict(cursor)
    conn.close()
    return rows


class TenantService:
    """Employees, templates, audit logs, and tenant settings - scoped to a
    single tenant per instance for real multi-tenant data isolation."""

    def __init__(self, tenant_id: str = "default"):
        _ensure_db_ready()
        self.tenant_id = tenant_id or "default"

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
            WHERE e.tenant_id = ?
            GROUP BY e.id
            ORDER BY e.created_at DESC
        """, (self.tenant_id,))
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
            "tenant_id": self.tenant_id,
        }
        with _db_lock:
            conn = _get_conn()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO employees
                  (id, name, email, department, manager, risk_rating,
                   hits_count, total_simulations, created_at, tenant_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (row["id"], row["name"], row["email"], row["department"],
                  row["manager"], row["risk_rating"], 0, 0, row["created_at"], self.tenant_id))
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
                f"UPDATE employees SET {set_clause} WHERE id = ? AND tenant_id = ?",
                (*fields.values(), employee_id, self.tenant_id),
            )
            conn.commit()
            conn.close()
        return self.get_employee(employee_id)

    def get_employee(self, employee_id: str) -> dict | None:
        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM employees WHERE id = ? AND tenant_id = ?", (employee_id, self.tenant_id))
        row = _fetchone_dict(cursor)
        conn.close()
        return row

    def delete_employee(self, employee_id: str) -> bool:
        with _db_lock:
            conn = _get_conn()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM employees WHERE id = ? AND tenant_id = ?", (employee_id, self.tenant_id))
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
        cursor.execute(
            "SELECT * FROM templates WHERE tenant_id = ? OR is_global = 1 ORDER BY created_at DESC",
            (self.tenant_id,),
        )
        rows = _fetchall_dict(cursor)
        conn.close()
        for row in rows:
            row["is_global"] = bool(row["is_global"])
        return rows

    def create_template(self, name: str, category: str, subject: str, body: str,
                         description: str = "", thumbnail: str = "", theme: str = "") -> dict:
        row = {
            "id": str(uuid.uuid4()), "name": name, "category": category, "theme": theme,
            "subject": subject, "body": body, "description": description,
            "thumbnail": thumbnail, "is_global": False,
            "created_at": _utcnow_iso(), "tenant_id": self.tenant_id,
        }
        with _db_lock:
            conn = _get_conn()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO templates
                  (id, name, category, theme, subject, body, description, thumbnail,
                   is_global, created_at, tenant_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
            """, (row["id"], row["name"], row["category"], row["theme"], row["subject"],
                  row["body"], row["description"], row["thumbnail"], row["created_at"], self.tenant_id))
            conn.commit()
            conn.close()
        return row

    def delete_template(self, template_id: str) -> bool:
        with _db_lock:
            conn = _get_conn()
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM templates WHERE id = ? AND is_global = 0 AND tenant_id = ?",
                (template_id, self.tenant_id),
            )
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
        cursor.execute(
            "SELECT * FROM audit_logs WHERE tenant_id = ? ORDER BY timestamp DESC LIMIT 500",
            (self.tenant_id,),
        )
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
            "timestamp": _utcnow_iso(), "tenant_id": self.tenant_id,
        }
        with _db_lock:
            conn = _get_conn()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO audit_logs (id, actor, category, message, ip_address, timestamp, tenant_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (row["id"], row["actor"], row["category"], row["message"],
                  row["ip_address"], row["timestamp"], self.tenant_id))
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
        # The 'default' tenant keeps using the original single-row table for
        # full backward compatibility (SSO + email configs). Tenants
        # onboarded later through Super Admin get a lighter-weight settings
        # shape backed by their own `tenants` row instead - full SSO/email
        # config customization for them is a follow-up, not built yet.
        if self.tenant_id == "default":
            conn = _get_conn()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM tenant_settings WHERE id = 1")
            row = _fetchone_dict(cursor)
            conn.close()
            row["domains"] = json.loads(row["domains"] or "[]")
            row["email_configs"] = json.loads(row["email_configs"] or "[]")
            return row

        tenant = self.get_tenant(self.tenant_id)
        if not tenant:
            raise ValueError(f"Unknown tenant: {self.tenant_id}")
        return {
            "name": tenant["company_name"],
            "domains": [],
            "primary_color": tenant["primary_color"],
            "logo_url": "",
            "sso_client_id": "",
            "sso_tenant_id": "",
            "sso_client_secret": "",
            "email_configs": [],
        }

    def save_settings(self, data: dict) -> dict:
        current = self.get_settings_raw()

        if self.tenant_id != "default":
            # Reduced settings surface for non-default tenants: only branding
            # color is currently editable (see get_settings_raw note above).
            branding = data.get("branding", {})
            primary_color = branding.get("primary_color", current["primary_color"])
            name = data.get("name", current["name"])
            with _db_lock:
                conn = _get_conn()
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE tenants SET company_name = ?, primary_color = ? WHERE id = ?",
                    (name, primary_color, self.tenant_id),
                )
                conn.commit()
                conn.close()
            return self.get_settings_raw()

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
            "tenant_id": self.tenant_id,
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
            WHERE e.department != '' AND e.tenant_id = ?
            GROUP BY e.department
            ORDER BY clicked_count DESC
        """, (self.tenant_id,))
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
            WHERE (r.clicked_at IS NOT NULL OR r.opened_at IS NOT NULL) AND c.tenant_id = ?
            ORDER BY COALESCE(r.clicked_at, r.opened_at) DESC
            LIMIT ?
        """, (self.tenant_id, limit))
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

    # ------------------------------------------------------------------
    # Super Admin: tenant (company) registry. Unlike every method above,
    # these intentionally ignore self.tenant_id - they operate on the
    # registry of ALL tenants and are only reachable via routes gated on
    # the "super_admin" role, never a regular tenant admin.
    # ------------------------------------------------------------------

    def list_tenants(self) -> list[dict]:
        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT t.*,
                   (SELECT COUNT(*) FROM employees e WHERE e.tenant_id = t.id) AS employee_count,
                   (SELECT COUNT(*) FROM campaigns c WHERE c.tenant_id = t.id) AS campaign_count
            FROM tenants t
            ORDER BY t.created_at DESC
        """)
        rows = _fetchall_dict(cursor)
        conn.close()
        return rows

    def get_tenant(self, tenant_id: str) -> dict | None:
        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM tenants WHERE id = ?", (tenant_id,))
        row = _fetchone_dict(cursor)
        conn.close()
        return row

    def create_tenant(self, company_name: str, contact_email: str, admin_email: str,
                       contact_name: str = "", contact_mobile: str = "", designation: str = "",
                       primary_color: str = "#7a1220") -> dict:
        row = {
            "id": str(uuid.uuid4()), "company_name": company_name,
            "contact_name": contact_name,
            "contact_email": contact_email, "contact_mobile": contact_mobile,
            "designation": designation, "admin_email": admin_email,
            "primary_color": primary_color, "status": "active",
            "created_at": _utcnow_iso(),
        }
        with _db_lock:
            conn = _get_conn()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO tenants
                  (id, company_name, contact_name, contact_email, contact_mobile, designation,
                   admin_email, primary_color, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (row["id"], row["company_name"], row["contact_name"], row["contact_email"], row["contact_mobile"],
                  row["designation"], row["admin_email"], row["primary_color"],
                  row["status"], row["created_at"]))
            conn.commit()
            conn.close()
        return row

    def update_tenant(self, tenant_id: str, data: dict) -> dict | None:
        allowed = {"company_name", "contact_name", "contact_email", "contact_mobile", "designation",
                   "admin_email", "primary_color", "status"}
        fields = {k: v for k, v in data.items() if k in allowed}
        if not fields:
            return self.get_tenant(tenant_id)
        set_clause = ", ".join(f"{k} = ?" for k in fields)
        with _db_lock:
            conn = _get_conn()
            cursor = conn.cursor()
            cursor.execute(
                f"UPDATE tenants SET {set_clause} WHERE id = ?",
                (*fields.values(), tenant_id),
            )
            conn.commit()
            conn.close()
        return self.get_tenant(tenant_id)

    def delete_tenant(self, tenant_id: str) -> bool:
        """Deletes the tenant registry row and all of its scoped data
        (employees, templates, campaigns/recipients/events, audit logs)."""
        with _db_lock:
            conn = _get_conn()
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM campaigns WHERE tenant_id = ?", (tenant_id,))
            campaign_ids = [r[0] for r in cursor.fetchall()]
            for cid in campaign_ids:
                cursor.execute("DELETE FROM events WHERE campaign_id = ?", (cid,))
                cursor.execute("DELETE FROM recipients WHERE campaign_id = ?", (cid,))
            cursor.execute("DELETE FROM campaigns WHERE tenant_id = ?", (tenant_id,))
            cursor.execute("DELETE FROM employees WHERE tenant_id = ?", (tenant_id,))
            cursor.execute("DELETE FROM templates WHERE tenant_id = ? AND is_global = 0", (tenant_id,))
            cursor.execute("DELETE FROM audit_logs WHERE tenant_id = ?", (tenant_id,))
            cursor.execute("DELETE FROM tenants WHERE id = ?", (tenant_id,))
            deleted = cursor.rowcount > 0
            conn.commit()
            conn.close()
        return deleted
