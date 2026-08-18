"""
Auth service – SQLite/Postgres, mirrors tenant_service.py's pattern.

Two concerns live here:
  - AuthService: users (super_admin + tenant admins), password hashing/verify.
  - RegistrationService: the public registration -> onboarding form ->
    super-admin maker-checker approval pipeline. Approving a SUBMITTED
    registration is what actually creates the tenant (via TenantService)
    and that tenant's first admin user.
"""

import hashlib
import logging
import secrets
import uuid
from datetime import datetime, timezone

import bcrypt

from phishing_campaign_service import _get_conn, _fetchone_dict, _fetchall_dict
from tenant_service import _db_lock, _ensure_db_ready, TenantService


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def generate_temp_password() -> str:
    # Short, unambiguous, easy to read out of an email - not meant to be
    # memorized, just used once before the forced reset.
    return secrets.token_urlsafe(9)


class AuthService:
    def __init__(self):
        _ensure_db_ready()

    def find_by_email(self, email: str) -> dict | None:
        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email.strip().lower(),))
        row = _fetchone_dict(cursor)
        conn.close()
        if row:
            row["must_change_password"] = bool(row["must_change_password"])
        return row

    def find_by_id(self, user_id: str) -> dict | None:
        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = _fetchone_dict(cursor)
        conn.close()
        if row:
            row["must_change_password"] = bool(row["must_change_password"])
        return row

    def create_user(self, email: str, password: str, display_name: str = "",
                     role: str = "admin", tenant_id: str | None = None,
                     must_change_password: bool = False) -> dict:
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        row = {
            "id": str(uuid.uuid4()), "email": email.strip().lower(),
            "password_hash": password_hash, "display_name": display_name,
            "role": role, "tenant_id": tenant_id,
            "must_change_password": 1 if must_change_password else 0,
            "status": "active", "created_at": _utcnow_iso(),
        }
        with _db_lock:
            conn = _get_conn()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (id, email, password_hash, display_name, role,
                                    tenant_id, must_change_password, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (row["id"], row["email"], row["password_hash"], row["display_name"],
                  row["role"], row["tenant_id"], row["must_change_password"], row["status"], row["created_at"]))
            conn.commit()
            conn.close()
        return row

    def list_by_tenant(self, tenant_id: str) -> list[dict]:
        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE tenant_id = ? ORDER BY created_at DESC", (tenant_id,))
        rows = _fetchall_dict(cursor)
        conn.close()
        for row in rows:
            row["must_change_password"] = bool(row["must_change_password"])
        return rows

    def delete_user(self, user_id: str, tenant_id: str) -> bool:
        # Scoped to tenant_id so one tenant's admin can never delete a
        # user belonging to a different company.
        with _db_lock:
            conn = _get_conn()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM users WHERE id = ? AND tenant_id = ?", (user_id, tenant_id))
            deleted = cursor.rowcount > 0
            conn.commit()
            conn.close()
        return deleted

    def reset_password(self, user_id: str, new_password: str, must_change_password: bool) -> None:
        password_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
        with _db_lock:
            conn = _get_conn()
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET password_hash = ?, must_change_password = ? WHERE id = ?",
                (password_hash, 1 if must_change_password else 0, user_id),
            )
            conn.commit()
            conn.close()

    def verify_password(self, user: dict, password: str) -> bool:
        try:
            return bcrypt.checkpw(password.encode(), user["password_hash"].encode())
        except Exception:
            return False

    def ensure_super_admin_seeded(self, username: str, password: str) -> None:
        """Idempotent - a fixed super-admin account, provisioned on every
        startup if it doesn't already exist. Not a real email address, just
        a login identifier, same as any other row in `users`."""
        existing = self.find_by_email(username)
        if existing:
            return
        self.create_user(
            email=username, password=password, display_name="Super Admin",
            role="super_admin", tenant_id=None, must_change_password=False,
        )
        logging.info(f"Seeded super-admin account: {username}")


class RegistrationService:
    """Operates across all registrations - only reachable from routes gated
    on the super_admin role (or, for the public routes, unauthenticated by
    design and scoped to a single token)."""

    def __init__(self):
        _ensure_db_ready()

    def create_registration(self, company_name: str, contact_name: str, contact_email: str,
                             contact_mobile: str = "", designation: str = "") -> tuple[dict, str]:
        raw_token = secrets.token_urlsafe(24)
        row = {
            "id": str(uuid.uuid4()), "company_name": company_name,
            "contact_name": contact_name, "contact_email": contact_email.strip().lower(),
            "contact_mobile": contact_mobile, "designation": designation,
            "status": "PENDING_ONBOARDING", "onboarding_token_hash": _hash_token(raw_token),
            "created_at": _utcnow_iso(),
        }
        with _db_lock:
            conn = _get_conn()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO registrations
                  (id, company_name, contact_name, contact_email, contact_mobile,
                   designation, status, onboarding_token_hash, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (row["id"], row["company_name"], row["contact_name"], row["contact_email"],
                  row["contact_mobile"], row["designation"], row["status"],
                  row["onboarding_token_hash"], row["created_at"]))
            conn.commit()
            conn.close()
        return row, raw_token

    def get_by_token(self, raw_token: str) -> dict | None:
        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM registrations WHERE onboarding_token_hash = ?", (_hash_token(raw_token),))
        row = _fetchone_dict(cursor)
        conn.close()
        return row

    def get_by_tenant_id(self, tenant_id: str) -> dict | None:
        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM registrations WHERE tenant_id = ?", (tenant_id,))
        row = _fetchone_dict(cursor)
        conn.close()
        return row

    def get(self, registration_id: str) -> dict | None:
        conn = _get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM registrations WHERE id = ?", (registration_id,))
        row = _fetchone_dict(cursor)
        conn.close()
        return row

    def list_all(self, status: str | None = None) -> list[dict]:
        conn = _get_conn()
        cursor = conn.cursor()
        if status:
            cursor.execute("SELECT * FROM registrations WHERE status = ? ORDER BY created_at DESC", (status,))
        else:
            cursor.execute("SELECT * FROM registrations ORDER BY created_at DESC")
        rows = _fetchall_dict(cursor)
        conn.close()
        return rows

    def submit_onboarding(self, raw_token: str, address: str, gst_number: str,
                           employee_count: str, logo_url: str, primary_color: str) -> dict | None:
        reg = self.get_by_token(raw_token)
        if not reg:
            return None
        if reg["status"] not in ("PENDING_ONBOARDING", "CHANGES_REQUESTED"):
            raise ValueError(f"Cannot submit onboarding in status {reg['status']}")
        with _db_lock:
            conn = _get_conn()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE registrations
                SET address = ?, gst_number = ?, employee_count = ?, logo_url = ?,
                    primary_color = ?, status = 'SUBMITTED', submitted_at = ?
                WHERE id = ?
            """, (address, gst_number, employee_count, logo_url, primary_color, _utcnow_iso(), reg["id"]))
            conn.commit()
            conn.close()
        return self.get(reg["id"])

    def approve(self, registration_id: str) -> dict:
        reg = self.get(registration_id)
        if not reg:
            raise ValueError("Registration not found")
        if reg["status"] != "SUBMITTED":
            raise ValueError(f"Cannot approve a registration in status {reg['status']}")

        # Login email must be globally unique (it's a real credential, not
        # tenant-scoped simulation data) - fail with a clear error before
        # creating anything, rather than a raw 500 mid-approval leaving an
        # orphaned tenant with no admin user.
        auth_svc = AuthService()
        if auth_svc.find_by_email(reg["contact_email"]):
            raise ValueError(
                f"{reg['contact_email']} already has a Workmate Shield account. "
                "Use a different contact email for this company, or remove the existing account first."
            )

        tenant_svc = TenantService()
        tenant = tenant_svc.create_tenant(
            company_name=reg["company_name"], contact_email=reg["contact_email"],
            admin_email=reg["contact_email"], contact_name=reg["contact_name"],
            contact_mobile=reg["contact_mobile"], designation=reg["designation"],
            primary_color=reg["primary_color"] or "#7a1220", logo_url=reg["logo_url"] or "",
        )

        temp_password = generate_temp_password()
        user = auth_svc.create_user(
            email=reg["contact_email"], password=temp_password, display_name=reg["contact_name"],
            role="admin", tenant_id=tenant["id"], must_change_password=True,
        )

        with _db_lock:
            conn = _get_conn()
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE registrations SET status = 'APPROVED', tenant_id = ?, reviewed_at = ? WHERE id = ?",
                (tenant["id"], _utcnow_iso(), registration_id),
            )
            conn.commit()
            conn.close()

        return {"tenant": tenant, "user": user, "temp_password": temp_password}

    def reject(self, registration_id: str, reason: str = "") -> dict | None:
        reg = self.get(registration_id)
        if not reg:
            return None
        with _db_lock:
            conn = _get_conn()
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE registrations SET status = 'REJECTED', reject_reason = ?, reviewed_at = ? WHERE id = ?",
                (reason, _utcnow_iso(), registration_id),
            )
            conn.commit()
            conn.close()
        return self.get(registration_id)
