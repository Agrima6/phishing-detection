"""
One-off admin utility: promote a fixed list of email addresses to Super
Admin in Clerk, creating the account with a set password if it doesn't
exist yet. Uses CLERK_SECRET_KEY from the backend's own .env - no secrets
need to be typed anywhere to run this.

The password is passed as a command-line argument rather than hardcoded,
so it never ends up committed in git history.

Usage (from the backend directory, with the venv active):
    python3 scripts/set_super_admins.py 'YourChosenPassword'
"""

import os
import sys
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

SECRET = os.environ.get("CLERK_SECRET_KEY")
if not SECRET:
    sys.exit("CLERK_SECRET_KEY not found - run this from the backend directory with .env present")

if len(sys.argv) < 2:
    sys.exit("Usage: python3 scripts/set_super_admins.py '<password>'")

HEADERS = {"Authorization": f"Bearer {SECRET}", "Content-Type": "application/json"}
BASE = "https://api.clerk.com/v1"

TARGETS = ["yaduvanshi.v@gmail.com", "info@wcspl.net", "support@wcspl.net"]
PASSWORD = sys.argv[1]


def verify_email(user_obj: dict, target_email: str):
    """Mark the user's email address verified. Without this, an account
    created directly via the Backend API has an unverified email, and Clerk
    refuses to complete a plain password sign-in for it (surfaces to the
    user as a vague "additional verification required" error)."""
    for addr in user_obj.get("email_addresses", []):
        if addr.get("email_address", "").lower() == target_email.lower():
            if addr.get("verification", {}).get("status") == "verified":
                return "already verified"
            resp = requests.patch(
                f"{BASE}/email_addresses/{addr['id']}",
                headers=HEADERS,
                json={"verified": True},
                timeout=15,
            )
            return f"{resp.status_code} {resp.text[:150]}"
    return "email address not found on user object"


for email in TARGETS:
    r = requests.get(f"{BASE}/users", headers=HEADERS, params={"email_address": [email]}, timeout=15)
    r.raise_for_status()
    users = r.json()
    if users:
        user_obj = users[0]
        uid = user_obj["id"]
        # Password and metadata are separate endpoints on Clerk's current API -
        # the old combined PATCH /v1/users/{id} with public_metadata is deprecated.
        pw_resp = requests.patch(
            f"{BASE}/users/{uid}",
            headers=HEADERS,
            json={"password": PASSWORD, "skip_password_checks": True},
            timeout=15,
        )
        meta_resp = requests.patch(
            f"{BASE}/users/{uid}/metadata",
            headers=HEADERS,
            json={"public_metadata": {"role": "super_admin"}},
            timeout=15,
        )
        verify_result = verify_email(user_obj, email)
        print(email, "-> updated existing user. password:", pw_resp.status_code, pw_resp.text[:150])
        print(email, "-> role:", meta_resp.status_code, meta_resp.text[:150])
        print(email, "-> email verification:", verify_result)
    else:
        resp = requests.post(
            f"{BASE}/users",
            headers=HEADERS,
            json={
                "email_address": [email],
                "password": PASSWORD,
                "public_metadata": {"role": "super_admin"},
                "skip_password_checks": True,
            },
            timeout=15,
        )
        print(email, "-> created new user:", resp.status_code, resp.text[:300])
        if resp.status_code < 300:
            verify_result = verify_email(resp.json(), email)
            print(email, "-> email verification:", verify_result)
