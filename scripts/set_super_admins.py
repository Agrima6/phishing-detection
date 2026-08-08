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

for email in TARGETS:
    r = requests.get(f"{BASE}/users", headers=HEADERS, params={"email_address": [email]}, timeout=15)
    r.raise_for_status()
    users = r.json()
    if users:
        uid = users[0]["id"]
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
        print(email, "-> updated existing user. password:", pw_resp.status_code, pw_resp.text[:150])
        print(email, "-> role:", meta_resp.status_code, meta_resp.text[:150])
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
