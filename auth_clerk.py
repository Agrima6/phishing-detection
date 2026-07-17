"""
Clerk Authentication Module

Verifies a signed-in Clerk session for the admin dashboard and stores the
resulting profile/role in the Flask session, mirroring the pattern the old
Entra SSO module used (verify once, then trust the Flask session cookie).
"""

import logging

from clerk_backend_api import AuthenticateRequestOptions, Clerk
from flask import Blueprint, jsonify, make_response, request, session

from config import config

logger = logging.getLogger(__name__)

auth_clerk_bp = Blueprint("auth_clerk", __name__, url_prefix="/api/auth/clerk")

_clerk_client: Clerk | None = None


def is_clerk_configured() -> bool:
    """Check whether Clerk environment variables are set."""
    return bool(config.CLERK_PUBLISHABLE_KEY and config.CLERK_SECRET_KEY)


def _get_clerk_client() -> Clerk:
    global _clerk_client
    if _clerk_client is None:
        _clerk_client = Clerk(bearer_auth=config.CLERK_SECRET_KEY)
    return _clerk_client


def _primary_email(clerk_user) -> str:
    if not clerk_user.email_addresses:
        return ""
    primary = next(
        (e for e in clerk_user.email_addresses if e.id == clerk_user.primary_email_address_id),
        clerk_user.email_addresses[0],
    )
    return primary.email_address


@auth_clerk_bp.route("/session", methods=["POST", "OPTIONS"])
def clerk_session():
    """Verify the browser's Clerk session (cookie or Bearer token) and start a Flask session."""
    if request.method == "OPTIONS":
        return "", 200
    if not is_clerk_configured():
        return make_response(jsonify({"error": "Clerk is not configured"}), 503)

    # `request` only needs a `.headers` mapping to satisfy clerk_backend_api's Requestish
    # protocol, so the Flask request object can be passed straight through.
    request_state = _get_clerk_client().authenticate_request(
        request, AuthenticateRequestOptions()
    )
    if not request_state.is_signed_in:
        return make_response(jsonify({"error": "Not signed in"}), 401)

    user_id = request_state.payload.get("sub")
    try:
        clerk_user = _get_clerk_client().users.get(user_id=user_id)
    except Exception as exc:
        logger.error(f"Failed to fetch Clerk user {user_id}: {exc}")
        return make_response(jsonify({"error": "Failed to load user profile"}), 500)

    email = _primary_email(clerk_user)
    name = " ".join(filter(None, [clerk_user.first_name, clerk_user.last_name])).strip() or email
    # Role is assigned per-user in the Clerk Dashboard under
    # User -> Metadata -> Public: {"role": "admin"} (admin/operator/auditor/template_author).
    # No role set = no access, so newly-created Clerk users can't self-grant permissions.
    role = (clerk_user.public_metadata or {}).get("role")

    user_data = {"id": user_id, "name": name, "email": email, "role": role}
    session["clerk_user"] = user_data

    logger.info(f"Clerk login successful for {email} (role={role or 'none'})")
    return make_response(jsonify(user_data), 200)


@auth_clerk_bp.route("/status", methods=["GET"])
def clerk_status():
    """Check if Clerk is configured and if the current Flask session has a verified user."""
    user = session.get("clerk_user")
    return make_response(jsonify({
        "clerk_configured": is_clerk_configured(),
        "publishable_key": config.CLERK_PUBLISHABLE_KEY,
        "authenticated": user is not None,
        "user": user,
    }), 200)


@auth_clerk_bp.route("/logout", methods=["GET", "POST"])
def clerk_logout():
    """Clear the Flask session. The browser's Clerk session is cleared client-side via Clerk.signOut()."""
    session.pop("clerk_user", None)
    return make_response(jsonify({"message": "Logged out"}), 200)
