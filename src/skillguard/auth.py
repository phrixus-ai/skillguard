"""SkillGuard Auth — Simple session-based admin authentication."""

from __future__ import annotations

import os
from functools import wraps

from flask import request, jsonify, session, redirect, url_for

# Default values (safe for public GitHub) — override via .env
ADMIN_PASSWORD_HASH = os.environ.get(
    "ADMIN_PASSWORD_HASH",
    "scrypt:32768:8:1$WoUesGV85uyLuHRT$e781788d10635af6c0341d599bf6d462dfdb26317d9e527ccb6c6be463232b6e63522fc9b479d828cb84e89b10ba549ae373e2380a653eb532432ddbb9cdf76e"  # default: "1234"
)
API_KEY = os.environ.get("API_KEY", "sg_replace_with_your_own_api_key")


def check_admin_auth() -> bool:
    """Check if request is authenticated via session or API key."""
    # Check API key in header
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        if token == API_KEY:
            return True
    # Check session
    if session.get("admin_logged_in"):
        return True
    return False


def admin_required(f):
    """Decorator to protect admin endpoints."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not check_admin_auth():
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated
