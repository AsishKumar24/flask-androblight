"""
Two-Factor Authentication Routes (TOTP via pyotp)
===================================================
Endpoints for setting up, confirming, verifying, and disabling TOTP-based 2FA.

Flow:
  1. POST /auth/2fa/setup        — generate a new TOTP secret + otpauth URI
  2. POST /auth/2fa/confirm      — verify first OTP to activate 2FA
  3. POST /auth/2fa/verify       — verify OTP during login (returns full JWT tokens)
  4. POST /auth/2fa/disable      — disable 2FA (requires current OTP + password)
  5. GET  /auth/2fa/status       — return whether 2FA is enabled for the current user
"""

import pyotp
from flask import Blueprint, request, jsonify
from flask_jwt_extended import (
    jwt_required,
    get_jwt_identity,
    create_access_token,
    create_refresh_token,
)
import bcrypt

from models.database import db, User

totp_bp = Blueprint("totp", __name__, url_prefix="/auth/2fa")

# Issuer name shown in authenticator apps (e.g. Google Authenticator)
ISSUER_NAME = "AndroBlight"


def _get_totp(secret: str) -> pyotp.TOTP:
    return pyotp.TOTP(secret)


@totp_bp.route("/status", methods=["GET"])
@jwt_required()
def status():
    """Return whether 2FA is currently enabled for the authenticated user."""
    user_id = get_jwt_identity()
    user = db.session.get(User, int(user_id))
    if not user:
        return jsonify({"error": "User not found"}), 404

    return (
        jsonify(
            {
                "two_factor_enabled": user.two_factor_enabled,
            }
        ),
        200,
    )


@totp_bp.route("/setup", methods=["POST"])
@jwt_required()
def setup():
    """
    Generate a new TOTP secret for the user and return:
      - secret      (base32 string — show only for manual entry)
      - otpauth_uri (encode into QR code on the client)

    The secret is saved but 2FA is NOT yet enabled until /confirm succeeds.
    """
    user_id = get_jwt_identity()
    user = db.session.get(User, int(user_id))
    if not user:
        return jsonify({"error": "User not found"}), 404

    if user.two_factor_enabled:
        return jsonify({"error": "2FA is already enabled. Disable it first."}), 409

    # Generate a new random base32 secret
    secret = pyotp.random_base32()
    user.totp_secret = secret
    db.session.commit()

    totp = _get_totp(secret)
    otpauth_uri = totp.provisioning_uri(name=user.email, issuer_name=ISSUER_NAME)

    return (
        jsonify(
            {
                "secret": secret,
                "otpauth_uri": otpauth_uri,
                "message": "Scan the QR code in your authenticator app, then call /confirm with a valid OTP.",
            }
        ),
        200,
    )


@totp_bp.route("/confirm", methods=["POST"])
@jwt_required()
def confirm():
    """
    Confirm that the user has successfully scanned the QR code by verifying
    their first OTP. Activates 2FA on success.

    Request JSON: {"otp": "123456"}
    """
    user_id = get_jwt_identity()
    user = db.session.get(User, int(user_id))
    if not user:
        return jsonify({"error": "User not found"}), 404

    if user.two_factor_enabled:
        return jsonify({"error": "2FA is already enabled"}), 409

    if not user.totp_secret:
        return jsonify({"error": "No pending 2FA setup. Call /setup first."}), 400

    otp = (request.get_json(silent=True) or {}).get("otp", "").strip()
    if not otp:
        return jsonify({"error": "OTP is required"}), 400

    totp = _get_totp(user.totp_secret)
    if not totp.verify(otp, valid_window=1):
        return jsonify({"error": "Invalid OTP. Please try again."}), 422

    user.two_factor_enabled = True
    db.session.commit()

    return (
        jsonify(
            {
                "message": "2FA enabled successfully.",
                "two_factor_enabled": True,
            }
        ),
        200,
    )


@totp_bp.route("/verify", methods=["POST"])
def verify():
    """
    Second step of login when 2FA is enabled.
    Accepts the temporary pre-auth token (issued by login when 2FA is required)
    and verifies the OTP.

    Request JSON: {"pre_auth_token": "...", "otp": "123456"}
    On success: returns full access_token + refresh_token.
    """
    data = request.get_json(silent=True) or {}
    pre_auth_token = data.get("pre_auth_token", "").strip()
    otp = data.get("otp", "").strip()

    if not pre_auth_token or not otp:
        return jsonify({"error": "pre_auth_token and otp are required"}), 400

    # Decode the pre-auth token (it's a short-lived access token with claim type=pre_auth)
    from flask_jwt_extended import decode_token

    try:
        decoded = decode_token(pre_auth_token)
    except Exception:
        return jsonify({"error": "Invalid or expired pre-auth token"}), 401

    if decoded.get("type") != "access":
        return jsonify({"error": "Invalid token type"}), 401

    # The sub claim encodes "pre_auth:<user_id>"
    sub = decoded.get("sub", "")
    if not sub.startswith("pre_auth:"):
        return jsonify({"error": "Invalid pre-auth token"}), 401

    user_id = sub.split(":", 1)[1]
    user = db.session.get(User, int(user_id))
    if not user or not user.two_factor_enabled or not user.totp_secret:
        return jsonify({"error": "User not found or 2FA not configured"}), 404

    totp = _get_totp(user.totp_secret)
    if not totp.verify(otp, valid_window=1):
        return jsonify({"error": "Invalid OTP"}), 422

    # Issue full tokens
    access_token = create_access_token(identity=str(user.id))
    refresh_token = create_refresh_token(identity=str(user.id))

    return (
        jsonify(
            {
                "status": "success",
                "message": "2FA verified",
                "user": user.to_dict(),
                "access_token": access_token,
                "refresh_token": refresh_token,
            }
        ),
        200,
    )


@totp_bp.route("/disable", methods=["POST"])
@jwt_required()
def disable():
    """
    Disable 2FA. Requires current password and a valid OTP to prevent
    an attacker with a stolen JWT from disabling 2FA.

    Request JSON: {"password": "...", "otp": "123456"}
    """
    user_id = get_jwt_identity()
    user = db.session.get(User, int(user_id))
    if not user:
        return jsonify({"error": "User not found"}), 404

    if not user.two_factor_enabled:
        return jsonify({"error": "2FA is not enabled"}), 400

    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    otp = data.get("otp", "").strip()

    if not password or not otp:
        return jsonify({"error": "password and otp are required"}), 400

    # Verify password
    if not bcrypt.checkpw(password.encode("utf-8"), user.password_hash.encode("utf-8")):
        return jsonify({"error": "Incorrect password"}), 401

    # Verify OTP
    totp = _get_totp(user.totp_secret)
    if not totp.verify(otp, valid_window=1):
        return jsonify({"error": "Invalid OTP"}), 422

    user.two_factor_enabled = False
    user.totp_secret = None
    db.session.commit()

    return (
        jsonify(
            {
                "message": "2FA disabled successfully.",
                "two_factor_enabled": False,
            }
        ),
        200,
    )
