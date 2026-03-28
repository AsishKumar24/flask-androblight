"""
Auth Routes
============
User registration, login, and token refresh endpoints.
"""

import bcrypt
from flask import Blueprint, request, jsonify
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
)

from models.database import db, User

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


@auth_bp.route("/register", methods=["POST"])
def register():
    """
    Register a new user.

    Request JSON: {"email": "...", "password": "...", "display_name": "..."}
    Response: JWT access + refresh tokens
    """
    data = request.get_json()

    if not data:
        return jsonify({"status": "error", "error": "No JSON data provided"}), 400

    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    display_name = data.get("display_name", "").strip()

    # Validation
    if not email or not password:
        return (
            jsonify({"status": "error", "error": "Email and password are required"}),
            400,
        )

    if len(password) < 6:
        return (
            jsonify(
                {"status": "error", "error": "Password must be at least 6 characters"}
            ),
            400,
        )

    if "@" not in email or "." not in email:
        return jsonify({"status": "error", "error": "Invalid email format"}), 400

    # Check if user already exists
    existing = User.query.filter_by(email=email).first()
    if existing:
        return jsonify({"status": "error", "error": "Email already registered"}), 409

    # Hash password
    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode(
        "utf-8"
    )

    # Create user
    user = User(
        email=email,
        password_hash=password_hash,
        display_name=display_name or email.split("@")[0],
    )
    db.session.add(user)
    db.session.commit()

    # Generate tokens
    access_token = create_access_token(identity=str(user.id))
    refresh_token = create_refresh_token(identity=str(user.id))

    return (
        jsonify(
            {
                "status": "success",
                "message": "Registration successful",
                "user": user.to_dict(),
                "access_token": access_token,
                "refresh_token": refresh_token,
            }
        ),
        201,
    )


@auth_bp.route("/login", methods=["POST"])
def login():
    """
    Login with email and password.

    Request JSON: {"email": "...", "password": "..."}
    Response: JWT access + refresh tokens
    """
    data = request.get_json()

    if not data:
        return jsonify({"status": "error", "error": "No JSON data provided"}), 400

    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return (
            jsonify({"status": "error", "error": "Email and password are required"}),
            400,
        )

    # Find user
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"status": "error", "error": "Invalid email or password"}), 401

    # Verify password
    if not bcrypt.checkpw(password.encode("utf-8"), user.password_hash.encode("utf-8")):
        return jsonify({"status": "error", "error": "Invalid email or password"}), 401

    # If 2FA is enabled, issue a short-lived pre-auth token instead of full tokens.
    # The client must complete /auth/2fa/verify to receive real JWT tokens.
    if user.two_factor_enabled:
        pre_auth_token = create_access_token(
            identity=f"pre_auth:{user.id}",
            expires_delta=__import__("datetime").timedelta(minutes=5),
        )
        return (
            jsonify(
                {
                    "status": "2fa_required",
                    "message": "OTP required to complete login",
                    "pre_auth_token": pre_auth_token,
                    "user": {"email": user.email, "display_name": user.display_name},
                }
            ),
            200,
        )

    # Generate tokens
    access_token = create_access_token(identity=str(user.id))
    refresh_token = create_refresh_token(identity=str(user.id))

    return jsonify(
        {
            "status": "success",
            "message": "Login successful",
            "user": user.to_dict(),
            "access_token": access_token,
            "refresh_token": refresh_token,
        }
    )


@auth_bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    """
    Refresh an expired access token.

    Headers: Authorization: Bearer <refresh_token>
    Response: New access token
    """
    current_user_id = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user_id)

    return jsonify(
        {
            "status": "success",
            "access_token": new_access_token,
        }
    )


@auth_bp.route("/me", methods=["GET"])
@jwt_required()
def get_profile():
    """
    Get current user's profile.

    Headers: Authorization: Bearer <access_token>
    Response: User profile data
    """
    current_user_id = get_jwt_identity()
    user = db.session.get(User, int(current_user_id))

    if not user:
        return jsonify({"status": "error", "error": "User not found"}), 404

    return jsonify(
        {
            "status": "success",
            "user": user.to_dict(),
        }
    )
