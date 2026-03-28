"""
Custom Threat Rules Routes
===========================
CRUD endpoints for user-defined permission-based threat rules.

Endpoints:
  GET    /rules           — list all active rules for the authenticated user
  POST   /rules           — create a new rule
  PUT    /rules/<id>      — update an existing rule (owner only)
  DELETE /rules/<id>      — delete a rule (owner only)
"""

import json
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from models.database import db, ThreatRule

rules_bp = Blueprint("rules", __name__)


def _current_user_id() -> int:
    """JWT identity is stored as str(user.id); DB columns use int."""
    return int(get_jwt_identity())


@rules_bp.route("/rules", methods=["GET"])
@jwt_required()
def list_rules():
    """Return all active (and inactive) rules for the current user, plus global rules (user_id=NULL)."""
    user_id = _current_user_id()

    rules = (
        ThreatRule.query.filter(
            (ThreatRule.user_id == user_id) | (ThreatRule.user_id.is_(None))
        )
        .order_by(ThreatRule.created_at.desc())
        .all()
    )

    return jsonify({"rules": [r.to_dict() for r in rules]}), 200


@rules_bp.route("/rules", methods=["POST"])
@jwt_required()
def create_rule():
    """Create a new custom threat rule."""
    user_id = _current_user_id()
    data = request.get_json(silent=True) or {}

    name = data.get("name", "").strip()
    permissions = data.get("permissions", [])
    threat = data.get("threat", "").strip()
    description = data.get("description", "").strip()

    if not name or not permissions or not threat or not description:
        return (
            jsonify(
                {"error": "name, permissions, threat, and description are required"}
            ),
            400,
        )

    if not isinstance(permissions, list) or not all(
        isinstance(p, str) for p in permissions
    ):
        return jsonify({"error": "permissions must be a list of strings"}), 400

    if len(permissions) == 0:
        return jsonify({"error": "permissions list must not be empty"}), 400

    rule = ThreatRule(
        user_id=user_id,
        name=name,
        permissions=json.dumps(permissions),
        threat=threat,
        description=description,
        is_active=data.get("is_active", True),
    )
    db.session.add(rule)
    db.session.commit()

    return jsonify({"message": "Rule created", "rule": rule.to_dict()}), 201


@rules_bp.route("/rules/<int:rule_id>", methods=["PUT"])
@jwt_required()
def update_rule(rule_id):
    """Update a custom threat rule (owner only)."""
    user_id = _current_user_id()
    rule = ThreatRule.query.get_or_404(rule_id)

    if rule.user_id != user_id:
        return jsonify({"error": "Forbidden"}), 403

    data = request.get_json(silent=True) or {}

    if "name" in data:
        rule.name = data["name"].strip()
    if "permissions" in data:
        perms = data["permissions"]
        if not isinstance(perms, list) or not all(isinstance(p, str) for p in perms):
            return jsonify({"error": "permissions must be a list of strings"}), 400
        rule.permissions = json.dumps(perms)
    if "threat" in data:
        rule.threat = data["threat"].strip()
    if "description" in data:
        rule.description = data["description"].strip()
    if "is_active" in data:
        rule.is_active = bool(data["is_active"])

    db.session.commit()
    return jsonify({"message": "Rule updated", "rule": rule.to_dict()}), 200


@rules_bp.route("/rules/<int:rule_id>", methods=["DELETE"])
@jwt_required()
def delete_rule(rule_id):
    """Delete a custom threat rule (owner only)."""
    user_id = _current_user_id()
    rule = ThreatRule.query.get_or_404(rule_id)

    if rule.user_id != user_id:
        return jsonify({"error": "Forbidden"}), 403

    db.session.delete(rule)
    db.session.commit()
    return jsonify({"message": "Rule deleted"}), 200
