"""
Rescan / Updates Routes
========================
Endpoint for clients to poll for verdict changes detected by the background rescanner.

Endpoints:
  GET  /rescan/updates?since=<iso8601>   — returns scan records with changed verdicts
  POST /rescan/trigger                   — manually trigger a rescan (admin-level action)
"""

from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from models.database import db, ScanRecord

rescan_bp = Blueprint("rescan", __name__)


@rescan_bp.route("/rescan/updates", methods=["GET"])
@jwt_required()
def get_rescan_updates():
    """
    Return scan records whose verdict changed since a given timestamp.

    Query params:
      since  — ISO-8601 datetime string (e.g. 2024-01-15T12:00:00).
               Defaults to 24 hours ago if omitted.
    """
    user_id = get_jwt_identity()

    since_str = request.args.get("since")
    if since_str:
        try:
            # Accept both with and without timezone suffix
            since_str_clean = since_str.replace("Z", "+00:00")
            since_dt = datetime.fromisoformat(since_str_clean)
            if since_dt.tzinfo is None:
                since_dt = since_dt.replace(tzinfo=timezone.utc)
        except ValueError:
            return (
                jsonify({"error": "Invalid since parameter; use ISO-8601 format"}),
                400,
            )
    else:
        from datetime import timedelta

        since_dt = datetime.now(timezone.utc) - timedelta(hours=24)

    records = (
        ScanRecord.query.filter(
            ScanRecord.user_id == user_id,
            ScanRecord.verdict_changed == True,
            ScanRecord.verdict_changed_at >= since_dt,
        )
        .order_by(ScanRecord.verdict_changed_at.desc())
        .all()
    )

    return (
        jsonify(
            {
                "updates": [r.to_dict() for r in records],
                "count": len(records),
                "since": since_dt.isoformat(),
            }
        ),
        200,
    )


@rescan_bp.route("/rescan/trigger", methods=["POST"])
@jwt_required()
def trigger_rescan():
    """Manually trigger a background rescan (runs synchronously in request)."""
    try:
        from services.rescanner import rescan_cached_hashes

        stats = rescan_cached_hashes()
        return jsonify({"message": "Rescan complete", "stats": stats}), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
