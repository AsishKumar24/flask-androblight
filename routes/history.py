"""
History Routes
===============
Paginated, filterable, searchable scan history endpoint.
"""

from datetime import datetime

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from sqlalchemy import or_

from models.database import ScanRecord

history_bp = Blueprint("history", __name__)

ITEMS_PER_PAGE = 20


@history_bp.route("/history", methods=["GET"])
@jwt_required()
def get_history():
    """
    Get paginated, filtered scan history.

    Query params:
        search  — search term (matches file_name, package_name, identifier)
        filter  — 'malware', 'benign', 'apk', 'playstore'
        sort    — 'date', 'date_asc', 'risk', 'confidence'
        from    — ISO date string (start of date range)
        to      — ISO date string (end of date range)
        page    — page number (default 1)

    Response: Paginated array of scan records
    """
    current_user_id = int(get_jwt_identity())

    # Base query
    query = ScanRecord.query.filter_by(user_id=current_user_id)

    # Search filter
    search = request.args.get("search", "").strip()
    if search:
        search_pattern = f"%{search}%"
        query = query.filter(
            or_(
                ScanRecord.file_name.ilike(search_pattern),
                ScanRecord.package_name.ilike(search_pattern),
                ScanRecord.identifier.ilike(search_pattern),
            )
        )

    # Type/label filter
    filter_by = request.args.get("filter", "").lower()
    if filter_by == "malware":
        query = query.filter(ScanRecord.label == "Malware")
    elif filter_by == "benign":
        query = query.filter(ScanRecord.label == "Benign")
    elif filter_by == "apk":
        query = query.filter(ScanRecord.scan_type == "apk")
    elif filter_by == "playstore":
        query = query.filter(ScanRecord.scan_type == "playstore")

    # Date range filter
    from_date = request.args.get("from")
    to_date = request.args.get("to")
    if from_date:
        try:
            from_dt = datetime.fromisoformat(from_date.replace("Z", "+00:00"))
            query = query.filter(ScanRecord.created_at >= from_dt)
        except (ValueError, TypeError):
            pass
    if to_date:
        try:
            to_dt = datetime.fromisoformat(to_date.replace("Z", "+00:00"))
            query = query.filter(ScanRecord.created_at <= to_dt)
        except (ValueError, TypeError):
            pass

    # Sort
    sort_by = request.args.get("sort", "date").lower()
    if sort_by == "date_asc" or sort_by == "oldest":
        query = query.order_by(ScanRecord.created_at.asc())
    elif sort_by == "risk":
        query = query.order_by(
            ScanRecord.overall_score.asc()
        )  # Lower score = higher risk
    elif sort_by == "confidence":
        query = query.order_by(ScanRecord.confidence.desc())
    else:  # default: newest first
        query = query.order_by(ScanRecord.created_at.desc())

    # Pagination
    page = request.args.get("page", 1, type=int)
    page = max(1, page)

    total = query.count()
    records = query.offset((page - 1) * ITEMS_PER_PAGE).limit(ITEMS_PER_PAGE).all()

    return jsonify(
        {
            "status": "success",
            "records": [r.to_dict() for r in records],
            "pagination": {
                "page": page,
                "per_page": ITEMS_PER_PAGE,
                "total": total,
                "total_pages": max(1, (total + ITEMS_PER_PAGE - 1) // ITEMS_PER_PAGE),
                "has_next": page * ITEMS_PER_PAGE < total,
                "has_prev": page > 1,
            },
        }
    )
