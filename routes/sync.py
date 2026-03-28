"""
Sync Routes
=============
Cloud sync endpoints for scan history across devices.
"""

import json
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from models.database import db, ScanRecord

sync_bp = Blueprint('sync', __name__, url_prefix='/sync')


@sync_bp.route('/history', methods=['GET'])
@jwt_required()
def get_sync_history():
    """
    Get scan records newer than a given timestamp (for incremental sync).

    Query params:
        since (ISO timestamp) — return records updated after this time

    Response: Array of scan records
    """
    current_user_id = int(get_jwt_identity())
    since = request.args.get('since')

    query = ScanRecord.query.filter_by(user_id=current_user_id)

    if since:
        try:
            since_dt = datetime.fromisoformat(since.replace('Z', '+00:00'))
            query = query.filter(ScanRecord.updated_at > since_dt)
        except (ValueError, TypeError):
            return jsonify({'status': 'error', 'error': 'Invalid timestamp format'}), 400

    records = query.order_by(ScanRecord.created_at.desc()).all()

    return jsonify({
        'status': 'success',
        'count': len(records),
        'records': [r.to_dict() for r in records],
        'sync_timestamp': datetime.now(timezone.utc).isoformat(),
    })


@sync_bp.route('/history', methods=['POST'])
@jwt_required()
def push_sync_history():
    """
    Receive a batch of scan records from a client device.

    Request JSON: {"records": [...]}
    Response: Count of synced records
    """
    current_user_id = int(get_jwt_identity())
    data = request.get_json()

    if not data or 'records' not in data:
        return jsonify({'status': 'error', 'error': 'No records provided'}), 400

    records = data['records']
    synced_count = 0

    for record_data in records:
        # Check if this record already exists (by file_hash + user)
        existing = None
        if record_data.get('file_hash'):
            existing = ScanRecord.query.filter_by(
                user_id=current_user_id,
                file_hash=record_data['file_hash']
            ).first()

        if existing:
            # Update existing record (server timestamp wins)
            existing.label = record_data.get('label', existing.label)
            existing.confidence = record_data.get('confidence', existing.confidence)
            existing.overall_score = record_data.get('overall_score', existing.overall_score)
            existing.threat_level = record_data.get('threat_level', existing.threat_level)
            if record_data.get('result_json'):
                existing.result_json = json.dumps(record_data['result_json']) if isinstance(record_data['result_json'], dict) else record_data['result_json']
        else:
            # Create new record
            new_record = ScanRecord(
                user_id=current_user_id,
                file_hash=record_data.get('file_hash'),
                scan_type=record_data.get('scan_type', 'apk'),
                identifier=record_data.get('identifier', 'unknown'),
                file_name=record_data.get('file_name'),
                package_name=record_data.get('package_name'),
                file_size=record_data.get('file_size'),
                label=record_data.get('label', 'Unknown'),
                confidence=record_data.get('confidence', 0.0),
                overall_score=record_data.get('overall_score'),
                threat_level=record_data.get('threat_level'),
                result_json=json.dumps(record_data['result_json']) if isinstance(record_data.get('result_json'), dict) else record_data.get('result_json'),
            )
            db.session.add(new_record)
            synced_count += 1

    db.session.commit()

    return jsonify({
        'status': 'success',
        'synced': synced_count,
        'updated': len(records) - synced_count,
        'sync_timestamp': datetime.now(timezone.utc).isoformat(),
    })
