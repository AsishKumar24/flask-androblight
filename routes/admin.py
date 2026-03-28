"""
Admin Routes
=============
Administrative and utility endpoints: /health, /stats, /clear-cache, /report/<hash>
"""

import os
from flask import Blueprint, jsonify, send_file

from config import (
    CACHE_FILE,
    REPORTS_FOLDER,
    VIRUSTOTAL_ENABLED,
    HYBRID_ANALYSIS_ENABLED,
    METADEFENDER_ENABLED,
)
from services.scanner import load_cache
from services.report import generate_pdf_report, REPORTLAB_AVAILABLE

admin_bp = Blueprint("admin", __name__)


def _get_model():
    """Get the loaded ML model from the app context"""
    from flask import current_app

    return current_app.config.get("ML_MODEL")


@admin_bp.route("/health", methods=["GET"])
def health():
    """Health check endpoint"""
    model = _get_model()
    return jsonify(
        {
            "status": "ok",
            "version": "3.0.0",
            "model_loaded": model is not None,
            "virustotal_enabled": VIRUSTOTAL_ENABLED,
            "features": [
                "apk_scan",
                "permission_analysis",
                "certificate_verification",
                "metadata_extraction",
                "risk_scoring",
                "pdf_reports",
            ],
        }
    )


@admin_bp.route("/report/<file_hash>", methods=["GET"])
def get_report(file_hash):
    """
    Generate PDF report for a cached scan.

    URL param: file_hash (SHA256)
    Response: PDF file download
    """
    print(f"📄 Report requested for: {file_hash}")
    try:
        cache = load_cache()

        if file_hash not in cache:
            print(f"❌ Report failed: Hash {file_hash} not found in cache")
            return (
                jsonify(
                    {
                        "error": "Scan not found in server cache. Please re-scan the file.",
                        "status": "error",
                    }
                ),
                404,
            )

        if not REPORTLAB_AVAILABLE:
            print("❌ Report failed: ReportLab library not loaded")
            return (
                jsonify(
                    {
                        "error": "PDF generation engine not available on server",
                        "status": "error",
                    }
                ),
                501,
            )

        # Generate report
        os.makedirs(REPORTS_FOLDER, exist_ok=True)
        report_path = os.path.join(REPORTS_FOLDER, f"{file_hash[:16]}_report.pdf")

        print(f"⏳ Generating PDF: {report_path}...")
        generated_path = generate_pdf_report(cache[file_hash], report_path)

        if not generated_path or not os.path.exists(generated_path):
            print("❌ Report failed: PDF generation function returned error")
            return (
                jsonify(
                    {"error": "Failed to generate PDF document", "status": "error"}
                ),
                500,
            )

        print(f"✅ Report ready: {report_path}")
        return send_file(
            report_path, as_attachment=True, download_name="androblight_report.pdf"
        )

    except Exception as e:
        print(f"❌ Report error: {str(e)}")
        return jsonify({"error": str(e), "status": "error"}), 500


@admin_bp.route("/stats", methods=["GET"])
def get_stats():
    """Get scanning statistics"""
    cache = load_cache()

    total_scans = len(cache)
    malware_count = sum(
        1 for r in cache.values() if r.get("ml_detection", {}).get("label") == "Malware"
    )
    benign_count = total_scans - malware_count

    return jsonify(
        {
            "status": "success",
            "statistics": {
                "total_scans": total_scans,
                "malware_detected": malware_count,
                "benign_apps": benign_count,
                "detection_rate": (
                    f"{(malware_count/total_scans*100):.1f}%"
                    if total_scans > 0
                    else "0%"
                ),
            },
        }
    )


@admin_bp.route("/clear-cache", methods=["POST"])
def clear_cache():
    """Clear scan cache (admin endpoint)"""
    try:
        if os.path.exists(CACHE_FILE):
            os.remove(CACHE_FILE)
        return jsonify({"status": "success", "message": "Cache cleared"})
    except Exception as e:
        return jsonify({"error": str(e), "status": "error"}), 500


@admin_bp.route("/engines", methods=["GET"])
def get_engines():
    """List available AV engine integrations and their enabled status"""
    return jsonify(
        {
            "status": "success",
            "engines": [
                {
                    "name": "VirusTotal",
                    "description": "Aggregates 70+ AV engines",
                    "enabled": VIRUSTOTAL_ENABLED,
                },
                {
                    "name": "Hybrid Analysis",
                    "description": "Falcon Sandbox malware analysis",
                    "enabled": HYBRID_ANALYSIS_ENABLED,
                },
                {
                    "name": "MetaDefender",
                    "description": "OPSWAT multi-engine file scanning",
                    "enabled": METADEFENDER_ENABLED,
                },
            ],
        }
    )
