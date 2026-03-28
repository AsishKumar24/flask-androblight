"""
Monitor Routes
===============
Installed app monitoring endpoint.
POST /monitor/installed-apps — checks a list of installed package names
against known malware hashes and VirusTotal.
"""

import re
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, verify_jwt_in_request

from config import VIRUSTOTAL_ENABLED
from services.virustotal import check_virustotal
from services.scanner import load_cache

monitor_bp = Blueprint("monitor", __name__)

# Known suspicious package name patterns (prefix-based heuristics)
_SUSPICIOUS_PATTERNS = [
    r"^com\.android\.system\.",  # fake system packages
    r"\.spy\.",  # spy/spyware indicators
    r"\.keylogger",
    r"\.stalker",
    r"\.tracker",
    r"\.sms\.stealer",
    r"\.bankbot",
]

_TRUSTED_PREFIXES = [
    "com.google.",
    "com.android.",
    "com.samsung.",
    "com.huawei.",
    "com.microsoft.",
    "com.facebook.",
    "com.whatsapp",
    "com.instagram",
    "com.spotify.",
    "com.netflix.",
    "com.amazon.",
]


def _assess_package_risk(package_name):
    """
    Heuristic risk assessment for a package name.
    Returns (risk_level, reason, is_verified).
    """
    # Check against known trusted prefixes
    for trusted in _TRUSTED_PREFIXES:
        if package_name.startswith(trusted):
            return "low", "Known trusted publisher", False

    # Check against suspicious patterns
    for pattern in _SUSPICIOUS_PATTERNS:
        if re.search(pattern, package_name, re.I):
            return "high", f"Suspicious package name pattern: {pattern}", False

    # Check if it exists in the scan cache by package name
    cache = load_cache()
    for scan in cache.values():
        cached_pkg = scan.get("metadata", {}).get("package_name")
        if cached_pkg == package_name:
            label = scan.get("ml_detection", {}).get("label", "Unknown")
            confidence = scan.get("ml_detection", {}).get("confidence", 0)
            if label == "Malware":
                return (
                    "critical",
                    f"Previously scanned — detected as Malware ({round(confidence * 100)}% confidence)",
                    True,
                )
            return "low", "Previously scanned — detected as Benign", True

    # Unknown/unverified
    return "unknown", "Package not in threat database", False


def _get_optional_user_id():
    try:
        verify_jwt_in_request(optional=True)
        identity = get_jwt_identity()
        return int(identity) if identity else None
    except Exception:
        return None


@monitor_bp.route("/monitor/installed-apps", methods=["POST"])
def check_installed_apps():
    """
    Check all installed package names against the malware database.

    Request JSON:
        {
          "packages": ["com.example.app1", "com.example.app2", ...]
        }

    Response:
        {
          "status": "success",
          "total": N,
          "results": [
            {
              "package_name": "com.example.app",
              "risk_level": "high" | "critical" | "low" | "unknown",
              "reason": "...",
              "verified": true | false
            },
            ...
          ],
          "summary": {
            "critical": 0, "high": 0, "low": 0, "unknown": 0
          }
        }
    """
    data = request.get_json()
    if not data or "packages" not in data:
        return jsonify({"error": "'packages' list is required", "status": "error"}), 400

    packages = data["packages"]
    if not isinstance(packages, list):
        return jsonify({"error": "'packages' must be an array", "status": "error"}), 400

    # Limit per request (full device lists can exceed 500)
    packages = packages[:3000]

    results = []
    summary = {"critical": 0, "high": 0, "low": 0, "unknown": 0}

    for pkg in packages:
        if not isinstance(pkg, str) or not pkg.strip():
            continue

        pkg = pkg.strip()
        risk_level, reason, verified = _assess_package_risk(pkg)

        results.append(
            {
                "package_name": pkg,
                "risk_level": risk_level,
                "reason": reason,
                "verified": verified,
            }
        )

        key = risk_level if risk_level in summary else "unknown"
        summary[key] = summary.get(key, 0) + 1

    # Sort: critical → high → unknown → low
    _order = {"critical": 0, "high": 1, "unknown": 2, "low": 3}
    results.sort(key=lambda r: _order.get(r["risk_level"], 2))

    return jsonify(
        {
            "status": "success",
            "total": len(results),
            "results": results,
            "summary": summary,
        }
    )
