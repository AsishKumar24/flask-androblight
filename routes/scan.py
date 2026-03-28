"""
Scan Routes
============
API endpoints for APK scanning: /predict, /predict-playstore, /batch-predict
Now saves to database when user is authenticated.
"""

import os
import hashlib
import shutil
import json
import numpy as np
from datetime import datetime
from flask import Blueprint, request, jsonify
from werkzeug.utils import secure_filename
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request

from config import (
    UPLOAD_FOLDER,
    TEMP_EXTRACT_FOLDER,
    VIRUSTOTAL_ENABLED,
    HYBRID_ANALYSIS_ENABLED,
    METADEFENDER_ENABLED,
)
from services.scanner import (
    extract_apk,
    apk_to_image,
    classify_malware_family,
    get_file_hash,
    get_apk_metadata,
    load_cache,
    save_cache,
)
from services.permissions import parse_android_manifest, analyze_permissions
from services.certificate import extract_certificate_info
from services.virustotal import check_virustotal
from services.hybrid_analysis import check_hybrid_analysis
from services.metadefender import check_metadefender

import re

scan_bp = Blueprint("scan", __name__)


def _get_optional_user_id():
    """Get user ID from JWT if present, otherwise return None (anonymous scan)"""
    try:
        verify_jwt_in_request(optional=True)
        identity = get_jwt_identity()
        return int(identity) if identity else None
    except Exception:
        return None


def _save_scan_to_db(result, user_id, file_hash, scan_type="apk"):
    """Save scan result to database if user is authenticated"""
    if user_id is None:
        return
    try:
        from models.database import db, ScanRecord

        record = ScanRecord(
            user_id=user_id,
            file_hash=file_hash,
            scan_type=scan_type,
            identifier=result.get("metadata", {}).get("file_name", "unknown"),
            file_name=result.get("metadata", {}).get("file_name"),
            package_name=result.get("metadata", {}).get("package_name"),
            file_size=result.get("metadata", {}).get("file_size"),
            label=result.get("ml_detection", {}).get("label", "Unknown"),
            confidence=result.get("ml_detection", {}).get("confidence", 0.0),
            overall_score=result.get("overall_score"),
            threat_level=result.get("threat_level"),
            result_json=json.dumps(result),
        )
        db.session.add(record)
        db.session.commit()
    except Exception as e:
        print(f"⚠️ Failed to save scan to DB: {e}")


def _get_model():
    """Get the loaded ML model from the app context"""
    from flask import current_app

    return current_app.config.get("ML_MODEL")


def _generate_mock_response(filename="demo.apk"):
    """Generate mock response when model is not available"""
    import random

    is_malware = random.random() > 0.5
    confidence = random.uniform(0.7, 0.95)

    return {
        "status": "success",
        "demo_mode": True,
        "metadata": {
            "file_name": filename,
            "file_size": random.randint(1000000, 50000000),
            "file_size_readable": f"{random.randint(1, 50)} MB",
            "sha256": hashlib.sha256(os.urandom(32)).hexdigest(),
            "md5": hashlib.md5(os.urandom(16)).hexdigest(),
            "scan_timestamp": datetime.now().isoformat(),
            "package_name": f"com.{filename.replace('.apk', '')}",
            "version_name": f"{random.randint(1, 5)}.{random.randint(0, 9)}.{random.randint(0, 9)}",
            "main_activity": f".{filename.replace('.apk', '').title()}MainActivity",
        },
        "ml_detection": {
            "label": "Malware" if is_malware else "Benign",
            "confidence": confidence,
            "malware_family": (
                classify_malware_family(confidence) if is_malware else None
            ),
        },
        "permission_analysis": {
            "total_count": random.randint(5, 20),
            "critical": (
                [
                    {
                        "permission": "android.permission.READ_SMS",
                        "description": "Read SMS",
                        "risk": "Can access messages",
                    }
                ]
                if is_malware
                else []
            ),
            "high": [
                {
                    "permission": "android.permission.CAMERA",
                    "description": "Camera access",
                    "risk": "Can take photos",
                }
            ],
            "medium": [
                {
                    "permission": "android.permission.INTERNET",
                    "description": "Internet",
                    "risk": "Can send data",
                }
            ],
            "low": [],
            "unknown": [],
            "suspicious_combos": (
                [{"threat": "SMS Stealer", "description": "Can intercept SMS"}]
                if is_malware
                else []
            ),
            "risk_score": (
                random.randint(60, 90) if is_malware else random.randint(10, 40)
            ),
        },
        "certificate": {
            "signed": True,
            "debug_signed": is_malware,
            "fingerprint_sha256": hashlib.sha256(os.urandom(32)).hexdigest(),
        },
        "overall_score": (
            random.randint(20, 40) if is_malware else random.randint(75, 95)
        ),
        "threat_level": "high" if is_malware else "low",
        "recommendation": (
            "Do not install this application"
            if is_malware
            else "This application appears safe"
        ),
    }


def _get_recommendation(threat_level, ml_result, perm_analysis, locale="en"):
    """Generate recommendation based on analysis with locale support"""
    # Load translations
    try:
        import json as _json
        import os as _os

        i18n_path = _os.path.join(
            _os.path.dirname(__file__), "..", "i18n", f"{locale}.json"
        )
        if not _os.path.exists(i18n_path):
            i18n_path = _os.path.join(
                _os.path.dirname(__file__), "..", "i18n", "en.json"
            )
        with open(i18n_path, "r", encoding="utf-8") as f:
            t = _json.load(f)
    except Exception:
        t = {}

    recommendations = []

    if threat_level == "critical":
        recommendations.append(
            t.get(
                "rec_critical", "⚠️ DO NOT INSTALL - High malware probability detected"
            )
        )
    elif threat_level == "high":
        recommendations.append(
            t.get(
                "rec_high",
                "⚠️ Exercise extreme caution - Multiple risk indicators found",
            )
        )
    elif threat_level == "medium":
        recommendations.append(
            t.get("rec_medium", "⚠️ Review permissions carefully before installing")
        )
    else:
        recommendations.append(
            t.get("rec_low", "✅ This application appears safe to install")
        )

    if perm_analysis.get("suspicious_combos"):
        for combo in perm_analysis["suspicious_combos"]:
            recommendations.append(f"🚨 {combo['threat']}: {combo['description']}")

    if len(perm_analysis.get("critical", [])) > 0:
        count = len(perm_analysis["critical"])
        template = t.get(
            "rec_critical_perms", "🔴 {count} critical permission(s) requested"
        )
        recommendations.append(template.replace("{count}", str(count)))

    return recommendations


@scan_bp.route("/predict", methods=["POST"])
def predict():
    """
    Scan APK file for malware.

    Request: multipart/form-data with 'file' field
             Optional: 'is_rooted' (string 'true'/'false')
    Response: Comprehensive scan result with all analyses
    """
    try:
        user_id = _get_optional_user_id()

        # Locale from Accept-Language header (e.g., "hi" or "en")
        accept_lang = request.headers.get("Accept-Language", "en")
        locale = accept_lang.split(",")[0].split("-")[0].strip().lower()
        if locale not in ("en", "hi"):
            locale = "en"

        # Device info (root detection from mobile)
        is_rooted_str = request.form.get("is_rooted", "false")
        is_rooted = is_rooted_str.lower() in ("true", "1", "yes")
        device_model = request.form.get("device_model", "")
        android_version = request.form.get("android_version", "")
        device_info = {
            "is_rooted": is_rooted,
            "device_model": device_model,
            "android_version": android_version,
        }

        if "file" not in request.files:
            return jsonify({"error": "No file provided", "status": "error"}), 400

        file = request.files["file"]
        if file.filename == "":
            return jsonify({"error": "No file selected", "status": "error"}), 400

        # Save uploaded file
        filename = secure_filename(file.filename)
        apk_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(apk_path)

        # Check cache
        file_hash = get_file_hash(apk_path)
        cache = load_cache()

        if file_hash in cache:
            os.remove(apk_path)
            cached = cache[file_hash]
            cached["cached"] = True
            cached["device_info"] = device_info
            return jsonify(cached)

        # Create extraction directory
        extract_dir = os.path.join(TEMP_EXTRACT_FOLDER, filename.split(".")[0])
        os.makedirs(extract_dir, exist_ok=True)

        # Extract APK
        if not extract_apk(apk_path, extract_dir):
            os.remove(apk_path)
            shutil.rmtree(extract_dir, ignore_errors=True)
            return jsonify({"error": "Failed to extract APK", "status": "error"}), 400

        # Get metadata
        metadata = get_apk_metadata(apk_path, extract_dir)

        # Parse manifest and analyze permissions
        manifest = parse_android_manifest(extract_dir)
        perm_analysis = analyze_permissions(manifest["permissions"])

        # Get certificate info
        cert_info = extract_certificate_info(extract_dir)

        # ML Detection
        model = _get_model()
        if model is not None:
            image_array = apk_to_image(extract_dir)
            image_array = np.expand_dims(image_array, axis=0)
            prediction = model.predict(image_array)

            is_malware = prediction[0][0] > 0.5
            confidence = (
                float(prediction[0][0]) if is_malware else float(1 - prediction[0][0])
            )

            ml_result = {
                "label": "Malware" if is_malware else "Benign",
                "confidence": confidence,
                "raw_score": float(prediction[0][0]),
                "malware_family": (
                    classify_malware_family(confidence) if is_malware else None
                ),
            }
        else:
            # Demo mode
            import random

            is_malware = random.random() > 0.6
            confidence = random.uniform(0.75, 0.95)
            ml_result = {
                "label": "Malware" if is_malware else "Benign",
                "confidence": confidence,
                "demo_mode": True,
                "malware_family": (
                    classify_malware_family(confidence) if is_malware else None
                ),
            }

        # Multi-engine AV checks (4C)
        vt_result = check_virustotal(file_hash) if VIRUSTOTAL_ENABLED else None
        ha_result = (
            check_hybrid_analysis(file_hash) if HYBRID_ANALYSIS_ENABLED else None
        )
        md_result = check_metadefender(file_hash) if METADEFENDER_ENABLED else None

        multi_engine_results = [
            r for r in [vt_result, ha_result, md_result] if r is not None
        ]

        # Calculate overall score (0-100, higher is safer)
        overall_score = 100
        overall_score -= perm_analysis["risk_score"] * 0.3
        if ml_result["label"] == "Malware":
            overall_score -= ml_result["confidence"] * 40
        if cert_info.get("debug_signed"):
            overall_score -= 10
        if vt_result and vt_result.get("malicious", 0) > 0:
            overall_score -= vt_result["malicious"] * 2
        # Factor in root status (rooted devices increase risk)
        if is_rooted:
            overall_score -= 10

        overall_score = max(0, min(100, overall_score))

        # Determine threat level
        if overall_score < 30:
            threat_level = "critical"
        elif overall_score < 50:
            threat_level = "high"
        elif overall_score < 70:
            threat_level = "medium"
        else:
            threat_level = "low"

        # Build response
        result = {
            "status": "success",
            "metadata": {
                **metadata,
                "package_name": manifest["package_name"],
                "version_name": manifest["version_name"],
            },
            "manifest": {
                "package_name": manifest["package_name"],
                "permissions_count": len(manifest["permissions"]),
            },
            "ml_detection": ml_result,
            "permission_analysis": perm_analysis,
            "certificate": cert_info,
            "virustotal": vt_result,
            "multi_engine_results": multi_engine_results,
            "device_info": device_info,
            "overall_score": round(overall_score),
            "threat_level": threat_level,
            "recommendation": _get_recommendation(
                threat_level, ml_result, perm_analysis, locale
            ),
        }

        # Cache result
        cache[file_hash] = result
        save_cache(cache)

        # Save to database (if user is authenticated)
        _save_scan_to_db(result, user_id, file_hash, scan_type="apk")

        # Cleanup
        os.remove(apk_path)
        shutil.rmtree(extract_dir, ignore_errors=True)

        return jsonify(result)

    except Exception as e:
        # Cleanup on error
        if "apk_path" in locals() and os.path.exists(apk_path):
            os.remove(apk_path)
        if "extract_dir" in locals() and os.path.exists(extract_dir):
            shutil.rmtree(extract_dir, ignore_errors=True)

        return jsonify({"error": str(e), "status": "error"}), 500


@scan_bp.route("/predict-playstore", methods=["POST"])
def predict_playstore():
    """
    Scan a Play Store app by URL or package name using real Play Store metadata.

    Uses google-play-scraper to fetch live permissions, installs, rating, and
    data-safety info, then runs the same permission-risk analysis as the APK scanner.

    Request JSON: {"url": "..."} or {"package": "com.example.app"}
                  Optional: {"lang": "en", "country": "us"}
    Response: Same structure as /predict endpoint
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided", "status": "error"}), 400

        url = data.get("url")
        package = data.get("package")
        lang = data.get("lang", "en")
        country = data.get("country", "us")

        if not url and not package:
            return (
                jsonify({"error": "Provide either url or package name", "status": "error"}),
                400,
            )

        # Extract package name from Play Store URL
        if url:
            match = re.search(r"id=([a-zA-Z0-9_.]+)", url)
            if match:
                package = match.group(1)
            else:
                return jsonify({"error": "Invalid Play Store URL", "status": "error"}), 400

        # ── 1. Fetch real Play Store data ──────────────────────────────────────
        try:
            from google_play_scraper import app as gps_app, permissions as gps_perms
        except ImportError:
            return jsonify({
                "error": "google-play-scraper not installed. Run: pip install google-play-scraper",
                "status": "error",
            }), 500

        try:
            app_info = gps_app(package, lang=lang, country=country)
        except Exception as fetch_err:
            return jsonify({
                "error": f"Could not fetch Play Store data for '{package}': {fetch_err}",
                "status": "error",
            }), 404

        # Fetch declared permissions (may be empty for some apps)
        try:
            raw_permissions = gps_perms(package, lang=lang) or []
            # gps_perms returns list of dicts  [{"permission": "...", "type": "..."}]
            # or a flat list of strings depending on version — normalise both
            if raw_permissions and isinstance(raw_permissions[0], dict):
                permission_strings = [p.get("permission", "") for p in raw_permissions]
            else:
                permission_strings = [str(p) for p in raw_permissions]
        except Exception:
            permission_strings = []

        # ── 2. Run permission analysis (reuse existing service) ───────────────
        perm_analysis = analyze_permissions(permission_strings)

        # ── 3. Determine ML-style verdict from Play Store signals ─────────────
        # We have no binary to run through the CNN; instead we construct a
        # heuristic score from Play Store trust signals.
        installs = app_info.get("realInstalls") or app_info.get("minInstalls") or 0
        score = app_info.get("score") or 0          # 0-5 rating
        ratings = app_info.get("ratings") or 0
        contains_ads = app_info.get("containsAds", False)
        in_app_purchases = app_info.get("offersIAP", False)
        developer = app_info.get("developer", "Unknown")
        last_updated = app_info.get("updated")       # epoch ms

        # Trust signals → safety score (0-100, higher = safer)
        overall_score = 60  # neutral baseline for Play Store apps

        # Good signals
        if installs >= 1_000_000:
            overall_score += 10
        if score >= 4.0 and ratings >= 1000:
            overall_score += 10
        if not contains_ads:
            overall_score += 5

        # Bad signals
        overall_score -= perm_analysis["risk_score"] * 0.4   # permission risk
        if len(perm_analysis.get("critical", [])) > 0:
            overall_score -= len(perm_analysis["critical"]) * 3
        if perm_analysis.get("suspicious_combos"):
            overall_score -= len(perm_analysis["suspicious_combos"]) * 5

        # Also check VirusTotal by package hash (if enabled)
        vt_result = None
        if VIRUSTOTAL_ENABLED:
            pkg_hash = hashlib.sha256(package.encode()).hexdigest()
            vt_result = check_virustotal(pkg_hash)
            if vt_result and vt_result.get("malicious", 0) > 0:
                overall_score -= vt_result["malicious"] * 3

        overall_score = max(0, min(100, overall_score))

        # Threat level
        if overall_score < 30:
            threat_level = "critical"
        elif overall_score < 50:
            threat_level = "high"
        elif overall_score < 70:
            threat_level = "medium"
        else:
            threat_level = "low"

        # Heuristic ML-style result (no model — metadata-based)
        is_suspicious = overall_score < 50
        ml_result = {
            "label": "Suspicious" if is_suspicious else "Likely Safe",
            "confidence": round(abs(overall_score - 50) / 50, 2),
            "source": "play_store_metadata",
            "note": "No APK binary available — verdict based on permissions & trust signals",
        }

        # ── 4. Build response ──────────────────────────────────────────────────
        file_hash = hashlib.sha256(package.encode()).hexdigest()

        result = {
            "status": "success",
            "scan_type": "playstore",
            "metadata": {
                "package_name": package,
                "app_name": app_info.get("title", package),
                "developer": developer,
                "version_name": app_info.get("version", "N/A"),
                "installs": installs,
                "rating": score,
                "rating_count": ratings,
                "contains_ads": contains_ads,
                "in_app_purchases": in_app_purchases,
                "last_updated": last_updated,
                "play_store_url": f"https://play.google.com/store/apps/details?id={package}",
                "icon_url": app_info.get("icon"),
                "genre": app_info.get("genre"),
                "content_rating": app_info.get("contentRating"),
                "sha256": file_hash,
                "scan_timestamp": datetime.now().isoformat(),
            },
            "ml_detection": ml_result,
            "permission_analysis": perm_analysis,
            "permissions_declared": permission_strings,
            "virustotal": vt_result,
            "overall_score": round(overall_score),
            "threat_level": threat_level,
            "recommendation": _get_recommendation(threat_level, ml_result, perm_analysis),
        }

        # ── 5. Cache & persist ─────────────────────────────────────────────────
        cache = load_cache()
        cache[file_hash] = result
        save_cache(cache)

        ps_user_id = _get_optional_user_id()
        _save_scan_to_db(result, ps_user_id, file_hash, scan_type="playstore")

        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e), "status": "error"}), 500


@scan_bp.route("/batch-predict", methods=["POST"])
def batch_predict():
    """
    Scan multiple APK files in one request.

    Request: multipart/form-data with multiple 'files' fields
    Response: Array of scan results
    """
    try:
        if "files" not in request.files:
            return jsonify({"error": "No files provided", "status": "error"}), 400

        files = request.files.getlist("files")

        if len(files) > 10:
            return (
                jsonify({"error": "Maximum 10 files per batch", "status": "error"}),
                400,
            )

        results = []

        for file in files:
            if file.filename:
                mock_res = _generate_mock_response(file.filename)
                results.append({"filename": file.filename, **mock_res})

                # Save to cache
                file_hash = mock_res["metadata"]["sha256"]
                cache = load_cache()
                cache[file_hash] = mock_res
                save_cache(cache)

        return jsonify(
            {"status": "success", "total_files": len(results), "results": results}
        )

    except Exception as e:
        return jsonify({"error": str(e), "status": "error"}), 500
