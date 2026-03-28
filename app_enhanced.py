"""
AndroBlight Enhanced API Server
================================
A comprehensive Android malware detection API with advanced features:
- APK file scanning with CNN-LSTM model
- Permission analysis and risk scoring
- APK metadata extraction
- Certificate verification
- VirusTotal integration (optional)
- Play Store app scanning
- Detailed threat reports

Author: AndroBlight Team
"""

# Suppress TensorFlow warnings and info messages
import os

os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"  # 0=all, 1=INFO, 2=WARNING, 3=ERROR only
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=FutureWarning)

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename
import tensorflow as tf
import numpy as np
import cv2
import shutil
import zipfile
import hashlib
import xml.etree.ElementTree as ET
from datetime import datetime
import json
import re
import requests

# Optional: PDF report generation
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    from reportlab.lib.colors import HexColor

    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

app = Flask(__name__)

# ============================================================================
# CONFIGURATION
# ============================================================================

UPLOAD_FOLDER = "uploads"
TEMP_EXTRACT_FOLDER = "temp_extract"
REPORTS_FOLDER = "reports"
CACHE_FILE = "scan_cache.json"

# VirusTotal API (optional - set your API key)
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
VIRUSTOTAL_ENABLED = bool(VIRUSTOTAL_API_KEY)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100MB max file size

# CORS - Allow all origins for development
CORS(app, resources={r"/*": {"origins": "*"}})

# ============================================================================
# DANGEROUS PERMISSIONS DATABASE
# ============================================================================

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS": {
        "level": "critical",
        "description": "Read SMS messages",
        "risk": "Can access private messages and OTPs",
    },
    "android.permission.SEND_SMS": {
        "level": "critical",
        "description": "Send SMS messages",
        "risk": "Can send premium SMS causing charges",
    },
    "android.permission.READ_CONTACTS": {
        "level": "high",
        "description": "Read contacts",
        "risk": "Can harvest contact information",
    },
    "android.permission.READ_CALL_LOG": {
        "level": "high",
        "description": "Read call history",
        "risk": "Can monitor communication patterns",
    },
    "android.permission.RECORD_AUDIO": {
        "level": "critical",
        "description": "Record audio",
        "risk": "Can secretly record conversations",
    },
    "android.permission.CAMERA": {
        "level": "high",
        "description": "Access camera",
        "risk": "Can take photos/videos without consent",
    },
    "android.permission.ACCESS_FINE_LOCATION": {
        "level": "high",
        "description": "Precise location access",
        "risk": "Can track user location precisely",
    },
    "android.permission.ACCESS_COARSE_LOCATION": {
        "level": "medium",
        "description": "Approximate location",
        "risk": "Can track user location approximately",
    },
    "android.permission.READ_EXTERNAL_STORAGE": {
        "level": "medium",
        "description": "Read storage",
        "risk": "Can access files on device",
    },
    "android.permission.WRITE_EXTERNAL_STORAGE": {
        "level": "medium",
        "description": "Write storage",
        "risk": "Can modify files on device",
    },
    "android.permission.INTERNET": {
        "level": "low",
        "description": "Internet access",
        "risk": "Can send data to remote servers",
    },
    "android.permission.RECEIVE_BOOT_COMPLETED": {
        "level": "medium",
        "description": "Run at startup",
        "risk": "Can run automatically when device boots",
    },
    "android.permission.SYSTEM_ALERT_WINDOW": {
        "level": "critical",
        "description": "Draw over other apps",
        "risk": "Can display fake overlays for phishing",
    },
    "android.permission.REQUEST_INSTALL_PACKAGES": {
        "level": "critical",
        "description": "Install apps",
        "risk": "Can install additional malware",
    },
    "android.permission.BIND_ACCESSIBILITY_SERVICE": {
        "level": "critical",
        "description": "Accessibility service",
        "risk": "Can monitor and control device actions",
    },
    "android.permission.BIND_DEVICE_ADMIN": {
        "level": "critical",
        "description": "Device administrator",
        "risk": "Can lock device, wipe data, change settings",
    },
    "android.permission.READ_PHONE_STATE": {
        "level": "medium",
        "description": "Read phone state",
        "risk": "Can access device identifiers",
    },
    "android.permission.PROCESS_OUTGOING_CALLS": {
        "level": "high",
        "description": "Monitor outgoing calls",
        "risk": "Can intercept or redirect calls",
    },
    "android.permission.RECEIVE_SMS": {
        "level": "critical",
        "description": "Receive SMS",
        "risk": "Can intercept incoming messages",
    },
}

# Suspicious permission combinations
SUSPICIOUS_COMBOS = [
    {
        "permissions": [
            "android.permission.INTERNET",
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
        ],
        "threat": "SMS Stealer",
        "description": "Can intercept and send SMS messages to remote server",
    },
    {
        "permissions": [
            "android.permission.INTERNET",
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
        ],
        "threat": "Spyware",
        "description": "Can record audio/video and send to remote server",
    },
    {
        "permissions": [
            "android.permission.INTERNET",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.READ_CONTACTS",
        ],
        "threat": "Stalkerware",
        "description": "Can track location and harvest contacts",
    },
    {
        "permissions": [
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.INTERNET",
        ],
        "threat": "Banking Trojan",
        "description": "Can display fake overlays to steal credentials",
    },
    {
        "permissions": [
            "android.permission.BIND_DEVICE_ADMIN",
            "android.permission.INTERNET",
        ],
        "threat": "Ransomware",
        "description": "Can lock device and demand ransom",
    },
    {
        "permissions": [
            "android.permission.REQUEST_INSTALL_PACKAGES",
            "android.permission.INTERNET",
        ],
        "threat": "Dropper",
        "description": "Can download and install additional malware",
    },
]

# Malware family classification based on CNN output patterns
MALWARE_FAMILIES = {
    "adware": {
        "min_conf": 0.5,
        "max_conf": 0.65,
        "description": "Displays unwanted advertisements",
    },
    "trojan": {
        "min_conf": 0.65,
        "max_conf": 0.8,
        "description": "Disguised malicious software",
    },
    "spyware": {
        "min_conf": 0.8,
        "max_conf": 0.9,
        "description": "Monitors user activity secretly",
    },
    "ransomware": {
        "min_conf": 0.9,
        "max_conf": 1.0,
        "description": "Encrypts files and demands payment",
    },
}

# ============================================================================
# LOAD ML MODEL
# ============================================================================

model = None


def load_model():
    """Load the CNN-BiLSTM v3 model from the model/ directory"""
    global model
    model_path = "model/"
    if os.path.exists(model_path):
        try:
            model = tf.keras.models.load_model(model_path, compile=False)
            print("✅ CNN-BiLSTM v3 model loaded successfully")
        except Exception as e:
            print(f"⚠️ Failed to load model: {e}")
            model = None
    else:
        print("⚠️ Model directory not found - running in demo mode")
        model = None


# ============================================================================
# CACHE MANAGEMENT
# ============================================================================


def load_cache():
    """Load scan cache from file"""
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as f:
            return json.load(f)
    return {}


def save_cache(cache):
    """Save scan cache to file"""
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)


def get_file_hash(file_path):
    """Calculate SHA256 hash of file"""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


# ============================================================================
# APK ANALYSIS FUNCTIONS
# ============================================================================


def extract_apk(apk_path, extract_dir):
    """Extract APK to temporary directory"""
    try:
        with zipfile.ZipFile(apk_path, "r") as zip_ref:
            zip_ref.extractall(extract_dir)
        return True
    except Exception as e:
        print(f"Error extracting APK: {e}")
        return False


def parse_android_manifest(extract_dir):
    """Parse AndroidManifest.xml to extract metadata and permissions using androguard"""
    manifest_path = os.path.join(extract_dir, "AndroidManifest.xml")

    result = {
        "package_name": None,
        "version_name": None,
        "version_code": None,
        "min_sdk": None,
        "target_sdk": None,
        "permissions": [],
        "activities": [],
        "services": [],
        "receivers": [],
        "uses_features": [],
    }

    if not os.path.exists(manifest_path):
        return result

    try:
        # Try using androguard for proper AXML parsing
        from androguard.core.axml import AXMLPrinter

        with open(manifest_path, "rb") as f:
            axml = AXMLPrinter(f.read())
            manifest_xml = axml.get_xml_obj()

        # Parse the XML tree
        root = ET.fromstring(manifest_xml)

        # Extract package name
        result["package_name"] = root.get("package")

        # Extract version info
        result["version_name"] = root.get(
            "{http://schemas.android.com/apk/res/android}versionName"
        )
        result["version_code"] = root.get(
            "{http://schemas.android.com/apk/res/android}versionCode"
        )

        # Extract SDK versions
        for uses_sdk in root.findall(".//uses-sdk"):
            result["min_sdk"] = uses_sdk.get(
                "{http://schemas.android.com/apk/res/android}minSdkVersion"
            )
            result["target_sdk"] = uses_sdk.get(
                "{http://schemas.android.com/apk/res/android}targetSdkVersion"
            )

        # Extract permissions
        for uses_permission in root.findall(".//uses-permission"):
            perm = uses_permission.get(
                "{http://schemas.android.com/apk/res/android}name"
            )
            if perm and perm not in result["permissions"]:
                result["permissions"].append(perm)

        print(
            f"✅ Extracted {len(result['permissions'])} permissions from {result['package_name']}"
        )

        return result

    except ImportError:
        print("⚠️ androguard not installed, falling back to basic string extraction")
        # Fallback to basic string extraction if androguard not available
        try:
            with open(manifest_path, "rb") as f:
                content = f.read()

            strings = extract_strings_from_binary(content)

            for s in strings:
                if s.startswith("android.permission."):
                    if s not in result["permissions"]:
                        result["permissions"].append(s)
                elif re.match(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$", s, re.I):
                    if len(s) > 5 and "." in s:
                        if result["package_name"] is None:
                            result["package_name"] = s

            return result
        except Exception as e:
            print(f"Error parsing manifest: {e}")
            return result

    except Exception as e:
        print(f"Error parsing manifest with androguard: {e}")
        return result


def extract_strings_from_binary(content):
    """Extract readable strings from binary content"""
    strings = []
    current = []

    for byte in content:
        if 32 <= byte < 127:  # Printable ASCII
            current.append(chr(byte))
        else:
            if len(current) >= 5:  # Minimum string length
                strings.append("".join(current))
            current = []

    if len(current) >= 5:
        strings.append("".join(current))

    return strings


def analyze_permissions(permissions):
    """Analyze permissions for risk assessment"""
    analysis = {
        "total_count": len(permissions),
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
        "unknown": [],
        "suspicious_combos": [],
        "risk_score": 0,
    }

    for perm in permissions:
        if perm in DANGEROUS_PERMISSIONS:
            perm_info = DANGEROUS_PERMISSIONS[perm]
            level = perm_info["level"]
            entry = {
                "permission": perm,
                "description": perm_info["description"],
                "risk": perm_info["risk"],
            }
            analysis[level].append(entry)
        else:
            # Check if it's a custom permission
            if perm.startswith("android.permission."):
                analysis["unknown"].append({"permission": perm})

    # Check for suspicious combinations
    for combo in SUSPICIOUS_COMBOS:
        if all(p in permissions for p in combo["permissions"]):
            analysis["suspicious_combos"].append(
                {
                    "threat": combo["threat"],
                    "description": combo["description"],
                    "permissions": combo["permissions"],
                }
            )

    # Calculate risk score (0-100)
    score = 0
    score += len(analysis["critical"]) * 20
    score += len(analysis["high"]) * 10
    score += len(analysis["medium"]) * 5
    score += len(analysis["low"]) * 1
    score += len(analysis["suspicious_combos"]) * 25

    analysis["risk_score"] = min(100, score)

    return analysis


def extract_certificate_info(extract_dir):
    """Extract certificate information from APK"""
    cert_info = {
        "signed": False,
        "issuer": None,
        "subject": None,
        "valid_from": None,
        "valid_to": None,
        "fingerprint_sha256": None,
        "debug_signed": False,
    }

    # Look for certificate files
    meta_inf = os.path.join(extract_dir, "META-INF")
    if not os.path.exists(meta_inf):
        return cert_info

    for filename in os.listdir(meta_inf):
        if filename.endswith(".RSA") or filename.endswith(".DSA"):
            cert_path = os.path.join(meta_inf, filename)
            cert_info["signed"] = True

            # Calculate fingerprint
            with open(cert_path, "rb") as f:
                cert_data = f.read()
                cert_info["fingerprint_sha256"] = hashlib.sha256(cert_data).hexdigest()

            # Check for debug signature
            strings = extract_strings_from_binary(cert_data)
            for s in strings:
                if "debug" in s.lower() or "android debug" in s.lower():
                    cert_info["debug_signed"] = True
                if "CN=" in s:
                    cert_info["subject"] = s

            break

    return cert_info


def apk_to_image(extracted_dir):
    """
    Converts the extracted APK files into a greyscale image array for model prediction.
    Returns: numpy array of shape (128, 128, 1)  — v3 model input size
    """
    files_to_include = [
        "classes.dex",
        "AndroidManifest.xml",
        "META-INF/CERT.RSA",
        "resources.arsc",
    ]

    binary_data = bytearray()
    for file_name in files_to_include:
        file_path = os.path.join(extracted_dir, file_name)
        if os.path.exists(file_path):
            with open(file_path, "rb") as f:
                binary_data.extend(f.read())

    data_array = np.frombuffer(binary_data, dtype=np.uint8)

    size = int(np.ceil(np.sqrt(len(data_array)))) if len(data_array) > 0 else 1
    padded_data = np.zeros(size * size, dtype=np.uint8)
    padded_data[: len(data_array)] = data_array

    image = padded_data.reshape((size, size))
    # CRITICAL: v3 model expects 128x128 input (not 256x256)
    resized_image = cv2.resize(image, (128, 128), interpolation=cv2.INTER_LINEAR)

    normalized_image = resized_image / 255.0
    final_image = np.expand_dims(normalized_image, axis=-1)

    return final_image


def classify_malware_family(confidence):
    """Classify malware family based on confidence score"""
    for family, ranges in MALWARE_FAMILIES.items():
        if ranges["min_conf"] <= confidence < ranges["max_conf"]:
            return {"family": family, "description": ranges["description"]}
    return {"family": "generic", "description": "Generic malicious software"}


def get_apk_metadata(apk_path, extract_dir):
    """Extract comprehensive APK metadata"""
    file_stats = os.stat(apk_path)

    metadata = {
        "file_name": os.path.basename(apk_path),
        "file_size": file_stats.st_size,
        "file_size_readable": format_file_size(file_stats.st_size),
        "sha256": get_file_hash(apk_path),
        "md5": hashlib.md5(open(apk_path, "rb").read()).hexdigest(),
        "scan_timestamp": datetime.now().isoformat(),
    }

    return metadata


def format_file_size(size):
    """Format file size in human-readable format"""
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} TB"


# ============================================================================
# VIRUSTOTAL INTEGRATION (Optional)
# ============================================================================


def check_virustotal(file_hash):
    """Check file hash against VirusTotal database"""
    if not VIRUSTOTAL_ENABLED:
        return None

    try:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}

        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            stats = (
                data.get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )
            return {
                "found": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "total_engines": sum(stats.values()),
                "detection_ratio": f"{stats.get('malicious', 0)}/{sum(stats.values())}",
            }
        elif response.status_code == 404:
            return {"found": False, "message": "Not found in VirusTotal database"}
        else:
            return {"error": f"API error: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# REPORT GENERATION
# ============================================================================


def generate_pdf_report(scan_result, output_path):
    """Generate PDF report of scan results"""
    if not REPORTLAB_AVAILABLE:
        return None

    try:
        c = canvas.Canvas(output_path, pagesize=letter)
        width, height = letter

        # Header
        c.setFillColor(HexColor("#1a1a2e"))
        c.rect(0, height - 80, width, 80, fill=1)

        c.setFillColor(HexColor("#00d9ff"))
        c.setFont("Helvetica-Bold", 24)
        c.drawString(50, height - 50, "AndroBlight Scan Report")

        c.setFillColor(HexColor("#ffffff"))
        c.setFont("Helvetica", 12)
        c.drawString(
            50,
            height - 70,
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        )

        y = height - 120

        # File info
        c.setFillColor(HexColor("#000000"))
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, y, "File Information")
        y -= 20

        c.setFont("Helvetica", 10)
        metadata = scan_result.get("metadata", {})
        c.drawString(60, y, f"File Name: {metadata.get('file_name', 'N/A')}")
        y -= 15
        c.drawString(60, y, f"Size: {metadata.get('file_size_readable', 'N/A')}")
        y -= 15
        c.drawString(60, y, f"SHA256: {metadata.get('sha256', 'N/A')[:32]}...")
        y -= 30

        # Detection result
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, y, "Detection Result")
        y -= 20

        ml = scan_result.get("ml_detection", {})
        label = ml.get("label", "Unknown")
        confidence = ml.get("confidence", 0)

        if label == "Malware":
            c.setFillColor(HexColor("#ff4444"))
        else:
            c.setFillColor(HexColor("#00cc00"))

        c.setFont("Helvetica-Bold", 16)
        c.drawString(60, y, f"{label} ({confidence:.1%})")
        y -= 30

        c.setFillColor(HexColor("#000000"))

        # Permission analysis
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, y, "Permission Analysis")
        y -= 20

        perm_analysis = scan_result.get("permission_analysis", {})
        c.setFont("Helvetica", 10)
        c.drawString(60, y, f"Total Permissions: {perm_analysis.get('total_count', 0)}")
        y -= 15
        c.drawString(60, y, f"Critical: {len(perm_analysis.get('critical', []))}")
        y -= 15
        c.drawString(60, y, f"High Risk: {len(perm_analysis.get('high', []))}")
        y -= 15
        c.drawString(60, y, f"Risk Score: {perm_analysis.get('risk_score', 0)}/100")

        c.save()
        return output_path
    except Exception as e:
        print(f"Error generating PDF: {e}")
        return None


# ============================================================================
# MOCK RESPONSE FOR DEMO MODE
# ============================================================================


def generate_mock_response(filename="demo.apk"):
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


# ============================================================================
# API ENDPOINTS
# ============================================================================


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint"""
    return jsonify(
        {
            "status": "ok",
            "version": "2.0.0",
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


@app.route("/predict", methods=["POST"])
def predict():
    """
    Scan APK file for malware

    Request: multipart/form-data with 'file' field
    Response: Comprehensive scan result with all analyses
    """
    try:
        if "file" not in request.files:
            return jsonify({"error": "No file provided", "status": "error"}), 400

        file = request.files["file"]
        if file.filename == "":
            return jsonify({"error": "No file selected", "status": "error"}), 400

        # Save uploaded file
        filename = secure_filename(file.filename)
        apk_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(apk_path)

        # Check cache
        file_hash = get_file_hash(apk_path)
        cache = load_cache()

        if file_hash in cache:
            # Return cached result
            os.remove(apk_path)
            cached = cache[file_hash]
            cached["cached"] = True
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
            # Demo mode - generate mock
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

        # VirusTotal check
        vt_result = check_virustotal(file_hash) if VIRUSTOTAL_ENABLED else None

        # Calculate overall score (0-100, higher is safer)
        overall_score = 100
        overall_score -= perm_analysis["risk_score"] * 0.3
        if ml_result["label"] == "Malware":
            overall_score -= ml_result["confidence"] * 40
        if cert_info.get("debug_signed"):
            overall_score -= 10
        if vt_result and vt_result.get("malicious", 0) > 0:
            overall_score -= vt_result["malicious"] * 2

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
            "overall_score": round(overall_score),
            "threat_level": threat_level,
            "recommendation": get_recommendation(
                threat_level, ml_result, perm_analysis
            ),
        }

        # Cache result
        cache[file_hash] = result
        save_cache(cache)

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


def get_recommendation(threat_level, ml_result, perm_analysis):
    """Generate recommendation based on analysis"""
    recommendations = []

    has_custom_rule_hit = any(
        c.get("custom_rule") for c in perm_analysis.get("suspicious_combos") or []
    )

    if threat_level == "critical":
        recommendations.append("⚠️ DO NOT INSTALL - High malware probability detected")
    elif threat_level == "high":
        recommendations.append(
            "⚠️ Exercise extreme caution - Multiple risk indicators found"
        )
    elif threat_level == "medium":
        recommendations.append("⚠️ Review permissions carefully before installing")
    else:
        if has_custom_rule_hit:
            recommendations.append(
                "⚠️ One of your threat rules matched — follow the rule-based recommendation below; do not install if that reflects your policy."
            )
        else:
            recommendations.append("✅ This application appears safe to install")

    if perm_analysis.get("suspicious_combos"):
        for combo in perm_analysis["suspicious_combos"]:
            if combo.get("custom_rule"):
                name = combo.get("rule_name") or combo.get("threat", "Custom rule")
                perms = combo.get("permissions") or []
                pattern = ", ".join(perms)
                if len(pattern) > 160:
                    pattern = pattern[:157] + "..."
                recommendations.append(
                    f'🚨 According to your threat rule "{name}": do not download or install this app — it matches permissions you flagged ({pattern}).'
                )
            else:
                recommendations.append(f"🚨 {combo['threat']}: {combo['description']}")

    if len(perm_analysis.get("critical", [])) > 0:
        recommendations.append(
            f"🔴 {len(perm_analysis['critical'])} critical permissions requested"
        )

    return recommendations


@app.route("/predict-playstore", methods=["POST"])
def predict_playstore():
    """
    Scan Play Store app by URL or package name

    Request JSON: {"url": "..."} or {"package": "com.example.app"}
    Response: Same as /predict endpoint
    """
    try:
        data = request.get_json()

        if not data:
            return jsonify({"error": "No JSON data provided", "status": "error"}), 400

        url = data.get("url")
        package = data.get("package")

        if not url and not package:
            return (
                jsonify(
                    {"error": "Provide either url or package name", "status": "error"}
                ),
                400,
            )

        # Extract package name from URL if needed
        if url:
            match = re.search(r"id=([a-zA-Z0-9_.]+)", url)
            if match:
                package = match.group(1)
            else:
                return (
                    jsonify({"error": "Invalid Play Store URL", "status": "error"}),
                    400,
                )

        # For now, return a mock response
        # In production, you would:
        # 1. Use APKPure/APKMirror API to download APK
        # 2. Run the same analysis as /predict

        mock_res = generate_mock_response(f"{package}.apk")
        mock_res["metadata"]["package_name"] = package

        # Save to cache so PDF can find it
        file_hash = mock_res["metadata"]["sha256"]
        cache = load_cache()
        cache[file_hash] = mock_res
        save_cache(cache)

        return jsonify(
            {
                "status": "success",
                "demo_mode": True,
                "message": "Play Store scanning requires APK download integration",
                "package_name": package,
                **mock_res,
            }
        )

    except Exception as e:
        return jsonify({"error": str(e), "status": "error"}), 500


@app.route("/batch-predict", methods=["POST"])
def batch_predict():
    """
    Scan multiple APK files in one request

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
                # For batch, we return simplified mock results
                # In production, process each file
                mock_res = generate_mock_response(file.filename)
                results.append({"filename": file.filename, **mock_res})

                # Save to cache so PDF can find it
                file_hash = mock_res["metadata"]["sha256"]
                cache = load_cache()
                cache[file_hash] = mock_res
                save_cache(cache)

        return jsonify(
            {"status": "success", "total_files": len(results), "results": results}
        )

    except Exception as e:
        return jsonify({"error": str(e), "status": "error"}), 500


@app.route("/report/<file_hash>", methods=["GET"])
def get_report(file_hash):
    """
    Generate PDF report for a cached scan

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


@app.route("/stats", methods=["GET"])
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


@app.route("/clear-cache", methods=["POST"])
def clear_cache():
    """Clear scan cache (admin endpoint)"""
    try:
        if os.path.exists(CACHE_FILE):
            os.remove(CACHE_FILE)
        return jsonify({"status": "success", "message": "Cache cleared"})
    except Exception as e:
        return jsonify({"error": str(e), "status": "error"}), 500


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    # Create necessary directories
    for folder in [UPLOAD_FOLDER, TEMP_EXTRACT_FOLDER, REPORTS_FOLDER]:
        os.makedirs(folder, exist_ok=True)

    # Load ML model
    load_model()

    print(
        """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║   █████╗ ███╗   ██╗██████╗ ██████╗  ██████╗ ██████╗ ██╗      ║
    ║  ██╔══██╗████╗  ██║██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██║      ║
    ║  ███████║██╔██╗ ██║██║  ██║██████╔╝██║   ██║██████╔╝██║      ║
    ║  ██╔══██║██║╚██╗██║██║  ██║██╔══██╗██║   ██║██╔══██╗██║      ║
    ║  ██║  ██║██║ ╚████║██████╔╝██║  ██║╚██████╔╝██████╔╝███████╗ ║
    ║  ╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝ ║
    ║                                                               ║
    ║               Enhanced API Server v2.0                        ║
    ╚═══════════════════════════════════════════════════════════════╝
    
    🚀 Server starting on http://0.0.0.0:5000
    
    📋 Available Endpoints:
       GET  /health           - Health check & feature list
       POST /predict          - Scan APK file (full analysis)
       POST /predict-playstore - Scan Play Store app
       POST /batch-predict    - Batch scan multiple APKs
       GET  /report/<hash>    - Download PDF report
       GET  /stats            - Get scan statistics
       POST /clear-cache      - Clear scan cache
    
    ⚙️  Configuration:
       • Model loaded: """
        + ("✅ Yes" if model else "❌ No (Demo Mode)")
        + """
       • VirusTotal:   """
        + ("✅ Enabled" if VIRUSTOTAL_ENABLED else "❌ Disabled")
        + """
       • Max file size: 100 MB
       • Cache enabled: ✅ Yes
    """
    )

    app.run(debug=True, host="0.0.0.0", port=5000)
