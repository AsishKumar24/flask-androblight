"""
Scanner Service
===============
Handles APK extraction, binary-to-image conversion for the CNN-BiLSTM model,
and malware family classification.
"""

import os
import hashlib
import zipfile
import json
import numpy as np
import cv2

from config import CACHE_FILE
from models.permissions_db import MALWARE_FAMILIES


def extract_apk(apk_path, extract_dir):
    """Extract APK (ZIP archive) to a temporary directory"""
    try:
        with zipfile.ZipFile(apk_path, "r") as zip_ref:
            zip_ref.extractall(extract_dir)
        return True
    except Exception as e:
        print(f"Error extracting APK: {e}")
        return False


def apk_to_image(extracted_dir):
    """
    Converts the extracted APK files into a greyscale image array for model prediction.

    Process:
    1. Read raw bytes from key APK files (classes.dex, manifest, cert, resources)
    2. Concatenate into a single byte array
    3. Reshape into a square greyscale image
    4. Resize to 128x128 (CNN-BiLSTM v3 input size)
    5. Normalize to [0, 1] range

    Returns: numpy array of shape (128, 128, 1)
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
    """Classify malware family based on model confidence score"""
    for family, ranges in MALWARE_FAMILIES.items():
        if ranges["min_conf"] <= confidence < ranges["max_conf"]:
            return {"family": family, "description": ranges["description"]}
    return {"family": "generic", "description": "Generic malicious software"}


def get_file_hash(file_path):
    """Calculate SHA-256 hash of a file"""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def _compute_md5(file_path):
    """Calculate MD5 hash of a file using a context manager"""
    with open(file_path, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()


def get_apk_metadata(apk_path, extract_dir):
    """Extract comprehensive APK metadata"""
    file_stats = os.stat(apk_path)

    metadata = {
        "file_name": os.path.basename(apk_path),
        "file_size": file_stats.st_size,
        "file_size_readable": format_file_size(file_stats.st_size),
        "sha256": get_file_hash(apk_path),
        "md5": _compute_md5(apk_path),
        "scan_timestamp": __import__("datetime").datetime.now().isoformat(),
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
# CACHE MANAGEMENT (will be replaced by database in Chunk 2)
# ============================================================================


def load_cache():
    """Load scan cache from JSON file"""
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as f:
            return json.load(f)
    return {}


def save_cache(cache):
    """Save scan cache to JSON file"""
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)
