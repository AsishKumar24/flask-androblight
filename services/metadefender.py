"""
MetaDefender / OPSWAT Integration Service
==========================================
Checks file hashes against MetaDefender's multi-engine scanner.
https://metadefender.opswat.com
"""

import requests

from config import METADEFENDER_API_KEY, METADEFENDER_ENABLED


def check_metadefender(file_hash):
    """
    Check file hash against MetaDefender (OPSWAT) database.
    Returns None if disabled or API key not set.
    """
    if not METADEFENDER_ENABLED:
        return None

    try:
        url = f"https://api.metadefender.com/v4/hash/{file_hash}"
        headers = {
            "apikey": METADEFENDER_API_KEY,
        }

        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()

            # MetaDefender returns scan_results with per-engine verdicts
            scan_results = data.get("scan_results", {})
            scan_all = scan_results.get("scan_details", {})

            total = len(scan_all)
            positives = sum(
                1
                for eng in scan_all.values()
                if eng.get("threat_found") and eng["threat_found"] != ""
            )

            return {
                "engine": "MetaDefender",
                "found": True,
                "positives": positives,
                "total": total,
                "detection_ratio": f"{positives}/{total}",
                "malicious": positives > 0,
                "scan_all": {
                    name: details.get("threat_found", "")
                    for name, details in scan_all.items()
                    if details.get("threat_found")
                },
            }
        elif response.status_code == 404:
            return {"engine": "MetaDefender", "found": False, "message": "Not found"}
        else:
            return {
                "engine": "MetaDefender",
                "error": f"API error: {response.status_code}",
            }

    except Exception as e:
        return {"engine": "MetaDefender", "error": str(e)}
