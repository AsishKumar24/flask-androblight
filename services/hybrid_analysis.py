"""
Hybrid Analysis Integration Service
=====================================
Checks file hashes against Hybrid Analysis malware database.
https://www.hybrid-analysis.com
"""

import requests

from config import HYBRID_ANALYSIS_API_KEY, HYBRID_ANALYSIS_ENABLED


def check_hybrid_analysis(file_hash):
    """
    Check file hash against Hybrid Analysis database.
    Returns None if disabled or API key not set.
    """
    if not HYBRID_ANALYSIS_ENABLED:
        return None

    try:
        url = "https://www.hybrid-analysis.com/api/v2/search/hash"
        headers = {
            "api-key": HYBRID_ANALYSIS_API_KEY,
            "User-Agent": "Falcon Sandbox",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        payload = {"hash": file_hash}

        response = requests.post(url, headers=headers, data=payload, timeout=10)

        if response.status_code == 200:
            data = response.json()
            if not data:
                return {"found": False, "message": "Not found in Hybrid Analysis"}

            # Pick the most recent / highest-verdict report
            report = data[0] if isinstance(data, list) else data
            verdict = report.get("verdict", "no specific threat")
            threat_score = report.get("threat_score", 0)
            threat_level = report.get("threat_level", "")

            return {
                "engine": "Hybrid Analysis",
                "found": True,
                "verdict": verdict,
                "threat_score": threat_score,
                "threat_level": threat_level,
                "malicious": verdict in ("malicious", "whitelisted")
                and verdict != "whitelisted",
            }
        elif response.status_code == 404:
            return {"engine": "Hybrid Analysis", "found": False, "message": "Not found"}
        else:
            return {
                "engine": "Hybrid Analysis",
                "error": f"API error: {response.status_code}",
            }

    except Exception as e:
        return {"engine": "Hybrid Analysis", "error": str(e)}
