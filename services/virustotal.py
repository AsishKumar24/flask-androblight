"""
VirusTotal Integration Service
================================
Checks file hashes against VirusTotal's malware database.
"""

import requests

from config import VIRUSTOTAL_API_KEY, VIRUSTOTAL_ENABLED


def check_virustotal(file_hash):
    """Check file hash against VirusTotal database. Returns None if disabled."""
    if not VIRUSTOTAL_ENABLED:
        return None
    
    try:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            mal = stats.get('malicious', 0)
            return {
                'engine': 'VirusTotal',
                'found': True,
                'malicious': mal,
                'suspicious': stats.get('suspicious', 0),
                'undetected': stats.get('undetected', 0),
                'total_engines': sum(stats.values()),
                'detection_ratio': f"{mal}/{sum(stats.values()) or 1}",
            }
        elif response.status_code == 404:
            return {
                'engine': 'VirusTotal',
                'found': False,
                'message': 'Not found in VirusTotal database',
            }
        else:
            return {'engine': 'VirusTotal', 'error': f'API error: {response.status_code}'}
    except Exception as e:
        return {'engine': 'VirusTotal', 'error': str(e)}
