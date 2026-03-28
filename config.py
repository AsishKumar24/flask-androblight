"""
AndroBlight Configuration
=========================
All configuration constants, environment variables, and app settings.
"""
from dotenv import load_dotenv
import os
load_dotenv()
# Folder paths
UPLOAD_FOLDER = "uploads"
TEMP_EXTRACT_FOLDER = "temp_extract"
REPORTS_FOLDER = "reports"
CACHE_FILE = "scan_cache.json"
MODEL_PATH = os.environ.get("MODEL_PATH", "model/")

# Database — absolute path so the .db always lands in the project root
# regardless of the current working directory when Flask is launched.
_BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE_URI = "sqlite:///" + os.path.join(_BASE_DIR, "androblight.db")

# JWT Secret — override via environment variable in production
JWT_SECRET_KEY = os.environ.get(
    "JWT_SECRET_KEY", "androblight-secret-key-change-in-production"
)

# VirusTotal API (optional - set your API key)
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
VIRUSTOTAL_ENABLED = bool(VIRUSTOTAL_API_KEY)

# Hybrid Analysis API (optional - https://www.hybrid-analysis.com)
HYBRID_ANALYSIS_API_KEY = os.environ.get("HYBRID_ANALYSIS_API_KEY", "")
HYBRID_ANALYSIS_ENABLED = bool(HYBRID_ANALYSIS_API_KEY)

# MetaDefender / OPSWAT API (optional - https://metadefender.opswat.com)
METADEFENDER_API_KEY = os.environ.get("METADEFENDER_API_KEY", "")
METADEFENDER_ENABLED = bool(METADEFENDER_API_KEY)

# Max file upload size (100 MB)
MAX_CONTENT_LENGTH = 100 * 1024 * 1024
