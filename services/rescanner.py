"""
Periodic Rescanner
===================
Background job that re-checks previously scanned file hashes against VirusTotal.
If the verdict has changed since the original scan, the ScanRecord is updated
and verdict_changed is set to True so clients can notify the user.
"""

import json
from datetime import datetime, timezone

from services.scanner import load_cache, save_cache
from services.virustotal import check_virustotal
from models.database import db, ScanRecord
import config as _cfg


def rescan_cached_hashes():
    """
    Iterate all hashes in scan_cache.json, re-query VirusTotal,
    and update ScanRecord rows whose verdict has changed.

    Returns:
        dict: {'checked': int, 'changed': int, 'errors': int}
    """
    if not _cfg.VIRUSTOTAL_ENABLED:
        print("[Rescanner] VirusTotal disabled — skipping rescan")
        return {"checked": 0, "changed": 0, "errors": 0}

    cache = load_cache()
    stats = {"checked": 0, "changed": 0, "errors": 0}

    for file_hash, cached_entry in list(cache.items()):
        stats["checked"] += 1
        old_malicious = cached_entry.get("malicious", False)
        old_label = "Malware" if old_malicious else "Benign"

        try:
            vt_result = check_virustotal(file_hash)

            if vt_result is None:
                # Hash not found in VT yet — skip
                continue

            new_malicious = vt_result.get("malicious", False)
            new_label = "Malware" if new_malicious else "Benign"

            if new_label != old_label:
                # Verdict changed — update the cache entry
                cached_entry["malicious"] = new_malicious
                cached_entry["verdict_changed"] = True
                cached_entry["verdict_changed_at"] = datetime.now(
                    timezone.utc
                ).isoformat()

                # Update all matching ScanRecord rows in the database
                records = ScanRecord.query.filter_by(file_hash=file_hash).all()
                now = datetime.now(timezone.utc)
                for record in records:
                    if record.label != new_label:
                        record.label = new_label
                        record.verdict_changed = True
                        record.verdict_changed_at = now
                        record.updated_at = now

                if records:
                    db.session.commit()
                    stats["changed"] += 1
                    print(
                        f"[Rescanner] Hash {file_hash[:16]}… verdict changed: "
                        f"{old_label} → {new_label}"
                    )

        except Exception as exc:
            stats["errors"] += 1
            print(f"[Rescanner] Error checking hash {file_hash[:16]}…: {exc}")

    save_cache(cache)
    print(
        f"[Rescanner] Done. checked={stats['checked']} "
        f"changed={stats['changed']} errors={stats['errors']}"
    )
    return stats
