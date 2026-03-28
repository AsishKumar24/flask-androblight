# AndroBlight — Implementation Plan

> **Reference:** [PRD.md](PRD.md) | [Detailed Feature.md](Detailed%20Feature.md) | [API List.md](API%20List.md)  
> **Total Chunks:** 6 | **Total Features:** 9

> **IMPORTANT:** These chunks are ordered so that each chunk's dependencies are satisfied by previous chunks. **Do not skip chunks or reorder them.** Each chunk is designed to be completable independently and testable in isolation.

---

## Chunk 1: Cleanup, Model Migration & Backend Modularization

**Goal:** Remove dead code, migrate to v3 model, split monolithic backend into modules  
**No new features — just restructuring + model fix**

### Backend Tasks:

```
CLEANUP:
1.1  DELETE main.py (entire file — it's dead code)
1.2  DELETE cnn-lstm_detection_model.h5 (old v1 model, replaced by v3)
1.3  REMOVE dead imports from app_enhanced.py:
     - Line 29: duplicate `import os`
     - Line 38: unused `from functools import lru_cache`  
     - Line 40: unused `from io import BytesIO`
     - Line 300: duplicate `import xml.etree.ElementTree as ET`

MODEL MIGRATION (v1 → v3):
1.4  COPY model directory: cp ~/Downloads/cnn_bilstm_v3_final/ → androblight-backend/model/
     The directory contains: config.json + metadata.json
     The weights file model.weights.h5 is already in androblight-backend/
     Move it into: androblight-backend/model/model.weights.h5
1.5  UPDATE load_model() in app_enhanced.py:
     - OLD: model = tf.keras.models.load_model('cnn-lstm_detection_model.h5')
     - NEW: model = tf.keras.models.load_model('model/')  
       (Keras 3 loads from directory: reads config.json for architecture + model.weights.h5 for weights)
1.6  FIX apk_to_image() — CRITICAL BUG:
     - OLD (line 479): resized_image = cv2.resize(image, (256, 256))
     - NEW: resized_image = cv2.resize(image, (128, 128))
     - The v3 model input shape is (128, 128, 1), NOT (256, 256, 1)

MODULARIZATION:
1.7  SPLIT app_enhanced.py into modules:
     - config.py → configuration constants, env vars
     - models/permissions_db.py → DANGEROUS_PERMISSIONS, SUSPICIOUS_COMBOS, MALWARE_FAMILIES
     - services/scanner.py → apk_to_image(), extract_apk(), classify_malware_family()
     - services/permissions.py → analyze_permissions(), parse_android_manifest()
     - services/certificate.py → extract_certificate_info()
     - services/virustotal.py → check_virustotal()
     - services/report.py → generate_pdf_report()
     - routes/scan.py → /predict, /predict-playstore, /batch-predict
     - routes/admin.py → /health, /stats, /clear-cache, /report/<hash>
     - app.py → Flask app factory, route registration, startup
1.8  VERIFY all endpoints still work after split + model migration
```

### Frontend Tasks:
```
None — mobile codebase is already clean and modular
```

### Test:
- Run `python app.py` → all endpoints respond correctly
- Run Flutter app → connects and scans work as before

---

## Chunk 2: Database + User Authentication (Prereq for Features 3, 5, 9)

**Goal:** Replace JSON file cache with SQLite/PostgreSQL, add user accounts

### Backend Tasks:
```
2.1  ADD dependencies: flask-sqlalchemy, flask-migrate, flask-jwt-extended, bcrypt
2.2  CREATE models/database.py:
     - User model: id, email, password_hash, created_at
     - ScanRecord model: id, user_id, file_hash, result_json, created_at, updated_at
2.3  CREATE auth/jwt_handler.py:
     - JWT token creation, validation, refresh
2.4  CREATE routes/auth.py:
     - POST /auth/register → create user, return JWT
     - POST /auth/login → verify password, return JWT
     - POST /auth/refresh → refresh expired JWT
2.5  ADD middleware: @jwt_required decorator for protected routes
2.6  MIGRATE scan_cache.json data to database
2.7  UPDATE routes/scan.py:
     - /predict now saves to database (with user_id if authenticated)
     - /predict still works without auth (anonymous scans)
```

### Frontend Tasks:
```
2.8  CREATE lib/services/auth_service.dart:
     - login(), register(), refreshToken(), logout()
     - Token storage in Hive secure box
2.9  CREATE lib/providers/auth_provider.dart:
     - State: authenticated/unauthenticated/loading
2.10 CREATE lib/screens/login_screen.dart
2.11 CREATE lib/screens/register_screen.dart
2.12 UPDATE lib/services/api_service.dart:
     - Add JWT Authorization header interceptor
2.13 UPDATE lib/core/constants.dart:
     - Add auth endpoints
2.14 UPDATE lib/main.dart:
     - Add AuthProvider to MultiProvider
     - Splash screen checks auth state
```

### Test:
- Register → Login → Scan → Verify scan saved in DB
- Logout → Login on "another device" (simulator) → History syncs

---

## Chunk 3: Cloud Sync + Advanced History (Features 3, 5)

**Goal:** Sync scan history across devices, add filtering/search

### Backend Tasks:
```
3.1  CREATE routes/sync.py:
     - GET /sync/history?since=<iso_timestamp> → return records newer than timestamp
     - POST /sync/history → receive batch of local scan records
3.2  CREATE routes/history.py:
     - GET /history?search=&filter=&sort=&page= → paginated filtered history
3.3  UPDATE ScanRecord model: add search index on file_name, package_name
```

### Frontend Tasks:
```
3.4  UPDATE lib/repositories/history_repository.dart:
     - Add syncWithCloud() method
     - Merge local + remote records
3.5  UPDATE lib/screens/history_screen.dart:
     - Add search bar at top
     - Add filter chips: All | Malware | Benign | APK | Play Store
     - Add sort dropdown: Newest | Oldest | Highest Risk
3.6  UPDATE lib/providers/history_provider.dart:
     - Add searchQuery, selectedFilter, sortOrder state
     - Add filteredHistory getter
3.7  UPDATE lib/core/constants.dart:
     - Add sync and history endpoints
```

### Test:
- Search for "whatsapp" → shows only matching scans
- Filter "Malware" → shows only malware results
- Install app on second device → login → history appears

---

## Chunk 4: Quick-Win Features (Features 1, 4, 7, 8)

**Goal:** Four independent features that require minimal architecture changes

### 4A: Root Detection (Feature 8)
```
BACKEND:
4A.1 UPDATE /predict to accept optional device_info field
4A.2 Factor is_rooted into risk score calculation

FRONTEND:
4A.3 CREATE lib/services/device_security_service.dart
     - checkRootStatus() via MethodChannel to Android native
4A.4 CREATE android/.../DeviceSecurityPlugin.kt (native Android code)
     - Check for su, Magisk, SuperSU, build tags
4A.5 UPDATE HomeScreen — show root status badge
4A.6 UPDATE ScanProvider — attach device_info to scan requests
```

### 4B: Multi-Language i18n (Feature 4)
```
BACKEND:
4B.1 CREATE i18n/en.json, i18n/hi.json
4B.2 UPDATE get_recommendation() to accept locale and return translated strings

FRONTEND:
4B.3 CREATE lib/l10n/app_en.arb, lib/l10n/app_hi.arb
4B.4 UPDATE pubspec.yaml — enable generate: true
4B.5 UPDATE MaterialApp — add localizationsDelegates
4B.6 REPLACE hardcoded strings across all screens with AppLocalizations
```

### 4C: Additional AV APIs (Feature 7)
```
BACKEND:
4C.1 CREATE services/hybrid_analysis.py — check_hybrid_analysis(hash)
4C.2 CREATE services/metadefender.py — check_metadefender(hash)
4C.3 UPDATE routes/scan.py — call all enabled engines, merge results
4C.4 ADD multi_engine_results to scan response JSON

FRONTEND:
4C.5 UPDATE ScanResult model — add multiEngineResults field
4C.6 UPDATE ResultScreen — add "Multi-Engine Verdicts" expandable section
```

### 4D: Installed App Monitoring (Feature 1)
```
BACKEND:
4D.1 CREATE routes/monitor.py
     - POST /monitor/installed-apps → check packages against DB

FRONTEND:
4D.2 ADD dependency: device_apps (or installed_apps)
4D.3 CREATE lib/screens/installed_apps_screen.dart
4D.4 CREATE lib/providers/monitor_provider.dart
4D.5 UPDATE HomeScreen — add third action card "Scan My Phone"
4D.6 UPDATE lib/core/constants.dart — add monitor endpoint
```

### Test each sub-chunk independently:
- 4A: Root detection shows status on HomeScreen
- 4B: Switch phone language → app strings change
- 4C: Scan shows results from multiple engines
- 4D: "Scan My Phone" lists all installed apps with risk levels

---

## Chunk 5: Custom Rules & Periodic Rescanning (Features 6, 2)

**Goal:** User-defined threat rules + automated background rescanning

### Backend Tasks:
```
5.1  CREATE models/threat_rule.py — ThreatRule database model
5.2  CREATE routes/rules.py — CRUD endpoints for rules
5.3  UPDATE services/permissions.py — load custom rules during analysis
5.4  CREATE services/scheduler.py — APScheduler background job
5.5  CREATE services/rescanner.py — rescan_cached_hashes() function
5.6  CREATE routes/rescan.py — GET /rescan/updates?since=<timestamp>
```

### Frontend Tasks:
```
5.7  CREATE lib/screens/rules_screen.dart — list/create/edit rules
5.8  CREATE lib/providers/rules_provider.dart
5.9  UPDATE HistoryProvider — add checkForUpdates() polling
5.10 UPDATE ScanCard widget — show "verdict changed" badge
```

### Test:
- Create rule: "SMS + INTERNET = Suspicious"
- Scan APK with those permissions → custom rule flagged
- Wait for rescan cycle → check for updated verdicts

---

## Chunk 6: Two-Factor Authentication (Feature 9)

**Goal:** TOTP-based 2FA for enterprise security

### Backend Tasks:
```
6.1  ADD dependencies: pyotp, qrcode, Pillow
6.2  UPDATE User model — add totp_secret, is_2fa_enabled, backup_codes
6.3  CREATE routes/two_factor.py:
     - POST /auth/2fa/setup → generate TOTP secret, return QR URI
     - POST /auth/2fa/verify → verify TOTP during login
     - POST /auth/2fa/disable → remove TOTP
6.4  UPDATE routes/auth.py login flow:
     - If 2FA enabled, return requires_2fa: true
     - Require /auth/2fa/verify before issuing full JWT
```

### Frontend Tasks:
```
6.5  CREATE lib/screens/two_factor_setup_screen.dart — QR code display
6.6  CREATE lib/screens/two_factor_verify_screen.dart — 6-digit input
6.7  UPDATE lib/providers/auth_provider.dart — 2FA state
6.8  UPDATE LoginScreen — redirect to 2FA verify if required
```

---

## Chunk Summary

| Chunk | Features Covered | Backend | Frontend | Effort |
|---|---|---|---|---|
| 1 | None (cleanup) | Modularize + fix model | None | 🟢 Medium |
| 2 | Prereq for 3,5,9 | DB + Auth | Login/Register | 🔴 High |
| 3 | 3, 5 | Sync + History API | Search/Filter UI | 🟡 Medium |
| 4 | 1, 4, 7, 8 | 4 small additions | 4 small additions | 🟢 Medium |
| 5 | 6, 2 | Rules CRUD + Scheduler | Rules screen + badges | 🟡 Medium |
| 6 | 9 | TOTP endpoints | 2FA screens | 🟡 Medium |

> **For AI-assisted implementation:** Each chunk above is self-contained with exact file paths, function names, and endpoint specs. Feed one chunk at a time to avoid hallucination.
