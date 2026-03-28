# AndroBlight — Detailed Feature Specifications

> **Reference:** [PRD.md](PRD.md) | [plan.md](plan.md) | [API List.md](API%20List.md)  
> **Total Features:** 9 (excludes Behavioral Analysis & Network Monitoring)

Each feature is documented with:
- **What it is** (plain English, no jargon)
- **Why it matters**
- **Where the code changes live** (backend file, frontend file, or both)
- **API endpoint** (exact route, request, response)
- **Dependencies** (what must be built first)

---

## Feature 1: Real-time Installed App Monitoring

> **COMMENT: This feature lets the mobile app send the list of all apps installed on the user's phone to the backend. The backend checks each package name against known malware databases and returns which ones are suspicious. Think of it as "scan my entire phone" instead of scanning one APK at a time.**

**What it does:**
- The Flutter app collects all installed package names from the Android device
- Sends the list to the backend in one API call
- Backend checks each package against its malware database + VirusTotal
- Returns a risk-rated list of installed apps

**Backend changes:**
- New endpoint: `POST /monitor/installed-apps`
- Request body: `{"packages": ["com.whatsapp", "com.facebook.orca", ...]}`
- Response: array of `{package_name, risk_level, reason}`

**Frontend changes:**
- New Flutter package: `installed_apps` or `device_apps` to list installed apps
- New screen: `InstalledAppsScreen` — shows list with risk indicators
- New provider: `MonitorProvider`
- Add to HomeScreen as a third action card

**Dependencies:** None — can be built independently  
**Estimated effort:** Medium  
**Implementation chunk:** [Chunk 4D](plan.md)

---

## Feature 2: Automated Periodic Rescanning

> **COMMENT: Instead of the user manually re-scanning apps, the system automatically re-checks previously scanned apps on a schedule (e.g., daily). If a previously-safe app is now flagged as malware (because threat databases updated), the user gets notified.**

**What it does:**
- Backend runs a background job every 24 hours
- Re-checks all cached scan hashes against VirusTotal for updated verdicts
- Marks any changed results
- Mobile app polls for updates or receives push notifications

**Backend changes:**
- Add `APScheduler` to run periodic jobs
- New endpoint: `GET /rescan/updates?since=<timestamp>` — returns scans whose verdict changed
- Background worker function `rescan_cached_hashes()`

**Frontend changes:**
- `HistoryProvider` gains a `checkForUpdates()` method
- History items show a "verdict changed" badge if the rescan found something new
- Optional: push notification integration

**Dependencies:** Requires a real database (Feature 3's prerequisite) to store persistent scan history across restarts  
**Estimated effort:** Medium  
**Implementation chunk:** [Chunk 5](plan.md)

---

## Feature 3: Cloud Sync for Scan History

> **COMMENT: Currently, scan history lives only on the phone (Hive local storage). If the user switches phones or reinstalls the app, their history is gone. This feature adds user accounts and stores scan history in a cloud database so it syncs across devices.**

**What it does:**
- User creates an account (email + password) or logs in
- Scan history is saved both locally (Hive) and remotely (cloud database)
- When the user logs in on a new device, history syncs down
- Conflict resolution: server timestamp wins

**Backend changes (MAJOR):**
- Add PostgreSQL (or SQLite for dev) with SQLAlchemy ORM
- New models: `User`, `ScanRecord`
- New auth endpoints: `POST /auth/register`, `POST /auth/login`, `POST /auth/refresh`
- JWT token-based authentication
- New sync endpoints: `GET /sync/history?since=<timestamp>`, `POST /sync/history`
- Replace `scan_cache.json` with database storage

**Frontend changes:**
- New screens: `LoginScreen`, `RegisterScreen`, `ProfileScreen`
- New service: `AuthService` — handles JWT token storage, refresh
- `ApiService` updated to attach JWT `Authorization` header to all requests
- `StorageService` updated to store auth tokens securely
- `HistoryRepository` updated to sync with cloud
- New provider: `AuthProvider`

**Dependencies:** None — but this is a **prerequisite** for Features 2, 5, 9  
**Estimated effort:** High  
**Implementation chunk:** [Chunk 2](plan.md) + [Chunk 3](plan.md)

---

## Feature 4: Multi-Language Support (i18n)

> **COMMENT: Make the app available in multiple languages. The backend sends message keys instead of hardcoded English strings, and the mobile app translates them based on the user's device language.**

**What it does:**
- Backend returns translatable keys (e.g., `"recommendation_do_not_install"`) alongside or instead of hardcoded English text
- Mobile app uses Flutter's localization system to display translated strings
- Initially support: English, Hindi

**Backend changes:**
- Add `Accept-Language` header support
- Replace hardcoded recommendation strings with language-aware function
- Create `i18n/` folder with JSON translation files
- Modify `get_recommendation()` to accept locale parameter

**Frontend changes:**
- Add `flutter_localizations` and `intl` to pubspec.yaml (intl already present)
- Create `lib/l10n/` folder with ARB files (`app_en.arb`, `app_hi.arb`)
- Generate localization delegates
- Wrap MaterialApp with `localizationsDelegates`
- Replace all hardcoded UI strings with `AppLocalizations.of(context).xxx`

**Dependencies:** None — can be built independently  
**Estimated effort:** Low-Medium  
**Implementation chunk:** [Chunk 4B](plan.md)

---

## Feature 5: Advanced Filtering & Search in History

> **COMMENT: Currently the history screen just shows a flat list sorted by date. This feature adds search (by filename), filters (by date range, malware/benign, scan type), and sort options. The filtering happens both locally on saved data and via the server for cloud-synced data.**

**What it does:**
- Search bar on HistoryScreen to filter by app name / package name
- Filter chips: "All", "Malware", "Benign", "APK Scan", "Play Store"
- Date range picker
- Sort by: date (newest/oldest), risk score, confidence

**Backend changes (for cloud-synced history):**
- New endpoint: `GET /history?search=<term>&filter=<malware|benign>&sort=<date|risk>&from=<date>&to=<date>&page=<n>`
- Pagination support (20 items per page)

**Frontend changes:**
- `HistoryScreen` — add search bar, filter chips, sort dropdown
- `HistoryProvider` — add filtering/search/sort logic
- `HistoryRepository` — add filtered query methods for both local (Hive) and remote

**Dependencies:** Feature 3 (for cloud filtering). Local filtering can be done independently.  
**Estimated effort:** Medium  
**Implementation chunk:** [Chunk 3](plan.md)

---

## Feature 6: Custom Threat Rule Definitions

> **COMMENT: Currently, suspicious permission combinations are hardcoded in `app_enhanced.py` (lines 175–206). This feature lets admins/users define their own rules like "flag any app that requests CAMERA + INTERNET + RECORD_AUDIO". Rules are stored as JSON and can be managed via API.**

**What it does:**
- Admin can create/edit/delete custom rules via API
- Rules define: permission combinations → threat label + description
- Rules run alongside the hardcoded ones during every scan
- Mobile app shows which custom rules triggered in the result

**Backend changes:**
- New model: `ThreatRule` — stored in database or JSON file
- New endpoints: `GET /rules`, `POST /rules`, `PUT /rules/<id>`, `DELETE /rules/<id>`
- Modify `analyze_permissions()` to load and evaluate custom rules alongside built-in `SUSPICIOUS_COMBOS`

**Frontend changes:**
- New screen: `RulesScreen` (admin only) — list, create, edit rules
- `ResultScreen` — show which custom rules matched
- New provider: `RulesProvider`

**Dependencies:** Feature 3 (database) recommended but not required (can use JSON file)  
**Estimated effort:** Medium  
**Implementation chunk:** [Chunk 5](plan.md)

---

## Feature 7: Integration with Additional Antivirus APIs

> **COMMENT: Currently the backend only checks VirusTotal. This feature adds more antivirus API sources (Hybrid Analysis, MetaDefender) using the same pattern — send the hash, get a verdict, merge results into the scan response.**

**What it does:**
- Check file hash against multiple AV engines
- Merge results into a combined "multi-engine" verdict
- Show per-engine results in the mobile app

**Backend changes:**
- New functions (following the same pattern as `check_virustotal()`):
  - `check_hybrid_analysis(file_hash)` — Hybrid Analysis API
  - `check_metadefender(file_hash)` — OPSWAT MetaDefender API
- New config: `HYBRID_ANALYSIS_API_KEY`, `METADEFENDER_API_KEY`
- Modify `/predict` response to include `multi_engine_results` array
- New endpoint: `GET /engines` — list available and enabled AV engines

**Frontend changes:**
- `ScanResult` model — add `multiEngineResults` field
- `ResultScreen` — add "Multi-Engine Results" section showing per-engine verdicts
- `constants.dart` — add new endpoint

**Dependencies:** None — each API integration is independent (needs API keys)  
**Estimated effort:** Low per API  
**Implementation chunk:** [Chunk 4C](plan.md)

---

## Feature 8: Root/Jailbreak Detection

> **COMMENT: The mobile app checks whether the Android device is rooted (has superuser access). Rooted devices are more vulnerable to malware. The detection result is shown to the user and sent to the backend as metadata with each scan.**

**What it does:**
- Flutter app checks for root indicators:
  - Presence of `su` binary
  - Presence of Magisk, SuperSU
  - System properties (`ro.debuggable`, `ro.secure`)
  - Test write access to system partition
- Display root status on home screen
- Attach root status to every scan request sent to backend

**Backend changes:**
- Modify `/predict` to accept optional `device_info` in request body
- Store `is_rooted` flag with scan result
- Factor root status into overall risk score (+10 risk if rooted)

**Frontend changes:**
- New service: `DeviceSecurityService` — performs root checks via MethodChannel
- Add root status indicator to HomeScreen header
- Modify `ApiService.scanApk()` to include `device_info` in form data

**Dependencies:** None — can be built independently  
**Estimated effort:** Low  
**Implementation chunk:** [Chunk 4A](plan.md)

---

## Feature 9: Two-Factor Authentication (2FA) for Enterprise

> **COMMENT: For enterprise deployments where the app is managed by an organization's IT team. Users must verify their identity with a second factor (TOTP code from Google Authenticator / Microsoft Authenticator) in addition to their password.**

**What it does:**
- After login, user is prompted for a 6-digit TOTP code
- Enterprise admin can enforce 2FA for all users in their organization
- Backup codes provided during 2FA setup

**Backend changes:**
- New dependency: `pyotp` for TOTP generation/verification
- New dependency: `qrcode` for QR code generation
- New endpoints:
  - `POST /auth/2fa/setup` — returns QR code URI + backup codes
  - `POST /auth/2fa/verify` — verifies TOTP code during login
  - `POST /auth/2fa/disable` — disables 2FA
- Modify `POST /auth/login` to return `requires_2fa: true` if enabled

**Frontend changes:**
- New screen: `TwoFactorSetupScreen` — shows QR code, guided setup
- New screen: `TwoFactorVerifyScreen` — 6-digit code input after login
- Modify `LoginScreen` to handle 2FA flow
- `AuthProvider` updated with 2FA state management

**Dependencies:** Feature 3 (user authentication system must exist first)  
**Estimated effort:** Medium-High  
**Implementation chunk:** [Chunk 6](plan.md)

---

## Feature Priority Matrix

| Feature | Effort | Dependencies | Chunk | Priority |
|---|---|---|---|---|
| 8 — Root Detection | 🟢 Low | None | 4A | Quick win |
| 4 — i18n | 🟢 Low-Med | None | 4B | Quick win |
| 7 — Additional AV APIs | 🟢 Low | API keys | 4C | Quick win |
| 1 — Installed App Monitoring | 🟡 Medium | None | 4D | Quick win |
| 5 — History Filtering | 🟡 Medium | Feature 3 | 3 | After auth |
| 6 — Custom Rules | 🟡 Medium | Feature 3 (optional) | 5 | After auth |
| 2 — Periodic Rescanning | 🟡 Medium | Feature 3 (DB) | 5 | After auth |
| 3 — Cloud Sync | 🔴 High | None (prereq) | 2+3 | Foundation |
| 9 — 2FA | 🔴 Med-High | Feature 3 | 6 | Last |
