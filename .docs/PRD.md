# AndroBlight — Product Requirements Document (PRD)

> **Version:** 2.0 → 3.0 Roadmap  
> **Date:** March 25, 2026  
> **Team:** AndroBlight Group-47  
> **Repositories:** `androblight-backend` (Python/Flask) + `androblight-mobile` (Flutter/Dart)  
> **Scope:** 9 implementable features (excluded: Behavioral Analysis & Network Monitoring — require separate infrastructure)

---

## Table of Contents (Cross-references)

| Document | Description |
|---|---|
| [PRD.md](PRD.md) | This file — project overview, file inventory, dead code cleanup |
| [Detailed Feature.md](Detailed%20Feature.md) | All 9 feature specifications with comments |
| [plan.md](plan.md) | 6 implementation chunks with step-by-step tasks |
| [API List.md](API%20List.md) | Backend ↔ Frontend API contract |
| [Database Schema.md](Database%20Schema.md) | ER diagram and model definitions |
| [Tech Doc.md](Tech%20Doc.md) | ML model architecture, tech stack, testing strategy |
| [User Flow Diagram.md](User%20Flow%20Diagram.md) | Architecture diagrams and data flow |

---

## 1. Project Overview

### What is AndroBlight?
AndroBlight is an Android malware detection system with two components:
- **Backend** — A Flask API server that uses a CNN-BiLSTM deep learning model to classify APK files as malware or benign
- **Mobile App** — A Flutter app that lets users upload APK files or enter Play Store URLs, sends them to the backend, and displays scan results

### What does it do today?
1. User picks an APK file or enters a Play Store URL on the mobile app
2. The app sends the file to the backend's `/predict` endpoint
3. The backend extracts the APK, converts binary data to a greyscale image, runs it through the CNN-BiLSTM model
4. The backend also analyzes Android permissions, checks certificates, and optionally queries VirusTotal
5. The result (malware/benign + confidence + details) is sent back to the mobile app
6. The app displays the result and saves it to local Hive storage

### What is planned?
9 new features to make the system enterprise-ready. Each is specified in [Detailed Feature.md](Detailed%20Feature.md).

> **Excluded from scope:** Behavioral Analysis and Network Traffic Monitoring have been removed. Both require separate infrastructure projects (Android emulator sandboxing, VPN services) that cannot be implemented within this codebase. They may be revisited as standalone projects in the future.

---

## 2. File Inventory

### Backend — `androblight-backend/`

| File | Lines | Purpose | Status |
|---|---|---|---|
| `app_enhanced.py` | 1,084 | Main API server (everything in one file) | ⚠️ Active — needs modularization |
| `main.py` | 303 | Old version — 152 lines commented out, 151 lines duplicate | ❌ **DELETE** |
| `requirements.txt` | 25 | Dependencies | ✅ Keep, will expand |
| `cnn-lstm_detection_model.h5` | 50MB | Old v1 model (256×256 input) | ❌ **DELETE** — replaced by v3 |
| `model.weights.h5` | 32MB | **Active v3 CNN-BiLSTM model weights (128×128 input)** | ✅ **USE THIS** |
| `scan_cache.json` | 4KB | JSON file cache | ⚠️ Replace with DB |

> **⚠️ Critical model mismatch in current code:** The backend's `apk_to_image()` resizes images to 256×256, but `model.weights.h5` is the v3 model trained on **128×128** input. This must be fixed in Chunk 1 (see [plan.md](plan.md)).

### Mobile — `androblight-mobile/lib/`

| File | Lines | Purpose | Status |
|---|---|---|---|
| `main.dart` | 57 | App entry, provider setup | ✅ Clean |
| **core/** | | | |
| `constants.dart` | 22 | API config (baseUrl, endpoints, timeouts) | ✅ Clean — will add new endpoints |
| `theme.dart` | 170 | Dark theme, colors, Material 3 | ✅ Clean |
| `responsive.dart` | 94 | Screen size adaptation utility | ✅ Clean |
| `exceptions.dart` | 57 | Custom exception classes | ✅ Clean |
| `asset_helper.dart` | 30 | Bundle asset copy utility | ✅ Clean |
| **models/** | | | |
| `scan_result.dart` | 260 | Scan result model + sub-models | ✅ Clean — will expand |
| `scan_history_item.dart` | 58 | Hive history item model | ✅ Clean — will expand |
| `scan_history_item.g.dart` | 58 | Hive generated adapter | ✅ Auto-generated |
| **services/** | | | |
| `api_service.dart` | 149 | Dio HTTP client | ✅ Clean — will add new methods |
| `storage_service.dart` | 42 | Hive local storage | ✅ Clean |
| **repositories/** | | | |
| `scan_repository.dart` | 55 | Scan abstraction layer | ✅ Clean |
| `history_repository.dart` | 63 | History abstraction layer | ✅ Clean |
| **providers/** | | | |
| `scan_provider.dart` | 248 | Scan state management + demo mode | ✅ Clean |
| `health_provider.dart` | 51 | Backend health check state | ✅ Clean |
| `history_provider.dart` | 54 | History state management | ✅ Clean |
| **screens/** | | | |
| `splash_screen.dart` | 280 | Animated splash + health check | ✅ Clean |
| `home_screen.dart` | 311 | Main hub with scan options | ✅ Clean |
| `scan_apk_screen.dart` | 204 | APK file picker + scan trigger | ✅ Clean |
| `scan_playstore_screen.dart` | 295 | Play Store URL/package input | ✅ Clean |
| `result_screen.dart` | 370 | Full scan result display | ✅ Clean |
| `history_screen.dart` | 150 | Past scans list | ✅ Clean |
| **widgets/** | | | |
| `loading_overlay.dart` | 72 | Full-screen loading overlay | ✅ Clean |
| `scan_card.dart` | 170 | History list item card | ✅ Clean |
| `confidence_indicator.dart` | 154 | Animated circular gauge | ✅ Clean |

---

## 3. Dead Code & Cleanup Plan

### Backend — Files to Delete

| Item | Reason |
|---|---|
| `main.py` (entire file) | Lines 1–151 are commented-out old code. Lines 152–303 duplicate `app_enhanced.py` logic with a simpler response format. The Flutter app already uses `app_enhanced.py` endpoints. **Delete this file entirely.** |
| `cnn-lstm_detection_model.h5` | Old v1 model with 256×256 input. Replaced by `model.weights.h5` (v3, 128×128 input). **Delete after migrating to v3.** |

### Backend — Lines to Remove from `app_enhanced.py`

| Lines | What | Why Remove |
|---|---|---|
| 29 | `import os` | Duplicate — already imported on line 17 |
| 34 | `import xml.etree.ElementTree as ET` | Line 34 imports `ET` globally, then line 300 re-imports it inside `parse_android_manifest()`. **Remove line 300.** |
| 38 | `from functools import lru_cache` | Imported but **never used** anywhere — remove |
| 40 | `from io import BytesIO` | Imported but **never used** anywhere — remove |
| 300 | `import xml.etree.ElementTree as ET` | Duplicate import inside function — already imported at line 34 |

### Mobile — No Dead Code
The Flutter codebase is clean. All files are actively used with clear separation of concerns. No files to delete.
