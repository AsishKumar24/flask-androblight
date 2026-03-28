# AndroBlight — Technical Documentation

> **Reference:** [PRD.md](PRD.md) | [Database Schema.md](Database%20Schema.md) | [API List.md](API%20List.md)

---

## 1. Tech Stack

### Backend

| Component | Technology | Version | Purpose |
|---|---|---|---|
| Runtime | Python | 3.10+ | Server language |
| Framework | Flask | 3.x | REST API server |
| ML Framework | TensorFlow / Keras | 2.x / 3.13.2 | CNN-BiLSTM model inference |
| Image Processing | OpenCV (cv2) | 4.x | APK binary → greyscale image conversion |
| APK Analysis | AndroGuard | 3.x | APK manifest parsing, certificate extraction |
| Database | SQLAlchemy + SQLite/PostgreSQL | 2.x | ORM + persistent storage |
| Auth | Flask-JWT-Extended + bcrypt | — | JWT token auth + password hashing |
| 2FA | pyotp + qrcode | — | TOTP generation/verification |
| PDF Reports | ReportLab | — | PDF scan report generation |
| AV Integration | requests | — | VirusTotal, Hybrid Analysis, MetaDefender APIs |
| Background Jobs | APScheduler | — | Periodic rescanning |
| CORS | Flask-CORS | — | Cross-origin support for mobile app |

### Mobile (Flutter)

| Component | Technology | Version | Purpose |
|---|---|---|---|
| Framework | Flutter | 3.x | Cross-platform mobile UI |
| Language | Dart | 3.x | App logic |
| State Management | Provider | 6.x | ChangeNotifier-based state |
| HTTP Client | Dio | 5.x | API requests with interceptors |
| Local Storage | Hive | 2.x | Offline scan history |
| Date Formatting | intl | — | Timestamp display |
| File Picker | file_picker | — | APK file selection |
| Device Apps | device_apps / installed_apps | — | List installed packages (Feature 1) |
| Localization | flutter_localizations + intl | — | i18n support (Feature 4) |

---

## 2. ML Model Architecture — CNN-BiLSTM v3

### Model File
- **Location:** `androblight-backend/model/` (after Chunk 1 migration)
- **Architecture config:** `model/config.json`
- **Weights:** `model/model.weights.h5`
- **Keras version:** 3.13.2
- **Saved:** 2026-03-14

### Architecture

```
Input (128×128×1 greyscale image)
  ↓ Data Augmentation (training only):
    - RandomFlip (horizontal)
    - RandomRotation (±5°)
    - RandomZoom (5%)
  ↓ CNN Feature Extraction:
    - Conv2D(32, 3×3, relu, same) → BatchNorm → MaxPool(2×2) → Dropout(0.3)
      Output: 64×64×32
    - Conv2D(64, 3×3, relu, same) → BatchNorm → MaxPool(2×2) → Dropout(0.3)
      Output: 32×32×64
    - Conv2D(128, 3×3, relu, same) → BatchNorm → MaxPool(2×2) → Dropout(0.3)
      Output: 16×16×128
    - Conv2D(256, 3×3, relu, same) → BatchNorm → MaxPool(2×2) → Dropout(0.4)
      Output: 8×8×256
  ↓ Reshape: (8×8×256) → (8, 2048)
  ↓ Bidirectional LSTM (128 units, recurrent_dropout=0.2)
    Forward LSTM (128) + Backward LSTM (128) → concat → 256
  ↓ Dropout(0.5)
  ↓ Dense(128, relu, L2 regularization=0.001)
  ↓ Dropout(0.4)
  ↓ Dense(1, sigmoid) → output probability
```

### Input/Output

| Parameter | Value |
|---|---|
| Input shape | `(batch, 128, 128, 1)` |
| Input type | Float32, normalized (0.0 - 1.0) |
| Output shape | `(batch, 1)` |
| Output range | 0.0 (benign) to 1.0 (malware) |
| Threshold | > 0.5 = Malware |

### Training Configuration

| Parameter | Value |
|---|---|
| Optimizer | Adam |
| Learning Rate | CosineDecay (initial=0.001, decay_steps=10900) |
| Loss | Custom `loss_fn` (binary) |
| Metrics | Accuracy |

### How APK → Image Conversion Works

```python
# 1. Extract these files from the APK (ZIP):
files_to_include = ['classes.dex', 'AndroidManifest.xml', 'META-INF/CERT.RSA', 'resources.arsc']

# 2. Concatenate their raw bytes:
binary_data = bytearray()
for file in files_to_include:
    binary_data.extend(read_bytes(file))

# 3. Convert to numpy array:
data_array = np.frombuffer(binary_data, dtype=np.uint8)

# 4. Pad to square:
size = ceil(sqrt(len(data_array)))
padded = np.zeros(size * size, dtype=np.uint8)
padded[:len(data_array)] = data_array
image = padded.reshape((size, size))

# 5. Resize to model input:
resized = cv2.resize(image, (128, 128))  # ← CRITICAL: must be 128, not 256

# 6. Normalize and add channel:
normalized = resized / 255.0
final = np.expand_dims(normalized, axis=-1)  # Shape: (128, 128, 1)
```

---

## 3. Project Structure (After Chunk 1 Modularization)

### Backend — Target Structure

```
androblight-backend/
├── app.py                      # Flask app factory, startup
├── config.py                   # Configuration constants, env vars
├── requirements.txt            # Python dependencies
├── model/                      # CNN-BiLSTM v3 model
│   ├── config.json             # Model architecture
│   ├── metadata.json           # Model metadata
│   └── model.weights.h5        # Model weights
├── models/                     # Data models
│   ├── permissions_db.py       # DANGEROUS_PERMISSIONS, SUSPICIOUS_COMBOS, MALWARE_FAMILIES
│   ├── database.py             # SQLAlchemy models (Chunk 2)
│   └── threat_rule.py          # ThreatRule model (Chunk 5)
├── services/                   # Business logic
│   ├── scanner.py              # apk_to_image(), extract_apk(), classify_malware_family()
│   ├── permissions.py          # analyze_permissions(), parse_android_manifest()
│   ├── certificate.py          # extract_certificate_info()
│   ├── virustotal.py           # check_virustotal()
│   ├── hybrid_analysis.py      # check_hybrid_analysis() (Chunk 4C)
│   ├── metadefender.py         # check_metadefender() (Chunk 4C)
│   ├── report.py               # generate_pdf_report()
│   ├── scheduler.py            # APScheduler setup (Chunk 5)
│   └── rescanner.py            # rescan_cached_hashes() (Chunk 5)
├── routes/                     # API endpoints
│   ├── scan.py                 # /predict, /predict-playstore, /batch-predict
│   ├── admin.py                # /health, /stats, /clear-cache, /report/<hash>
│   ├── auth.py                 # /auth/register, /auth/login, /auth/refresh (Chunk 2)
│   ├── sync.py                 # /sync/history (Chunk 3)
│   ├── history.py              # /history (Chunk 3)
│   ├── monitor.py              # /monitor/installed-apps (Chunk 4D)
│   ├── rules.py                # /rules CRUD (Chunk 5)
│   ├── rescan.py               # /rescan/updates (Chunk 5)
│   └── two_factor.py           # /auth/2fa/* (Chunk 6)
├── auth/                       # Authentication utilities
│   └── jwt_handler.py          # JWT creation, validation (Chunk 2)
├── i18n/                       # Translations (Chunk 4B)
│   ├── en.json
│   └── hi.json
├── uploads/                    # Temporary APK uploads
├── temp_extract/               # Temporary APK extraction
└── reports/                    # Generated PDF reports
```

### Mobile — Current Structure (No changes to structure)

```
androblight-mobile/lib/
├── main.dart
├── core/
│   ├── constants.dart
│   ├── theme.dart
│   ├── responsive.dart
│   ├── exceptions.dart
│   └── asset_helper.dart
├── models/
│   ├── scan_result.dart
│   ├── scan_history_item.dart
│   └── scan_history_item.g.dart
├── services/
│   ├── api_service.dart
│   ├── storage_service.dart
│   ├── auth_service.dart           # NEW (Chunk 2)
│   ├── device_security_service.dart # NEW (Chunk 4A)
│   └── network_monitor_service.dart # REMOVED from scope
├── repositories/
│   ├── scan_repository.dart
│   └── history_repository.dart
├── providers/
│   ├── scan_provider.dart
│   ├── health_provider.dart
│   ├── history_provider.dart
│   ├── auth_provider.dart          # NEW (Chunk 2)
│   ├── monitor_provider.dart       # NEW (Chunk 4D)
│   └── rules_provider.dart         # NEW (Chunk 5)
├── screens/
│   ├── splash_screen.dart
│   ├── home_screen.dart
│   ├── scan_apk_screen.dart
│   ├── scan_playstore_screen.dart
│   ├── result_screen.dart
│   ├── history_screen.dart
│   ├── login_screen.dart                # NEW (Chunk 2)
│   ├── register_screen.dart             # NEW (Chunk 2)
│   ├── installed_apps_screen.dart       # NEW (Chunk 4D)
│   ├── rules_screen.dart                # NEW (Chunk 5)
│   ├── two_factor_setup_screen.dart     # NEW (Chunk 6)
│   └── two_factor_verify_screen.dart    # NEW (Chunk 6)
├── widgets/
│   ├── loading_overlay.dart
│   ├── scan_card.dart
│   └── confidence_indicator.dart
└── l10n/                               # NEW (Chunk 4B)
    ├── app_en.arb
    └── app_hi.arb
```

---

## 4. Testing Strategy

### For each chunk, test:

| Layer | Tool | What to Test |
|---|---|---|
| Backend API | `pytest` + `requests` | Each endpoint responds correctly, error cases handled |
| Backend Unit | `pytest` | Each service function in isolation |
| Frontend Unit | `flutter test` | Providers, repositories, models |
| Integration | Manual | Full flow: app → backend → response → display |
| Regression | After each chunk | All previous chunk features still work |

### Critical Test Cases:

```
✅ Scan APK → malware detected → correct result displayed
✅ Scan APK → benign → correct result displayed  
✅ Backend offline → app falls back to demo mode
✅ Register → login → scan → history synced
✅ Search history → correct results filtered
✅ Custom rule matches → shown in result
✅ Root detected → shown on home screen
✅ Language switched → all strings translated
✅ Multiple AV engines → merged results shown
✅ 2FA setup → QR code generated → code verified
✅ Installed apps scan → risk list returned
✅ Periodic rescan → changed verdict shown
```

---

## 5. Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `FLASK_ENV` | No | `development` | Flask environment |
| `SECRET_KEY` | Yes | — | Flask secret key for sessions |
| `JWT_SECRET_KEY` | Yes | — | JWT signing secret |
| `DATABASE_URL` | No | `sqlite:///androblight.db` | Database connection string |
| `VIRUSTOTAL_API_KEY` | No | — | VirusTotal API key |
| `HYBRID_ANALYSIS_API_KEY` | No | — | Hybrid Analysis API key |
| `METADEFENDER_API_KEY` | No | — | MetaDefender API key |
| `MODEL_PATH` | No | `model/` | Path to CNN-BiLSTM model directory |
| `MAX_FILE_SIZE` | No | `50MB` | Maximum APK upload size |
