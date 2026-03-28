# AndroBlight — API List

> **Reference:** [PRD.md](PRD.md) | [Detailed Feature.md](Detailed%20Feature.md)  
> **Base URL:** `http://<backend-host>:5000`

---

## Existing Endpoints (v2.0 — Currently Live)

| Method | Endpoint | Auth? | Request | Response | Status |
|---|---|---|---|---|---|
| GET | `/health` | No | — | `{status, version, model_loaded, features[]}` | ✅ Active |
| POST | `/predict` | No | `multipart/form-data: file` | Full scan result JSON (see below) | ✅ Active |
| POST | `/predict-playstore` | No | `{url?, package?}` | Full scan result JSON | ✅ Active |
| POST | `/batch-predict` | No | `multipart/form-data: files[]` | `{results: [...]}` | ✅ Active |
| GET | `/report/<hash>` | No | — | PDF file download | ✅ Active |
| GET | `/stats` | No | — | `{total_scans, malware_detected, ...}` | ✅ Active |
| POST | `/clear-cache` | No | — | `{status: success}` | ✅ Active |

---

## New Endpoints (v3.0 — Planned)

### Authentication (Feature 3)

| Method | Endpoint | Auth? | Request | Response |
|---|---|---|---|---|
| POST | `/auth/register` | No | `{email, password}` | `{token, user}` |
| POST | `/auth/login` | No | `{email, password}` | `{token, user, requires_2fa?}` |
| POST | `/auth/refresh` | JWT | — | `{token}` |

### Two-Factor Authentication (Feature 9)

| Method | Endpoint | Auth? | Request | Response |
|---|---|---|---|---|
| POST | `/auth/2fa/setup` | JWT | — | `{qr_uri, backup_codes[]}` |
| POST | `/auth/2fa/verify` | Partial JWT | `{code}` | `{token}` |
| POST | `/auth/2fa/disable` | JWT | — | `{status}` |

### History & Sync (Features 3, 5)

| Method | Endpoint | Auth? | Request | Response |
|---|---|---|---|---|
| GET | `/sync/history` | JWT | `?since=<iso>` | `{records: [...]}` |
| POST | `/sync/history` | JWT | `{records: [...]}` | `{synced_count}` |
| GET | `/history` | JWT | `?search=&filter=&sort=&page=` | `{results[], total, page}` |

### Monitoring (Feature 1)

| Method | Endpoint | Auth? | Request | Response |
|---|---|---|---|---|
| POST | `/monitor/installed-apps` | Optional | `{packages: [...]}` | `{results: [{pkg, risk, reason}]}` |

### Rescanning (Feature 2)

| Method | Endpoint | Auth? | Request | Response |
|---|---|---|---|---|
| GET | `/rescan/updates` | JWT | `?since=<iso>` | `{updated_scans: [...]}` |

### Custom Rules (Feature 6)

| Method | Endpoint | Auth? | Request | Response |
|---|---|---|---|---|
| GET | `/rules` | JWT | — | `{rules: [...]}` |
| POST | `/rules` | JWT | `{permissions[], threat, desc}` | `{rule}` |
| PUT | `/rules/<id>` | JWT | `{permissions[], threat, desc}` | `{rule}` |
| DELETE | `/rules/<id>` | JWT | — | `{status}` |

### AV Engines (Feature 7)

| Method | Endpoint | Auth? | Request | Response |
|---|---|---|---|---|
| GET | `/engines` | No | — | `{engines: [{name, enabled}]}` |

---

## Response Formats

### Scan Result (POST /predict response)

```json
{
  "status": "success",
  "prediction": {
    "label": "Malware",
    "confidence": 0.9234,
    "malware_family": "Trojan.AndroidOS.FakeInst",
    "threat_level": "HIGH"
  },
  "permission_analysis": {
    "total_permissions": 15,
    "dangerous_permissions": ["SEND_SMS", "READ_CONTACTS", "CAMERA"],
    "risk_score": 75,
    "suspicious_combinations": [
      {
        "permissions": ["SEND_SMS", "INTERNET"],
        "threat": "SMS Trojan",
        "description": "Can send premium SMS messages"
      }
    ]
  },
  "certificate_info": {
    "issuer": "CN=Debug, O=Android",
    "is_debug_cert": true,
    "validity": {...}
  },
  "virustotal": {
    "detected": true,
    "positives": 15,
    "total": 60,
    "scan_date": "2026-03-25"
  },
  "multi_engine_results": [
    {"engine": "VirusTotal", "detected": true, "result": "Trojan.AndroidOS"},
    {"engine": "HybridAnalysis", "detected": true, "result": "malicious"},
    {"engine": "MetaDefender", "detected": false, "result": "clean"}
  ],
  "metadata": {
    "file_hash": "sha256:abc123...",
    "file_name": "suspicious.apk",
    "file_size": 1024000,
    "scan_timestamp": "2026-03-25T12:00:00Z"
  },
  "recommendation": "DO NOT INSTALL — This app shows strong malware indicators"
}
```

### Auth Token Response

```json
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "user": {
    "id": 1,
    "email": "user@example.com",
    "is_2fa_enabled": false,
    "created_at": "2026-03-25T12:00:00Z"
  }
}
```

### History Response (paginated)

```json
{
  "results": [
    {
      "id": 1,
      "file_hash": "sha256:abc123...",
      "file_name": "app.apk",
      "label": "Malware",
      "confidence": 0.92,
      "threat_level": "HIGH",
      "scanned_at": "2026-03-25T12:00:00Z"
    }
  ],
  "total": 45,
  "page": 1,
  "per_page": 20
}
```

---

## Error Responses

All error responses follow this format:

```json
{
  "error": "Human-readable error message",
  "status": "error",
  "code": 400
}
```

| HTTP Code | Meaning |
|---|---|
| 400 | Bad request (missing file, invalid input) |
| 401 | Unauthorized (missing or expired JWT) |
| 403 | Forbidden (2FA required, insufficient permissions) |
| 404 | Not found (scan hash, rule ID) |
| 413 | File too large |
| 429 | Rate limit exceeded (AV API throttling) |
| 500 | Server error |

---

## Authentication Flow

```
1. Register:      POST /auth/register → {token}
2. Login:         POST /auth/login → {token, requires_2fa?}
3. If 2FA:        POST /auth/2fa/verify → {token}
4. Use token:     Authorization: Bearer <token>
5. Token expired: POST /auth/refresh → {new_token}
```

All JWT-protected endpoints return `401` if the token is missing or expired. The Flutter app's `ApiService` automatically refreshes expired tokens via interceptor.
