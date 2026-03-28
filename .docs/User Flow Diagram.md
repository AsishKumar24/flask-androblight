# AndroBlight — User Flow Diagrams

> **Reference:** [PRD.md](PRD.md) | [Detailed Feature.md](Detailed%20Feature.md) | [API List.md](API%20List.md)

---

## 1. Current Architecture

```mermaid
graph TB
    subgraph "Flutter Mobile App"
        A[main.dart] --> B[SplashScreen]
        B --> C[HomeScreen]
        C --> D[ScanApkScreen]
        C --> E[ScanPlaystoreScreen]
        C --> F[HistoryScreen]
        D --> G[ResultScreen]
        E --> G
        
        H[ScanProvider] --> I[ScanRepository]
        J[HistoryProvider] --> K[HistoryRepository]
        L[HealthProvider] --> I
        
        I --> M[ApiService]
        K --> N[StorageService / Hive]
    end
    
    subgraph "Flask Backend"
        O[app_enhanced.py] --> P[CNN-BiLSTM Model]
        O --> Q[Permission Analyzer]
        O --> R[Certificate Checker]
        O --> S[VirusTotal API]
        O --> T[PDF Report Generator]
        O --> U[JSON File Cache]
    end
    
    M -->|HTTP POST /predict| O
    M -->|HTTP POST /predict-playstore| O
    M -->|HTTP GET /health| O
    G -->|HTTP GET /report/sha256| O
```

---

## 2. Target Architecture (After All Chunks)

```mermaid
graph TB
    subgraph "Flutter Mobile App"
        A[main.dart] --> B[SplashScreen]
        B -->|Auth check| C{Logged in?}
        C -->|No| D[LoginScreen]
        C -->|Yes| E[HomeScreen]
        D --> E
        
        E --> F[ScanApkScreen]
        E --> G[ScanPlaystoreScreen]
        E --> H[HistoryScreen]
        E --> I[InstalledAppsScreen]
        E --> J[RulesScreen]
        
        F --> K[ResultScreen]
        G --> K
        
        L[AuthProvider]
        M[ScanProvider]
        N[HistoryProvider]
        O[MonitorProvider]
        P[RulesProvider]
    end
    
    subgraph "Flask Backend (Modularized)"
        Q[app.py] --> R[routes/scan.py]
        Q --> S[routes/auth.py]
        Q --> T[routes/sync.py]
        Q --> U[routes/history.py]
        Q --> V[routes/monitor.py]
        Q --> W[routes/rules.py]
        Q --> X[routes/rescan.py]
        Q --> Y[routes/two_factor.py]
        
        R --> Z[services/scanner.py]
        R --> AA[services/permissions.py]
        R --> AB[services/certificate.py]
        R --> AC[services/virustotal.py]
        R --> AD[services/hybrid_analysis.py]
        R --> AE[services/metadefender.py]
        
        AF[services/scheduler.py] --> AG[services/rescanner.py]
        
        AH[(PostgreSQL DB)]
        AI[CNN-BiLSTM v3 Model]
    end
    
    L -->|JWT Auth| S
    M -->|POST /predict| R
    N -->|GET /sync/history| T
    O -->|POST /monitor/installed-apps| V
    P -->|CRUD /rules| W
```

---

## 3. Core User Flows

### Flow 1: APK Scan (Current + Enhanced)

```mermaid
sequenceDiagram
    actor User
    participant App as Flutter App
    participant API as Backend API
    participant ML as CNN-BiLSTM Model
    participant VT as VirusTotal
    participant HA as Hybrid Analysis
    participant MD as MetaDefender

    User->>App: Select APK file
    App->>App: FilePicker → get file
    App->>API: POST /predict (multipart: file + device_info)
    
    API->>API: Extract APK (ZIP)
    API->>API: Parse AndroidManifest.xml
    API->>API: Analyze permissions
    API->>API: Extract certificate info
    API->>API: Convert binary → 128×128 greyscale image
    API->>ML: model.predict(image)
    ML-->>API: confidence (0.0 - 1.0)
    
    par Multi-Engine Check
        API->>VT: Check file hash
        VT-->>API: VirusTotal result
        API->>HA: Check file hash
        HA-->>API: Hybrid Analysis result
        API->>MD: Check file hash
        MD-->>API: MetaDefender result
    end
    
    API->>API: Merge all results
    API->>API: Save to database
    API-->>App: Scan result JSON
    
    App->>App: Save to Hive (local)
    App->>App: Navigate to ResultScreen
    App->>User: Display result with confidence gauge
```

### Flow 2: User Registration & Login

```mermaid
sequenceDiagram
    actor User
    participant App as Flutter App
    participant API as Backend API
    participant DB as Database

    User->>App: Tap "Register"
    App->>App: Show RegisterScreen
    User->>App: Enter email + password
    App->>API: POST /auth/register
    API->>DB: Create user (hash password)
    API-->>App: {token, user}
    App->>App: Store JWT in Hive
    App->>App: Navigate to HomeScreen
    
    Note over User,DB: Later — on new device:
    
    User->>App: Tap "Login"
    App->>API: POST /auth/login
    API->>DB: Verify credentials
    
    alt 2FA Enabled
        API-->>App: {requires_2fa: true}
        App->>App: Show TwoFactorVerifyScreen
        User->>App: Enter 6-digit code
        App->>API: POST /auth/2fa/verify
        API-->>App: {token}
    else No 2FA
        API-->>App: {token, user}
    end
    
    App->>App: Store JWT
    App->>API: GET /sync/history
    API-->>App: Previous scan records
    App->>App: Merge into local Hive
    App->>App: Navigate to HomeScreen
```

### Flow 3: Cloud Sync

```mermaid
sequenceDiagram
    participant Phone1 as Device 1
    participant API as Backend
    participant DB as Database
    participant Phone2 as Device 2

    Phone1->>API: POST /predict (file + JWT)
    API->>DB: Save scan record (user_id=1)
    API-->>Phone1: Scan result
    Phone1->>Phone1: Save to local Hive

    Note over Phone1,Phone2: User logs in on Device 2

    Phone2->>API: POST /auth/login
    API-->>Phone2: {token}
    Phone2->>API: GET /sync/history?since=never
    API->>DB: SELECT * FROM scans WHERE user_id=1
    API-->>Phone2: All scan records
    Phone2->>Phone2: Save to local Hive
    Phone2->>Phone2: Display in HistoryScreen
```

### Flow 4: Installed App Monitoring

```mermaid
sequenceDiagram
    actor User
    participant App as Flutter App
    participant Native as Android Native
    participant API as Backend
    participant VT as VirusTotal

    User->>App: Tap "Scan My Phone"
    App->>Native: MethodChannel → getInstalledApps()
    Native-->>App: [{packageName, appName, icon}, ...]
    App->>App: Extract package names
    App->>API: POST /monitor/installed-apps {packages: [...]}
    
    loop Each package
        API->>VT: Check package hash
        VT-->>API: Verdict
    end
    
    API-->>App: [{pkg, risk_level, reason}, ...]
    App->>App: Display InstalledAppsScreen
    App->>User: Color-coded risk list
```

### Flow 5: History Search & Filter

```mermaid
sequenceDiagram
    actor User
    participant App as Flutter App
    participant API as Backend

    User->>App: Open HistoryScreen
    App->>App: Load local Hive history
    App->>User: Show full list

    User->>App: Type "whatsapp" in search
    App->>App: Filter local results
    App->>User: Show matching items

    User->>App: Tap "Malware" filter chip
    App->>App: Filter: label == "Malware"
    App->>User: Show only malware results

    Note over User,API: If logged in — also search cloud:
    
    App->>API: GET /history?search=whatsapp&filter=malware&page=1
    API-->>App: Paginated results
    App->>App: Merge with local
    App->>User: Updated list
```

---

## 4. State Management Flow

```mermaid
graph LR
    subgraph "Providers (ChangeNotifier)"
        A[AuthProvider] -->|token| B[ApiService]
        C[ScanProvider] -->|scanApkFile| D[ScanRepository]
        E[HistoryProvider] -->|loadHistory| F[HistoryRepository]
        G[HealthProvider] -->|checkHealth| D
        H[MonitorProvider] -->|scanInstalledApps| B
        I[RulesProvider] -->|loadRules| B
    end
    
    subgraph "Services"
        D --> B[ApiService]
        F --> B
        F --> J[StorageService/Hive]
    end
    
    subgraph "Backend"
        B -->|HTTP| K[Flask API]
    end
```

---

## 5. Demo Mode Flow

```mermaid
sequenceDiagram
    participant App as Flutter App
    participant API as Backend

    App->>API: GET /health
    
    alt Backend Online
        API-->>App: {status: healthy}
        App->>App: Set isBackendOnline = true
        Note over App: All features use real API
    else Backend Offline
        App->>App: Connection timeout
        App->>App: Set isBackendOnline = false
        App->>App: Enable Demo Mode
        Note over App: Scans return simulated results
        Note over App: History works locally only
        Note over App: Auth features disabled
    end
```

The Flutter app has a `devMode` flag in `constants.dart` that can be toggled to force demo mode even when the backend is available. This is useful for development and presentations.
