# PhishGuard: Real-Time Phishing & Threat Detection Browser Extension

## Guide
- Add the model training dataset to Data folder, Dataset used: 'https://www.kaggle.com/datasets/sarrazer/url-dataset-iscx-url2016'
- prerequisite node.js and python 3.10+, also install the dependencies from requiremnets.txt 

## Executive Summary
PhishGuard is an advanced, real-time browser security extension designed to intercept, analyze, and neutralize zero-day phishing links, malware distribution endpoints, and brand impersonation attempts directly at the client layer before malicious payloads can execute. Backed by a high-performance FastAPI orchestration engine and an enterprise Security Operations Center (SOC) dashboard, PhishGuard unifies live network forensics, threat intelligence feed aggregation, advanced typosquatting detection, and a customized multi-class Machine Learning classification engine to deliver decisive risk verdicts with sub-100ms processing latency.

---

## 1. Core Defense Architecture & Multi-Layered Detection Engine

PhishGuard employs a strict multi-stage filtering hierarchy to ensure high throughput, zero false positives on legitimate high-traffic infrastructure, and exhaustive forensic evaluation for unknown or newly registered endpoints.

```
+-----------------------------------------------------------------------------+
|                            Inbound URL Request                              |
+-----------------------------------------------------------------------------+
                                      |
                                      v
+-----------------------------------------------------------------------------+
|                      Stage 1: Strict Whitelist Verification                 |
|             (Tranco Top 10k In-Memory Set Cache — O(1) Lookup)              |
+-----------------------------------------------------------------------------+
                                      |
                +---------------------+---------------------+
                | (Match: Low Risk / 0 Score)               | (No Match)
                v                                           v
    [ Immediate Safe Response ]       +---------------------------------------+
                                      | Stage 2: Cyber Threat Intelligence    |
                                      |   (URLhaus & VirusTotal API Lookups)  |
                                      +---------------------------------------+
                                                            |
                                      +---------------------+-----------------+
                                      | (Match: Known Bad)                    | (Clean / Unknown)
                                      v                                       v
                        [ Immediate Critical Verdict ]     +-----------------------------------+
                                                           | Stage 3: Live Infrastructure      |
                                                           | - DNS A/AAAA Resolution (NXDOMAIN)|
                                                           | - WHOIS Creation Age (< 30 Days)  |
                                                           | - Sequence Matching Typosquatting |
                                                           +-----------------------------------+
                                                                               |
                                                                               v
                                                           +-----------------------------------+
                                                           | Stage 4: Multi-Class ML Engine    |
                                                           | - 30 Lexical & Structural Features|
                                                           | - XGBoost (5-Class Probability)   |
                                                           +-----------------------------------+
                                                                               |
                                                                               v
                                                           +-----------------------------------+
                                                           | Final Scoring & Dashboard Logging |
                                                           +-----------------------------------+
```

### 1.1 Stage 1: Ultra-Fast Tranco Whitelist Verification
To eliminate unnecessary API overhead and guarantee zero friction for end-users visiting ubiquitous services, the backend initializes the **Tranco Top 1,000,000** domain list at startup. It caches the top 10,000 domains into an in-memory Python `set`. When a URL is scanned, it is checked against this set in $O(1)$ time. 
*Strict Whitelist Rules:* A URL is only passed as verified safe if the domain matches the Top 10k set, contains no query parameters, and targets the root path (`/`). This eliminates the risk of Open Redirect bypasses (e.g., `google.com/url?q=malicious.com`) or malicious file hosting on cloud storage buckets.

### 1.2 Stage 2: Active Cyber Threat Intelligence (CTI) Integration
If the domain is not in the strict whitelist, PhishGuard queries external CTI databases:
- **URLhaus API:** Immediate validation against active malware distribution endpoints.
- **VirusTotal API v3:** Evaluates community consensus and multi-engine antivirus detection statistics. If 2 or more security vendors flag the URL as malicious, processing halts and an immediate **Critical** verdict (Risk Score: 100) is returned.

### 1.3 Stage 3: Active Network Forensics & Typosquatting Engine
PhishGuard does not rely strictly on static strings. It actively queries network and registration infrastructure:
- **DNS Resolution Check:** Uses `dnspython` to verify if the domain resolves to active `A` or `AAAA` records. Domains returning `NXDOMAIN` or lacking nameservers are instantly tagged as dead or parked infrastructure with a heavy heuristic penalty.
- **WHOIS Registration Age:** Queries registrar databases via `python-whois`. Phishing campaigns rely heavily on disposable infrastructure. Domains registered within the last 30 days are automatically assigned a high-risk security tag and penalty.
- **Brand Spoofing & Typosquatting:** Parses the full URL structure into discrete tokens and executes Levenshtein distance sequence matching (`difflib.SequenceMatcher`) against 15 highly targeted financial and tech institutions (e.g., Chase, Wells Fargo, Bank of America, PayPal, Google, Microsoft). If a token achieves $\ge 75\%$ similarity without matching the official authorized TLDs, a typosquatting penalty is enforced.

### 1.4 Stage 4: Multi-Class XGBoost Machine Learning Engine
For URLs that pass initial CTI and infrastructure checks, the system computes exactly 30 lexical and structural features (e.g., entropy calculations across domain and directory names, character continuity rates, delimiter frequencies, token length distributions). 

These features are fed into a serialized, hyperparameter-optimized Machine Learning pipeline (`phishguard_model.pkl`). Unlike standard binary classifiers, PhishGuard utilizes a multi-class XGBoost classifier trained on the comprehensive ISCX benchmark dataset across 5 specific categories:
1. `Benign` (Safe web traffic)
2. `Phishing` (Deceptive credential harvesting)
3. `Malware` (Payload delivery endpoints)
4. `Defacement` (Compromised or altered sites)
5. `Spam` (Unsolicited advertising or scam networks)

The XGBoost model outputs a 5-class soft probability distribution. The backend calculates the final ML risk percentage as $100\% - P(\text{Benign})$.

### 1.5 Stage 5: Deterministic Fallback & Verdict Aggregation
If the ML model is offline or unparsable due to malformed URL structures, the API gracefully transitions to a deterministic heuristic scoring model. Final risk scores are mapped directly to operational severity classifications:
- **0 - 39 (Low):** Normal browsing activity.
- **40 - 74 (Medium):** Suspicious structural anomalies or mild keywords.
- **75 - 89 (High):** Definitive typosquatting, dead DNS, or new domain registration.
- **90 - 100 (Critical):** Confirmed threat intel blacklist or high-confidence ML malicious classification.

---

## 2. System Component Breakdown

```
/phishguard
├── /backend                 # FastAPI Orchestration Layer & Active Security Engines
│   ├── main.py              # REST Endpoints, CTI Lookups, DNS/WHOIS, Heuristics
│   ├── feature_extractor.py # 30-Feature Lexical Calculation Engine
│   └── requirements.txt     # Python Runtime Dependencies
├── /dashboard               # Analyst Security Operations Center (SOC) Interface
│   ├── src/                 # React 18 / Vite / TailwindCSS Source Code
│   └── package.json         # Node.js Dependencies
├── /extension               # Chrome Client Extension (Manifest V3)
│   ├── manifest.json        # Browser Permissions & Background Hooks
│   ├── background.js        # Background Service Worker for API Interception
│   ├── content.js           # DOM Inspector
│   └── popup/               # Extension UI
├── /ml                      # Machine Learning Training Pipeline & Serialized Models
│   ├── train_model.py       # Multi-class XGBoost Training & RandomizedSearchCV
│   ├── phishguard_model.pkl # Serialized Production XGBoost Model
│   └── label_encoder.pkl    # Serialized 5-Class Target Mapping Encoder
└── /reports                 # System Benchmarks & Data Schemas
    ├── selected_features.json # Production 30-Feature Schema Source of Truth
    └── plots/               # 5x5 Confusion Matrix & Feature Importance Charts
```

---

## 3. Operational Deployment Guide

### 3.1 Backend Environment Setup
The backend requires Python 3.10+ and an active virtual environment.

```bash
cd backend
python -m venv .venv

# On Windows PowerShell:
.\.venv\Scripts\Activate.ps1
# On Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the FastAPI Server
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```
*The API documentation interactive swagger interface will be accessible at `http://localhost:8000/docs`.*(If you run the extension locally)

### 3.2 SOC Dashboard Setup
Requires Node.js 18+.

```bash
cd dashboard
npm install
npm run dev
```
*Access the live SOC interface at `http://localhost:5173`.*

### 3.3 Sideloading the Chrome Client Extension
1. Open Google Chrome and enter `chrome://extensions/` into the URL bar.
2. Enable **Developer Mode** using the toggle in the upper right.
3. Click **Load Unpacked**.
4. Select the `/extension` directory inside the repository. The PhishGuard shield icon will appear in your browser toolbar, continuously monitoring navigation events.

---

## 4. REST API Specification

### 4.1 URL Analysis Endpoint (`POST /scan`)
Executes the full multi-stage threat detection pipeline against a provided URL string.

**Request Payload (`application/json`):**
```json
{
  "url": "https://secure-update-login-paypal.com/auth?session=98124"
}
```

**Response Payload (`200 OK`):**
```json
{
  "url": "https://secure-update-login-paypal.com/auth?session=98124",
  "risk_score": 100,
  "severity": "Critical",
  "reasons": [
    "Potential Typosquatting: 'paypal' deceptively resembles 'paypal'",
    "Brand Spoofing: Deceptive use of 'paypal' in URL",
    "Domain is very new (Registered 4 days ago)",
    "Suspicious keywords in URL",
    "ML Model predicted risk 100%"
  ]
}
```

### 4.2 SOC Dashboard Analytics Endpoint (`GET /stats`)
Returns aggregated metrics, Top TLD distributions, timeline trends, and recent scan logs for the React dashboard.

**Response Payload (`200 OK`):**
```json
{
  "stats": {
    "scanned": 1420,
    "blocked": 48,
    "alerts": 12,
    "nodes": 3
  },
  "tldData": [
    {"name": ".com", "count": 890},
    {"name": ".net", "count": 150},
    {"name": ".ru", "count": 94}
  ],
  "timelineData": [
    {"time": "18:00", "detections": 2, "scans": 45},
    {"time": "19:00", "detections": 8, "scans": 120}
  ],
  "recentScans": [
    {
      "url": "https://secure-update-login-paypal.com/auth",
      "severity": "Critical",
      "score": 100,
      "time": "19:24:10",
      "reasons": ["Brand Spoofing: Deceptive use of 'paypal' in URL"]
    }
  ]
}
```

---

## 5. Model Evaluation & Benchmark Performance

The production model (`phishguard_model.pkl`) was trained on the benchmark ISCX dataset utilizing `StratifiedKFold` validation and hyperparameter tuning via `RandomizedSearchCV`.

### Hold-out Test Set Performance Metrics:
- **Overall Accuracy:** 98.19%
- **Macro F1-Score:** 98.20%
- **ROC-AUC (One-vs-Rest):** 99.95%

```
Class Classification Performance Breakdown:
+-------------------+-----------+--------+----------+---------+
| Threat Category   | Precision | Recall | F1-Score | Support |
+-------------------+-----------+--------+----------+---------+
| Benign            | 0.98      | 0.99   | 0.98     | 1,556   |
| Defacement        | 0.99      | 0.99   | 0.99     | 1,586   |
| Malware           | 0.99      | 0.98   | 0.99     | 1,343   |
| Phishing          | 0.96      | 0.96   | 0.96     | 1,517   |
| Spam              | 0.99      | 0.98   | 0.99     | 1,340   |
+-------------------+-----------+--------+----------+---------+
| Total / Macro Avg | 0.98      | 0.98   | 0.98     | 7,342   |
+-------------------+-----------+--------+----------+---------+
```

### Key Performance Attributes:
1. **Inference Latency:** Feature extraction and in-memory XGBoost tree evaluation execute in under 15ms. Combined with asynchronous DNS/WHOIS network calls, average round-trip latency remains under 100ms.
2. **Robustness:** Handles missing URL components seamlessly. Missing directories or arguments are mapped to structural sentinel values ($-1$) to prevent data drift or runtime exceptions during inference.
3. **Scalability:** The FastAPI backend utilizes asynchronous workers and memory-cached sets, allowing a single standard instance to handle over 2,500 scans per second.
