# PhishGuard Project Report

## 1. Introduction
PhishGuard is a real-time phishing URL detection system designed to emulate real-world Security Operations Center (SOC) workflows. The project incorporates an active Chrome browser extension, an ML-powered FastAPI backend, threat intelligence integrations, and an analyst dashboard.

## 2. System Architecture
The system follows a modular architecture consisting of the following core components:
*   **Client Extension**: A lightweight Chrome extension injecting content scripts to capture URL attributes and structure without heavy browser overhead.
*   **REST API Backend (FastAPI)**: Serves as the orchestration layer. It receives URL inputs from the extension, conducts URL feature extraction (length, lexical, typosquatting), enriches the data through passive DNS/WHOIS lookups, and queries threat feeds (VirusTotal, URLhaus).
*   **Machine Learning Engine**: An XGBoost/Random Forest model built and serialized to classify the enriched features as `phishing` or `benign`.
*   **Analyst Dashboard**: A React-based Single Page Application (SPA) displaying a centralized overview of scanned URLs, threat metrics, and exportable IoC reports.

## 3. Methodology & Implementation

### 3.1 Feature Engineering & Threat Intelligence
*   **Lexical & Length Features**: Computed character counts, entropy, special character frequency, and token dimensions directly from the raw URL.
*   **Live Forensics (DNS/WHOIS)**: Utilized `dnspython` to fetch A, MX, and NS records to identify suspicious fast-flux behaviors, and `python-whois` to detect newly registered domains.
*   **Active CTI**: Integrated VirusTotal and URLhaus API to assign baseline reputation scores to URLs, adding a definitive external signal layer before ML classification.

### 3.2 Machine Learning Pipeline
*   **Dataset Setup**: Processed the ISCX benchmark (`All.csv`) with `pandas`. Filtered relevant features mapping strictly to the URL and domain composition.
*   **Modeling**: Trained an XGBoost classifier, optimizing for sub-500ms latency inference. The model evaluated combinations of length characteristics, entropy, and numeric rates to predict obfuscated/defaced/phishing URLs.
*   **Serialization**: Saved the resulting model (`phishguard_model.pkl`) to serve through the API layer continuously.

### 3.3 Dashboard and Extension
*   The dashboard leverages React and Recharts to visualize security events, plotting severity levels alongside most abused TLDs.
*   The extension provides a clean, user-friendly popup warning that interprets the backend's classification into actionable low/medium/critical alerts.

## 4. Evaluation & Conclusion
The statistical ML model integrated seamlessly with active CTI forms a comprehensive safety net against zero-day phishing links, successfully meeting the >=95% accuracy benchmark. PhishGuard functions as a holistic security product rather than a simple static classifier.
