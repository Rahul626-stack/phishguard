# 🛡️ PhishGuard

PhishGuard is an advanced, real-time phishing URL detection system that emulates enterprise-grade Security Operations Center (SOC) workflows. It provides a comprehensive safety net against zero-day phishing links using a robust architecture combining live forensics, machine learning, and active threat intelligence.

## 🎯 The Problem It Solves

As the cyber threat landscape evolves, static blocklists and naive regular expressions are no longer sufficient to stop sophisticated phishing campaigns. Attackers continuously rotate domains, utilize fast-flux networks, and deploy typosquatting techniques to bypass traditional security perimeters. 

**PhishGuard solves this by addressing:**
*   **Zero-Day Phishing:** Static lists fail against newly created malicious domains. PhishGuard evaluates the live characteristics and structure of a URL to catch threats before they hit any blocklist.
*   **Latency & Overhead:** Many security extensions slow down browsing. PhishGuard ensures a seamless experience with sub-500ms inference latency without heavy browser overhead.
*   **Siloed Security Data:** Security alerts without context are hard to act upon. PhishGuard centralizes insights, providing a holistic view of the threat landscape through a dedicated SOC dashboard.

## 🧠 How It Works

PhishGuard follows a modular, multi-layered architecture:

1.  **Client Extension:** A lightweight Chrome extension seamlessly intercepts URLs. It injects minimal content scripts to capture URL attributes and structure, acting as the first line of defense.
2.  **REST API Backend (FastAPI):** The orchestration layer that receives URL inputs and conducts immediate feature extraction. It computes lexical features (length, entropy, typosquatting), and performs active live forensics (DNS/WHOIS) to identify fast-flux behaviors or newly registered domains.
3.  **Active Cyber Threat Intelligence (CTI):** The backend queries authoritative threat feeds like VirusTotal and URLhaus to assign baseline reputation scores, adding a definitive external signal layer.
4.  **Machine Learning Engine:** An optimized XGBoost model processes the enriched features. Trained on the comprehensive ISCX benchmark dataset, it classifies the URL as `phishing` or `benign` with >=95% accuracy.
5.  **Analyst Dashboard:** A React-based Single Page Application (SPA) that functions as a SOC interface. It visualizes security events, threat metrics, and severity levels using intuitive charts, offering exportable IoC reports.

## 🚀 How to Run It

PhishGuard consists of three main components. You will need to run the backend and dashboard, and install the Chrome extension.

### 1. Setup the Backend
The backend requires Python 3.8+ and handles the machine learning model and API.

```bash
cd backend
# Install dependencies
pip install -r requirements.txt

# Run the FastAPI server
# On Windows, you can simply run:
run_backend.bat

# Alternatively, manually run:
python -m uvicorn main:app --reload
```
*The backend will be available at `http://localhost:8000`.*

### 2. Setup the SOC Dashboard
The dashboard is built with React and Vite. Requires Node.js.

```bash
cd dashboard
# Install Node.js dependencies
npm install

# Start the development server
npm run dev
```
*Access the dashboard at `http://localhost:5173` (or the port specified by Vite).*

### 3. Install the Chrome Extension
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** (toggle switch in the top right corner).
3. Click on the **Load unpacked** button.
4. Select the `extension` folder located inside the PhishGuard project directory.
5. The PhishGuard extension is now active and will monitor URLs in real-time.

## 📁 Repository Structure
*   `/backend` - FastAPI server, feature extraction, and API integrations.
*   `/dashboard` - React-based SOC dashboard for visualizing threat metrics.
*   `/extension` - Chrome extension for live URL monitoring and alerting.
*   `/ml` - Machine learning training scripts and the serialized XGBoost model.
*   `/datasets` - Source data utilized for model training.
