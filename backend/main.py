from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import joblib
import os
import requests
import urllib.parse
import dns.resolver
from feature_extractor import extract_features

def check_urlhaus(url: str) -> bool:
    """Queries the open URLhaus API to check if the URL is a known threat."""
    try:
        response = requests.post('https://urlhaus-api.abuse.ch/v1/url/', data={'url': url}, timeout=2)
        if response.status_code == 200:
            data = response.json()
            # query_status is 'ok' if found in db, 'no_results' if not found
            if data.get('query_status') == 'ok':
                return True
    except:
        pass
    return False

app = FastAPI(title="PhishGuard API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

MODEL_PATH = os.path.join(os.path.dirname(__file__), '../ml/phishguard_model.pkl')
try:
    model = joblib.load(MODEL_PATH)
    print("Model loaded successfully.")
except Exception as e:
    model = None
    print(f"Failed to load model: {e}")

class URLScanRequest(BaseModel):
    url: str

class URLScanResponse(BaseModel):
    url: str
    risk_score: int
    severity: str
    reasons: list[str]

@app.get("/")
def read_root():
    return {"status": "PhishGuard API is running"}

@app.post("/scan", response_model=URLScanResponse)
def scan_url(req: URLScanRequest):
    url = req.url
    reasons = []
    
    # 0. Quick Whitelist for common trusted domains
    trusted_domains = ['google.com', 'youtube.com', 'facebook.com', 'github.com', 'microsoft.com', 'apple.com', 'linkedin.com']
    try:
        domain = urllib.parse.urlparse(url if url.startswith('http') else 'http://' + url).netloc
        domain = domain.replace('www.', '')
        if domain in trusted_domains:
            return URLScanResponse(
                url=url,
                risk_score=0,
                severity="Low",
                reasons=["Verified Trusted Domain (Whitelist)"]
            )
    except:
        pass
        
    # 0.5 Threat Intelligence (Active Lookup)
    is_blacklisted = check_urlhaus(url)
    if is_blacklisted:
        return URLScanResponse(
            url=url,
            risk_score=100,
            severity="Critical",
            reasons=["Blacklisted by URLhaus Threat Intelligence"]
        )
        
    # 1. Feature Extraction
    df_features = extract_features(url)
    
    # 2. ML Prediction
    ml_score = 0
    if model:
        # Predict probability of class 1 (phishing)
        proba = model.predict_proba(df_features)[0]
        ml_score = int(proba[1] * 100)
    else:
        reasons.append("ML model unavailable, relying on heuristics.")
        if len(url) > 75:
            ml_score += 40
            reasons.append("Unusually long URL")
        if url.count('.') > 3:
            ml_score += 30
            reasons.append("Multiple subdomains detected")
            
    # 3. Basic Heuristics
    if 'login' in url.lower() or 'verify' in url.lower():
        ml_score += 20
        reasons.append("Suspicious keywords in URL")
        
    final_score = min(ml_score, 100)
    
    if final_score < 40:
        severity = "Low"
    elif final_score < 75:
        severity = "Medium"
    elif final_score < 90:
        severity = "High"
    else:
        severity = "Critical"
        
    if final_score >= 40 and model:
        reasons.append(f"ML Model predicted risk {final_score}%")
        
    if not reasons:
        reasons.append("No immediate threats detected.")
        
    return URLScanResponse(
        url=url,
        risk_score=final_score,
        severity=severity,
        reasons=reasons
    )
