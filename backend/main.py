from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import joblib
import os
import requests
import urllib.parse
import base64
import dns.resolver
import whois
import difflib
from tranco import Tranco
from feature_extractor import extract_features
import datetime
from collections import defaultdict

# Global state for dashboard
dashboard_stats = {
    "scanned": 0,
    "blocked": 0,
    "alerts": 0,
    "nodes": 3 if os.path.exists(os.path.join(os.path.dirname(__file__), '../ml/phishguard_model.pkl')) else 0,
    "tld_counts": defaultdict(int),
    "timeline": [
        {"time": f"{(datetime.datetime.now() - datetime.timedelta(hours=i)).hour:02d}:00", "detections": 0, "scans": 0} 
        for i in range(5, -1, -1)
    ],
    "recent_scans": []
}

def update_dashboard_stats(url: str, severity: str, score: int):
    dashboard_stats["scanned"] += 1
    is_threat = severity in ["High", "Critical"]
    
    if is_threat:
        dashboard_stats["blocked"] += 1
    if severity == "Critical":
        dashboard_stats["alerts"] += 1
        
    try:
        domain = urllib.parse.urlparse(url if url.startswith('http') else 'http://' + url).netloc
        parts = domain.split('.')
        if len(parts) > 1:
            tld = "." + parts[-1]
            dashboard_stats["tld_counts"][tld] += 1
    except:
        pass

    now = datetime.datetime.now()
    current_hour = f"{now.hour:02d}:00"
    
    last_bucket = dashboard_stats["timeline"][-1]
    if last_bucket["time"] == current_hour:
        last_bucket["scans"] += 1
        if is_threat:
            last_bucket["detections"] += 1
    else:
        dashboard_stats["timeline"].pop(0)
        dashboard_stats["timeline"].append({"time": current_hour, "detections": 1 if is_threat else 0, "scans": 1})

    # Log recent scan
    dashboard_stats["recent_scans"].insert(0, {
        "url": url,
        "severity": severity,
        "score": score,
        "time": now.strftime("%H:%M:%S")
    })
    # Keep only the last 50 scans
    if len(dashboard_stats["recent_scans"]) > 50:
        dashboard_stats["recent_scans"].pop()


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

def check_virustotal(url: str) -> bool:
    """Queries the VirusTotal API using the provided API key."""
    vt_api_key = "405e209d35e1568aea1d68aeda7d4d1c72854233a79eec51d60d02fa3f2e9cb6"
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {
            "accept": "application/json",
            "x-apikey": vt_api_key
        }
        response = requests.get(f'https://www.virustotal.com/api/v3/urls/{url_id}', headers=headers, timeout=3)
        if response.status_code == 200:
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious_count = stats.get('malicious', 0)
            if malicious_count >= 2:
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

# Tranco Top 1M Initialization
try:
    print("Initializing Tranco list (This may take a moment on first run)...")
    t = Tranco(cache=True, cache_dir=os.path.join(os.path.dirname(__file__), '.tranco'))
    latest_list = t.list()
    # Cache the top 10k domains as a set for O(1) ultra-fast lookup
    trusted_domains = set(latest_list.top(10000))
    print(f"Loaded {len(trusted_domains)} trusted domains from Tranco.")
except Exception as e:
    print(f"Failed to load Tranco list: {e}")
    trusted_domains = set(['google.com', 'youtube.com', 'facebook.com', 'github.com', 'microsoft.com', 'apple.com', 'linkedin.com'])

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
    
    # 0. Quick Whitelist for Tranco top trusted domains
    try:
        parsed_url = urllib.parse.urlparse(url if url.startswith('http') else 'http://' + url)
        domain = parsed_url.netloc.replace('www.', '')
        path = parsed_url.path
        query = parsed_url.query
        
        # Strict Whitelisting: Must be a trusted domain with NO query strings and root path
        if domain in trusted_domains:
            if query == '' and (path == '' or path == '/'):
                return URLScanResponse(
                    url=url,
                    risk_score=0,
                    severity="Low",
                    reasons=["Verified Trusted Domain (Strict Whitelist)"]
                )
    except:
        pass
        
    # 0.5 Threat Intelligence (Active Lookup: URLhaus)
    is_blacklisted = check_urlhaus(url)
    if is_blacklisted:
        return URLScanResponse(
            url=url,
            risk_score=100,
            severity="Critical",
            reasons=["Blacklisted by URLhaus Threat Intelligence"]
        )
        
    # 0.6 Threat Intelligence (Active Lookup: VirusTotal)
    is_vt_malicious = check_virustotal(url)
    if is_vt_malicious:
        return URLScanResponse(
            url=url,
            risk_score=100,
            severity="Critical",
            reasons=["Flagged as Malicious by VirusTotal Threat Intelligence"]
        )
        
    # Active Infrastructure Checks (DNS, WHOIS & Typosquatting)
    active_reasons = []
    heuristic_penalty = 0
    
    try:
        parsed_url = urllib.parse.urlparse(url if url.startswith('http') else 'http://' + url)
        domain = parsed_url.netloc
        
        # 1. Brand Spoofing & Typosquatting Detection (Full URL)
        import re
        targeted_brands = ['google', 'youtube', 'facebook', 'github', 'microsoft', 'apple', 'linkedin', 'paypal', 'amazon', 'netflix', 'chase', 'bankofamerica', 'wells', 'instagram', 'twitter']
        
        raw_url = url.replace('https://', '').replace('http://', '').replace('www.', '')
        url_tokens = re.split(r'[\.\/\-\_\?\=\&]', raw_url)
        
        for token in url_tokens:
            token_lower = token.lower()
            for brand in targeted_brands:
                if len(token_lower) >= 4:
                    similarity = difflib.SequenceMatcher(None, token_lower, brand).ratio()
                    
                    if token_lower == brand:
                        # Exact match. Is it the legitimate official domain?
                        is_legit = domain.endswith(f"{brand}.com") or domain.endswith(f"{brand}.org") or domain.endswith(f"{brand}.net") or domain.endswith(f"{brand}.co.uk") or domain.endswith(f"{brand}.io")
                        if not is_legit:
                            active_reasons.append(f"Brand Spoofing: Deceptive use of '{brand}' in URL")
                            heuristic_penalty += 50
                    elif similarity >= 0.75:
                        active_reasons.append(f"Potential Typosquatting: '{token}' deceptively resembles '{brand}'")
                        heuristic_penalty += 40
        
        # 2. DNS Resolution (NXDOMAIN check)
        try:
            dns.resolver.resolve(domain, 'A')
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            active_reasons.append("Domain does not resolve to an IP (NXDOMAIN/Dead)")
            heuristic_penalty += 50
            
        # 2. WHOIS Age Check
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            if type(creation_date) is list:
                creation_date = creation_date[0]
            if creation_date:
                age_days = (datetime.datetime.now() - creation_date).days
                if age_days < 30:
                    active_reasons.append(f"Domain is very new (Registered {age_days} days ago)")
                    heuristic_penalty += 30
        except:
            pass # WHOIS failures shouldn't crash the scan
    except:
        pass

    # 1. Feature Extraction & ML Prediction
    ml_score = 0
    ml_success = False
    
    if model:
        try:
            df_features = extract_features(url)
            proba = model.predict_proba(df_features)[0]
            ml_score = int(proba[1] * 100)
            ml_success = True
        except Exception as e:
            reasons.append(f"ML extraction/prediction failed, falling back to heuristics")
    else:
        reasons.append("ML model unavailable, relying on heuristics.")
        
    # If ML failed or unavailable, calculate heuristic fallback score
    if not ml_success:
        if len(url) > 75:
            heuristic_penalty += 40
            reasons.append("Unusually long URL")
        if url.count('.') > 3:
            heuristic_penalty += 30
            reasons.append("Multiple subdomains detected")
        if 'login' in url.lower() or 'verify' in url.lower():
            heuristic_penalty += 20
            reasons.append("Suspicious keywords in URL")
            
        ml_score = min(heuristic_penalty, 100)
    else:
        # Decoupled Heuristics: Just add the context string to reasons
        if 'login' in url.lower() or 'verify' in url.lower():
            reasons.append("Suspicious keywords in URL")
            
    # Combine reasons
    reasons.extend(active_reasons)
        
    final_score = min(ml_score, 100)
    
    # Active checks (Spoofing, NXDOMAIN, WHOIS) are deterministic security flags.
    # If they triggered a penalty, it must override a "safe" ML prediction.
    if heuristic_penalty > 0:
        final_score = max(final_score, min(heuristic_penalty, 100))
    
    if final_score < 40:
        severity = "Low"
    elif final_score < 75:
        severity = "Medium"
    elif final_score < 90:
        severity = "High"
    else:
        severity = "Critical"
        
    if final_score >= 40 and ml_success:
        reasons.append(f"ML Model predicted risk {final_score}%")
        
    if not reasons:
        reasons.append("No immediate threats detected.")
        
    update_dashboard_stats(url, severity, final_score)
        
    return URLScanResponse(
        url=url,
        risk_score=final_score,
        severity=severity,
        reasons=reasons
    )

@app.get("/stats")
def get_stats():
    tld_list = [{"name": k, "count": v} for k, v in dashboard_stats["tld_counts"].items()]
    tld_list = sorted(tld_list, key=lambda x: x["count"], reverse=True)[:5]
    
    return {
        "stats": {
            "scanned": dashboard_stats["scanned"],
            "blocked": dashboard_stats["blocked"],
            "alerts": dashboard_stats["alerts"],
            "nodes": dashboard_stats["nodes"]
        },
        "tldData": tld_list,
        "timelineData": dashboard_stats["timeline"],
        "recentScans": dashboard_stats["recent_scans"]
    }
