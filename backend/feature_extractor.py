import joblib
import pandas as pd
import urllib.parse
import re
import os

FEATURE_NAMES_PATH = os.path.join(os.path.dirname(__file__), '../ml/feature_names.pkl')

def extract_features(url: str):
    if not url.startswith('http'):
        url = 'http://' + url
        
    parsed = urllib.parse.urlparse(url)
    
    if os.path.exists(FEATURE_NAMES_PATH):
        feature_names = joblib.load(FEATURE_NAMES_PATH)
    else:
        # Fallback to empty list or basic names
        feature_names = ['urlLen', 'domainlength', 'pathLength', 'NumberofDotsinURL']
        
    features = {name: 0 for name in feature_names}
    
    # Fill in calculable features
    features['urlLen'] = len(url)
    features['domainlength'] = len(parsed.netloc)
    features['pathLength'] = len(parsed.path)
    features['NumberofDotsinURL'] = url.count('.')
    features['URL_DigitCount'] = sum(c.isdigit() for c in url)
    features['host_DigitCount'] = sum(c.isdigit() for c in parsed.netloc)
    features['URL_Letter_Count'] = sum(c.isalpha() for c in url)
    
    # Return as DataFrame for XGBoost
    df = pd.DataFrame([features])
    # Ensure correct column order
    if len(feature_names) > 4:
        df = df[feature_names]
        
    return df
