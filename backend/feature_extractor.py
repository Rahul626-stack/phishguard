import pandas as pd
import urllib.parse
import re
import math
import os
import json
from collections import Counter

FEATURE_NAMES_PATH = os.path.join(os.path.dirname(__file__), '../reports/selected_features.json')

def entropy(s):
    if not s: return -1
    p, lns = Counter(s), float(len(s))
    return -sum(count/lns * math.log2(count/lns) for count in p.values())

def get_longest_word_len(text):
    if not text: return -1
    words = re.split(r'[^a-zA-Z0-9]', text)
    return max((len(w) for w in words), default=-1)

def extract_features(url: str):
    if not url.startswith('http'):
        url = 'http://' + url
        
    # Load selected features dynamically
    if os.path.exists(FEATURE_NAMES_PATH):
        with open(FEATURE_NAMES_PATH, 'r') as f:
            SELECTED_FEATURES = json.load(f)
    else:
        # Fallback if json is missing
        SELECTED_FEATURES = [] 
        
    features = {name: -1.0 for name in SELECTED_FEATURES} # Sentinel value -1
    
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    query = parsed.query
    
    path_parts = path.rsplit('/', 1)
    if len(path_parts) == 2:
        directory = path_parts[0] + '/'
        file_ext = path_parts[1]
    else:
        directory = path
        file_ext = ''
        
    if '.' in file_ext:
        filename, extension = file_ext.rsplit('.', 1)
    else:
        filename = file_ext
        extension = ''
        
    urlLen = len(url)
    features['urlLen'] = urlLen
    features['domainlength'] = len(domain) if domain else -1
    
    features['NumberofDotsinURL'] = url.count('.')
    features['URL_DigitCount'] = sum(c.isdigit() for c in url)
    features['NumberRate_URL'] = features['URL_DigitCount'] / urlLen if urlLen > 0 else 0
    features['Entropy_URL'] = entropy(url)
    
    features['spcharUrl'] = len(re.findall(r'[^a-zA-Z0-9]', url))
    features['SymbolCount_URL'] = features['spcharUrl']
    features['pathurlRatio'] = len(path) / urlLen if urlLen > 0 else 0
    
    # CharacterContinuityRate (Longest sequence of letters)
    consecutive_chars = re.findall(r'[a-zA-Z]+', url)
    longest_chars = max((len(x) for x in consecutive_chars), default=0)
    features['CharacterContinuityRate'] = longest_chars / urlLen if urlLen > 0 else 0
    
    features['Entropy_Domain'] = entropy(domain)
    features['Domain_LongestWordLength'] = get_longest_word_len(domain)
    features['domainUrlRatio'] = len(domain) / urlLen if urlLen > 0 else 0
    features['SymbolCount_Domain'] = len(re.findall(r'[^a-zA-Z0-9]', domain))
    features['NumberRate_Domain'] = sum(c.isdigit() for c in domain) / len(domain) if domain else 0
    
    domain_tokens = [t for t in re.split(r'\.', domain) if t]
    if domain_tokens:
        features['longdomaintokenlen'] = max(len(t) for t in domain_tokens)
        features['avgdomaintokenlen'] = sum(len(t) for t in domain_tokens) / len(domain_tokens)
    
    if directory and directory != '/':
        features['Directory_LetterCount'] = sum(c.isalpha() for c in directory)
        features['Directory_DigitCount'] = sum(c.isdigit() for c in directory)
        features['SymbolCount_Directoryname'] = len(re.findall(r'[^a-zA-Z0-9]', directory))
        features['Entropy_DirectoryName'] = entropy(directory)
    
    path_tokens = [t for t in re.split(r'[/]', path) if t]
    features['path_token_count'] = len(path_tokens)
    if path_tokens:
        features['avgpathtokenlen'] = sum(len(t) for t in path_tokens) / len(path_tokens)
    features['delimeter_path'] = len(re.findall(r'[^a-zA-Z0-9]', path)) if path else -1
    
    if filename:
        features['fileNameLen'] = len(filename)
        features['Filename_LetterCount'] = sum(c.isalpha() for c in filename)
        features['NumberRate_FileName'] = sum(c.isdigit() for c in filename) / len(filename)
        features['Entropy_Filename'] = entropy(filename)
        
    if extension:
        features['SymbolCount_Extension'] = len(re.findall(r'[^a-zA-Z0-9]', extension))
        features['NumberRate_Extension'] = sum(c.isdigit() for c in extension) / len(extension)
        features['Entropy_Extension'] = entropy(extension)
        
    if query:
        features['URLQueries_variable'] = len(urllib.parse.parse_qs(query))
        features['Arguments_LongestWordLength'] = get_longest_word_len(query)
        features['ArgUrlRatio'] = len(query) / urlLen if urlLen > 0 else 0
        features['argPathRatio'] = len(query) / len(path) if len(path) > 0 else -1
        
    after_path = parsed.query + parsed.fragment
    if after_path:
        features['NumberRate_AfterPath'] = sum(c.isdigit() for c in after_path) / len(after_path)
        
    # Return as DataFrame matching the exact columns needed by XGBoost
    df = pd.DataFrame([features])
    if SELECTED_FEATURES:
        # Reorder columns to match the training data exactly
        df = df[SELECTED_FEATURES]
        
    return df, domain.replace('www.', '')
