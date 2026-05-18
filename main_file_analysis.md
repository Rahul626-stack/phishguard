# Analysis of `main.py`: Issues and Proposed Improvements

This document outlines the critical flaws in the current `main.py` implementation, focusing on ML compatibility, heuristic scoring logic, whitelisting vulnerabilities, and overall cybersecurity posture.

## 1. Poor Heuristic Scoring Logic
The current implementation arbitrarily mixes static heuristic penalties with the Machine Learning model's calculated probabilities. 

**The Issue:**
```python
proba = model.predict_proba(df_features)[0]
ml_score = int(proba[1] * 100)

if 'login' in url.lower() or 'verify' in url.lower():
    ml_score += 20
```
- **Probability Calibration Destroyed:** The XGBoost model was rigorously trained to output an accurate probability between 0 and 1. Blindly adding a flat `+20` or `+30` to this percentage destroys the mathematical calibration. A highly confident safe URL (e.g., `login.microsoftonline.com`) might receive a 5% ML risk score, but the heuristic bumps it to 25%, miscategorizing it.
- **Redundancy:** The ML model already evaluates the structure of the URL (e.g., URL length, token counts). Adding manual penalties for length (`> 75`) creates a double-penalty effect.

**The Fix:**
- Strictly decouple ML predictions from heuristics. 
- If the ML model loads successfully, its probability should be the *only* factor determining the `risk_score`.
- Use the heuristics purely as "Explainable Tags" (e.g., adding "Suspicious keywords detected" to the `reasons` array) to help the user understand the context, without inflating the math.
- Only use heuristic point-additions as a **Fallback Score** if the ML model fails to load.

## 2. Poorly Built Whitelisting
The whitelist implementation is overly simplistic and presents a severe security vulnerability.

**The Issue:**
```python
domain = urllib.parse.urlparse(url).netloc
domain = domain.replace('www.', '')
if domain in trusted_domains:
    return risk_score = 0
```
- **Open Redirects:** Attackers regularly use Open Redirect vulnerabilities on trusted sites (e.g., `https://www.google.com/url?q=http://evil.com`). The current script sees `google.com`, ignores the payload, and instantly flags it as Safe.
- **Free Hosting Platforms:** Domains like `github.com` or `storage.googleapis.com` are trusted domains, but attackers can host malicious phishing payloads on them for free. A flat domain whitelist fails to account for path-level threats.

**The Fix:**
- Remove broad domain-level whitelisting for user-generated content hosting domains.
- Only whitelist specific, strict base paths, and ensure the URL does not contain redirect parameters.
- Alternatively, rely on the ML model, as it is robust enough to differentiate between a raw Google URL and an obfuscated Google redirect URL.

## 3. Weak Cybersecurity Logic (Missing Active Checks)
The current script lacks active infrastructure validation, which is a cornerstone of modern phishing detection.

**The Issue:**
- **No WHOIS Lookups:** Phishing domains are notoriously short-lived. A domain registered 2 days ago is significantly more suspicious than a domain registered 15 years ago. The script completely lacks WHOIS age validation.
- **Unused DNS Libraries:** The script imports `dns.resolver` but never actually executes any DNS queries. Checking if a domain has valid `A` records or specific `MX` records can immediately weed out randomly generated or parked domains.
- Without these network-layer checks, the tool relies entirely on lexical (string-based) analysis and URLhaus threat intel, meaning it cannot detect a brand-new phishing domain that structurally looks "normal" but has no infrastructure.

**The Fix:**
- **Implement DNS Validation:** Use `dnspython` to query `A` and `AAAA` records. If the domain doesn't resolve, flag it or return an error.
- **Implement WHOIS Age Checks:** Use the `python-whois` library to pull domain creation dates. If a domain is under 30 days old, attach a high-risk tag and manually bump the severity.

## 4. ML Model Compatibility
The ML model expects exactly 30 features matching `selected_features.json`. 

**The Issue:**
- While the `extract_features` function filters the dataframe to match the 30 columns, the backend needs robust error handling. If `feature_extractor.py` encounters an unparsable URL and returns a `-1` or `NaN` for a critical column that the XGBoost model wasn't trained to handle, it will throw a 500 Internal Server Error.

**The Fix:**
- Wrap `model.predict_proba` in a `try-except` block. If the feature matrix shape mismatches or the ML prediction fails, seamlessly drop down into the Heuristic Fallback mode so the API remains highly available.
