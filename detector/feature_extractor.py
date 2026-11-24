import os
import re
import math
from urllib.parse import urlparse
import joblib
import pandas as pd
from django.conf import settings

# Path to the saved trained model
MODEL_PATH = os.path.join(settings.BASE_DIR, "models", "phishing_detector.pkl")

# Cached model instance
_CACHED_MODEL = None

# Baseline feature defaults computed from PhiUSIIL dataset medians
DATASET_MEDIANS = {
    "URLLength": 27.0,
    "DomainLength": 19.0,
    "IsDomainIP": 0.0,
    "URLSimilarityIndex": 100.0,
    "CharContinuationRate": 1.0,
    "TLDLegitimateProb": 0.07996,
    "URLCharProb": 0.05869,
    "TLDLength": 3.0,
    "NoOfSubDomain": 1.0,
    "HasObfuscation": 0.0,
    "NoOfObfuscatedChar": 0.0,
    "ObfuscationRatio": 0.0,
    "NoOfLettersInURL": 14.0,
    "LetterRatioInURL": 0.5,
    "NoOfDegitsInURL": 0.0,
    "DegitRatioInURL": 0.0,
    "NoOfEqualsInURL": 0.0,
    "NoOfQMarkInURL": 0.0,
    "NoOfAmpersandInURL": 0.0,
    "NoOfOtherSpecialCharsInURL": 1.0,
    "SpacialCharRatioInURL": 0.048,
    "IsHTTPS": 1.0,
    "LineOfCode": 534.5,
    "LargestLineLength": 1066.5,
    "HasTitle": 1.0,
    "DomainTitleMatchScore": 100.0,
    "URLTitleMatchScore": 100.0,
    "HasFavicon": 0.0,
    "Robots": 0.0,
    "IsResponsive": 1.0,
    "NoOfURLRedirect": 0.0,
    "NoOfSelfRedirect": 0.0,
    "HasDescription": 0.0,
    "NoOfPopup": 0.0,
    "NoOfiFrame": 0.0,
    "HasExternalFormSubmit": 0.0,
    "HasSocialNet": 0.0,
    "HasSubmitButton": 0.0,
    "HasHiddenFields": 0.0,
    "HasPasswordField": 0.0,
    "Bank": 0.0,
    "Pay": 0.0,
    "Crypto": 0.0,
    "HasCopyrightInfo": 1.0,
    "NoOfImage": 11.0,
    "NoOfCSS": 2.0,
    "NoOfJS": 7.0,
    "NoOfSelfRef": 24.0,
    "NoOfEmptyRef": 0.0,
    "NoOfExternalRef": 13.0,
}


def get_model():
    """Loads and caches the trained Random Forest model."""
    global _CACHED_MODEL
    if _CACHED_MODEL is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                f"Model file not found at {MODEL_PATH}. Run training first."
            )
        _CACHED_MODEL = joblib.load(MODEL_PATH)
    return _CACHED_MODEL


def normalize_url(raw_url: str) -> str:
    """Ensures the URL has a proper scheme for parsing."""
    url = raw_url.strip()
    if not url.startswith(("http://", "https://", "ftp://")):
        url = "http://" + url
    return url


def calculate_char_continuation(url: str) -> float:
    """Calculates max consecutive identical character count ratio."""
    if not url:
        return 0.0
    max_cont = 1
    current_cont = 1
    for i in range(1, len(url)):
        if url[i] == url[i - 1]:
            current_cont += 1
            if current_cont > max_cont:
                max_cont = current_cont
        else:
            current_cont = 1
    return float(max_cont)


def extract_features(raw_url: str) -> dict:
    """
    Extracts 50 features matching the PhiUSIIL dataset schema
    and produces human-readable security indicators.
    """
    url = normalize_url(raw_url)
    parsed = urlparse(url)

    domain = parsed.netloc.split(":")[0]
    path = parsed.path
    url_len = max(len(url), 1)

    # 1. IP Address check
    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    is_domain_ip = 1.0 if re.match(ip_pattern, domain) else 0.0

    # 2. Scheme & HTTPS
    is_https = 1.0 if parsed.scheme.lower() == "https" else 0.0

    # 3. Domain & TLD
    domain_parts = domain.split(".")
    tld = domain_parts[-1] if len(domain_parts) > 1 else ""
    tld_length = float(len(tld))
    num_subdomains = float(max(0, len(domain_parts) - 2))

    # 4. Obfuscation (% characters)
    obfuscated_chars = url.count("%")
    has_obfuscation = 1.0 if obfuscated_chars > 0 else 0.0
    obfuscation_ratio = float(obfuscated_chars) / url_len

    # 5. Character counts & ratios
    num_letters = sum(c.isalpha() for c in url)
    letter_ratio = float(num_letters) / url_len

    num_digits = sum(c.isdigit() for c in url)
    digit_ratio = float(num_digits) / url_len

    num_equals = float(url.count("="))
    num_qmark = float(url.count("?"))
    num_ampersand = float(url.count("&"))

    # Special characters
    special_chars = sum(not c.isalnum() for c in url)
    special_char_ratio = float(special_chars) / url_len
    num_other_special = float(max(0, special_chars - (num_equals + num_qmark + num_ampersand)))

    char_continuation = calculate_char_continuation(url)

    # 6. Sensitive Keywords in URL
    url_lower = url.lower()
    has_bank = 1.0 if any(k in url_lower for k in ["bank", "banking", "chase", "wells", "citibank"]) else 0.0
    has_pay = 1.0 if any(k in url_lower for k in ["pay", "paypal", "payment", "checkout", "wallet"]) else 0.0
    has_crypto = 1.0 if any(k in url_lower for k in ["crypto", "binance", "coinbase", "bitcoin", "btc", "eth"]) else 0.0

    # Assemble feature dictionary with fallback to medians
    features = dict(DATASET_MEDIANS)

    features["URLLength"] = float(url_len)
    features["DomainLength"] = float(len(domain))
    features["IsDomainIP"] = is_domain_ip
    features["CharContinuationRate"] = char_continuation
    features["TLDLength"] = tld_length
    features["NoOfSubDomain"] = num_subdomains
    features["HasObfuscation"] = has_obfuscation
    features["NoOfObfuscatedChar"] = float(obfuscated_chars)
    features["ObfuscationRatio"] = obfuscation_ratio
    features["NoOfLettersInURL"] = float(num_letters)
    features["LetterRatioInURL"] = letter_ratio
    features["NoOfDegitsInURL"] = float(num_digits)
    features["DegitRatioInURL"] = digit_ratio
    features["NoOfEqualsInURL"] = num_equals
    features["NoOfQMarkInURL"] = num_qmark
    features["NoOfAmpersandInURL"] = num_ampersand
    features["NoOfOtherSpecialCharsInURL"] = num_other_special
    features["SpacialCharRatioInURL"] = special_char_ratio
    features["IsHTTPS"] = is_https
    features["Bank"] = has_bank
    features["Pay"] = has_pay
    features["Crypto"] = has_crypto

    # Build human-readable security indicators for frontend
    indicators = []
    if is_https:
        indicators.append({"type": "safe", "icon": "shield-check", "text": "HTTPS protocol is active (Encrypted connection)"})
    else:
        indicators.append({"type": "danger", "icon": "shield-alert", "text": "Insecure HTTP connection (No SSL encryption)"})

    if is_domain_ip:
        indicators.append({"type": "danger", "icon": "alert-triangle", "text": "Host is a raw IP address instead of a domain name (Common phishing tactic)"})
    else:
        indicators.append({"type": "safe", "icon": "globe", "text": f"Registered domain name: {domain}"})

    if num_subdomains > 2:
        indicators.append({"type": "warning", "icon": "layers", "text": f"Multiple subdomains ({int(num_subdomains)}) detected - often used to impersonate brands"})

    if has_obfuscation:
        indicators.append({"type": "danger", "icon": "code", "text": f"URL contains {int(obfuscated_chars)} obfuscated/hex-encoded characters"})

    if url_len > 75:
        indicators.append({"type": "warning", "icon": "maximize-2", "text": f"Unusually long URL length ({url_len} characters)"})

    if has_bank or has_pay or has_crypto:
        target = "Banking" if has_bank else ("Payment" if has_pay else "Cryptocurrency")
        indicators.append({"type": "warning", "icon": "dollar-sign", "text": f"High-value target keyword detected ({target}) in URL string"})

    summary = {
        "url": url,
        "domain": domain,
        "is_https": bool(is_https),
        "is_ip": bool(is_domain_ip),
        "url_length": int(url_len),
        "subdomains_count": int(num_subdomains),
        "has_obfuscation": bool(has_obfuscation),
        "tld": tld,
    }

    return features, indicators, summary


def predict_url(raw_url: str):
    """
    Extracts features, runs inference through the trained Random Forest model,
    and returns predictions with probabilities and indicators.
    """
    model = get_model()
    features_dict, indicators, summary = extract_features(raw_url)

    # Align with model's expected feature order
    feature_names = model.feature_names_in_
    input_df = pd.DataFrame([[features_dict.get(col, 0.0) for col in feature_names]], columns=feature_names)

    # Model prediction (1 = Phishing, 0 = Legitimate)
    prediction = int(model.predict(input_df)[0])
    probabilities = model.predict_proba(input_df)[0]

    # Probability of being Phishing (class 1)
    phishing_prob = float(probabilities[1]) * 100.0
    legitimate_prob = float(probabilities[0]) * 100.0

    # Consider phishing if predicted by model or probability >= 50%
    is_phishing = bool(prediction == 1 or phishing_prob >= 50.0)
    label = "Phishing" if is_phishing else "Legitimate"

    if is_phishing:
        risk_level = "High Threat" if phishing_prob > 75 else "Moderate Risk"
        badge_color = "red"
    else:
        risk_level = "Safe" if legitimate_prob > 85 else "Low Caution"
        badge_color = "green"

    return {
        "url": summary["url"],
        "is_phishing": is_phishing,
        "prediction": label,
        "confidence": round(phishing_prob if is_phishing else legitimate_prob, 2),
        "phishing_probability": round(phishing_prob, 2),
        "legitimate_probability": round(legitimate_prob, 2),
        "risk_level": risk_level,
        "badge_color": badge_color,
        "indicators": indicators,
        "summary": summary,
        "features": features_dict,
    }
