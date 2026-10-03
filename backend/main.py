from fastapi import FastAPI
from pydantic import BaseModel
from urllib.parse import urlparse
import re
import joblib
import pandas as pd

app = FastAPI(
    title="PHISHGUARD - Intelligent Phishing URL Detection",
    version="1.0.0"
)

# Load trained XGBoost model
model_data = joblib.load("ml/phishguard_model.joblib")
model = model_data["model"]
FEATURES = model_data["features"]


class URLRequest(BaseModel):
    url: str


def extract_features(url):
    url = url.strip()

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    features = {}

    features["URLLength"] = len(url)
    features["DomainLength"] = len(hostname)

    features["IsDomainIP"] = int(
        bool(re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", hostname))
    )

    features["URLSimilarityIndex"] = 0
    features["CharContinuationRate"] = 0
    features["TLDLegitimateProb"] = 0.5
    features["URLCharProb"] = 0.5
    features["TLDLength"] = len(hostname.split(".")[-1])

    features["NoOfSubDomain"] = max(0, hostname.count(".") - 1)

    features["HasObfuscation"] = int("@" in url or "%" in url)

    features["NoOfObfuscatedChar"] = sum(
        1 for c in url if c in ["@", "%"]
    )

    features["ObfuscationRatio"] = (
        features["NoOfObfuscatedChar"] / max(len(url), 1)
    )

    features["NoOfLettersInURL"] = sum(c.isalpha() for c in url)

    features["LetterRatioInURL"] = (
        features["NoOfLettersInURL"] / max(len(url), 1)
    )

    features["NoOfDegitsInURL"] = sum(c.isdigit() for c in url)

    features["DegitRatioInURL"] = (
        features["NoOfDegitsInURL"] / max(len(url), 1)
    )

    features["NoOfEqualsInURL"] = url.count("=")
    features["NoOfQMarkInURL"] = url.count("?")
    features["NoOfAmpersandInURL"] = url.count("&")

    special_chars = sum(
        not c.isalnum() and c not in "/.:_-"
        for c in url
    )

    features["NoOfOtherSpecialCharsInURL"] = special_chars

    features["SpacialCharRatioInURL"] = (
        special_chars / max(len(url), 1)
    )

    features["IsHTTPS"] = int(
        parsed.scheme.lower() == "https"
    )

    # Features that require webpage access
    # are set to safe defaults for this demo.
    defaults = {
        "LineOfCode": 0,
        "LargestLineLength": 0,
        "HasTitle": 0,
        "DomainTitleMatchScore": 0,
        "URLTitleMatchScore": 0,
        "HasFavicon": 0,
        "Robots": 0,
        "IsResponsive": 0,
        "NoOfURLRedirect": 0,
        "NoOfSelfRedirect": 0,
        "HasDescription": 0,
        "NoOfPopup": 0,
        "NoOfiFrame": 0,
        "HasExternalFormSubmit": 0,
        "HasSocialNet": 0,
        "HasSubmitButton": 0,
        "HasHiddenFields": 0,
        "HasPasswordField": 0,
        "Bank": 0,
        "Pay": 0,
        "Crypto": 0,
        "HasCopyrightInfo": 0,
        "NoOfImage": 0,
        "NoOfCSS": 0,
        "NoOfJS": 0,
        "NoOfSelfRef": 0,
        "NoOfEmptyRef": 0,
        "NoOfExternalRef": 0,
    }

    features.update(defaults)

    return pd.DataFrame(
        [[features.get(feature, 0) for feature in FEATURES]],
        columns=FEATURES
    )


def analyze_rules(url):
    score = 0
    reasons = []

    test_url = url if "://" in url else "https://" + url

    parsed = urlparse(test_url)
    hostname = parsed.hostname or ""
    lower_url = url.lower()

    if parsed.scheme.lower() != "https":
        score += 20
        reasons.append("URL does not use HTTPS")

    if re.match(
        r"^(?:\d{1,3}\.){3}\d{1,3}$",
        hostname
    ):
        score += 30
        reasons.append("URL uses an IP address")

    if "@" in url:
        score += 20
        reasons.append("URL contains @ symbol")

    if len(url) > 100:
        score += 10
        reasons.append("URL is unusually long")

    if hostname.count(".") >= 3:
        score += 10
        reasons.append("Many subdomains detected")

    suspicious_words = [
        "login",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "password",
        "bank",
        "signin",
        "confirm",
        "wallet",
        "payment"
    ]

    found = [
        word for word in suspicious_words
        if word in lower_url
    ]

    if found:
        score += 10
        reasons.append(
            "Suspicious keywords: " + ", ".join(found)
        )

    if "xn--" in hostname.lower():
        score += 20
        reasons.append("Punycode domain detected")

    return min(score, 100), reasons


@app.get("/")
def home():
    return {
        "status": "online",
        "message": "PHISHGUARD API is running!"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "model": "XGBoost"
    }


@app.post("/predict")
def predict_url(request: URLRequest):

    url = request.url.strip()

    features = extract_features(url)

    probability = model.predict_proba(features)[0][1]

    ml_score = round(float(probability) * 100, 2)

    rule_score, reasons = analyze_rules(url)

    risk_score = round(
        (ml_score * 0.7) + (rule_score * 0.3),
        2
    )

    if risk_score >= 70:
        prediction = "Phishing"
    elif risk_score >= 40:
        prediction = "Suspicious"
    else:
        prediction = "Likely Safe"

    confidence = round(
        risk_score if prediction != "Likely Safe"
        else 100 - risk_score,
        2
    )

    if not reasons:
        reasons.append(
            "No major suspicious URL patterns detected"
        )

    return {
        "url": url,
        "prediction": prediction,
        "confidence": confidence,
        "risk_score": risk_score,
        "ml_score": ml_score,
        "rule_score": rule_score,
        "reasons": reasons
    }