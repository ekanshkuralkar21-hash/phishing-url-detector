from fastapi import FastAPI
from pydantic import BaseModel
from urllib.parse import urlparse
import re

app = FastAPI(title="Phishing URL Detection API")


class URLRequest(BaseModel):
    url: str


def analyze_url(url: str):
    score = 0
    reasons = []

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    # 1. HTTPS check
    if parsed.scheme != "https":
        score += 20
        reasons.append("URL does not use HTTPS")

    # 2. IP address check
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    if re.match(ip_pattern, hostname):
        score += 30
        reasons.append("URL uses an IP address instead of a domain")

    # 3. @ symbol check
    if "@" in url:
        score += 25
        reasons.append("URL contains @ symbol")

    # 4. Long URL check
    if len(url) > 100:
        score += 15
        reasons.append("URL is unusually long")

    # 5. Too many subdomains
    if hostname.count(".") >= 3:
        score += 15
        reasons.append("URL contains many subdomains")

    # 6. Suspicious keywords
    suspicious_words = [
        "login",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "password",
        "bank",
        "signin"
    ]

    found_words = []

    for word in suspicious_words:
        if word in url.lower():
            found_words.append(word)

    if found_words:
        score += 10
        reasons.append(
            "Suspicious keywords found: "
            + ", ".join(found_words)
        )

    # Maximum score = 100
    score = min(score, 100)

    if score >= 40:
        prediction = "Phishing"
        confidence = score
    else:
        prediction = "Likely Safe"
        confidence = 100 - score

    return prediction, confidence, score, reasons


@app.get("/")
def home():
    return {
        "message": "Phishing Detection API is running!"
    }


@app.post("/predict")
def predict_url(request: URLRequest):

    prediction, confidence, risk_score, reasons = analyze_url(
        request.url
    )

    return {
        "url": request.url,
        "prediction": prediction,
        "confidence": confidence,
        "risk_score": risk_score,
        "reasons": reasons
    }