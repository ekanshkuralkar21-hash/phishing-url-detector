from fastapi import FastAPI
from pydantic import BaseModel
from urllib.parse import urlparse

app = FastAPI(title="Phishing URL Detection API")


class URLRequest(BaseModel):
    url: str


@app.get("/")
def home():
    return {
        "message": "Phishing Detection API is running!"
    }


@app.post("/predict")
def predict_url(request: URLRequest):
    url = request.url
    parsed = urlparse(url)

    suspicious = False
    reasons = []

    # Check HTTPS
    if parsed.scheme != "https":
        suspicious = True
        reasons.append("URL does not use HTTPS")

    # Check IP address in URL
    if parsed.hostname:
        parts = parsed.hostname.split(".")
        if len(parts) == 4 and all(part.isdigit() for part in parts):
            suspicious = True
            reasons.append("URL uses an IP address")

    # Check suspicious @ symbol
    if "@" in url:
        suspicious = True
        reasons.append("URL contains @ symbol")

    # Check very long URL
    if len(url) > 100:
        suspicious = True
        reasons.append("URL is unusually long")

    if suspicious:
        prediction = "Phishing"
        confidence = 85
    else:
        prediction = "Likely Safe"
        confidence = 90

    return {
        "url": url,
        "prediction": prediction,
        "confidence": confidence,
        "reasons": reasons
    }