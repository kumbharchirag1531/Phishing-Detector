from flask import Flask, render_template, request, jsonify
import joblib

from url_utils import normalize_url
from legit_domains import TOP_LEGIT_DOMAINS

app = Flask(__name__)

LEGIT_DOMAIN_SET = set(TOP_LEGIT_DOMAINS)


def extract_domain(normalized_url):
    """normalized_url has no scheme/www already (see normalize_url)."""
    return normalized_url.split("/")[0]

model = joblib.load("phishing_model.pkl")


def get_reasons(url):

    reasons = []

    if len(url) > 60:
        reasons.append("URL is unusually long")

    if url.count("-") > 2:
        reasons.append("Contains multiple hyphens")

    if "@" in url:
        reasons.append("@ symbol detected")

    if not url.startswith("https://"):
        reasons.append("HTTPS not used")

    if url.count(".") > 4:
        reasons.append("Contains many subdomains")

    suspicious_words = [
        "login",
        "verify",
        "secure",
        "update",
        "account",
        "banking",
        "confirm"
    ]

    for word in suspicious_words:
        if word in url.lower():
            reasons.append(
                f"Contains suspicious keyword: {word}"
            )

    return reasons


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():

    url = request.form.get("url")

    if not url:
        return jsonify({
            "error": "URL required"
        })

    normalized = normalize_url(url)
    domain = extract_domain(normalized)

    if domain in LEGIT_DOMAIN_SET:
        # Known-legitimate domain: trust the allow-list over the model.
        prediction = 0
        confidence = 0.98
    else:
        prediction = model.predict([normalized])[0]
        confidence = max(
            model.predict_proba([normalized])[0]
        )

    if prediction == 1:
        risk_score = int(confidence * 100)
    else:
        risk_score = int((1 - confidence) * 100)

    reasons = get_reasons(url)

    return jsonify({
        "prediction": int(prediction),
        "confidence": round(confidence * 100, 2),
        "risk_score": risk_score,
        "reasons": reasons
    })


if __name__ == "__main__":
    app.run(debug=False)
