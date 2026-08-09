"""
predict_email.py
-----------------
Loads the trained model (phishing_model.joblib) and classifies new,
unseen email text as "phishing" or "safe".

Usage:
    python predict_email.py                # runs built-in examples
    python predict_email.py "email text..."  # classify your own text
"""

import sys
import joblib
from features import EmailFeatureExtractor  # noqa: F401 (needed for unpickling)
from model import TextSelector  # noqa: F401 (needed for unpickling)

MODEL_PATH = "phishing_model.joblib"


def classify(email_text: str, model):
    pred = model.predict([email_text])[0]
    proba = model.predict_proba([email_text])[0]
    classes = list(model.classes_)
    confidence = proba[classes.index(pred)]
    return pred, confidence


def main():
    model = joblib.load(MODEL_PATH)

    if len(sys.argv) > 1:
        email_text = " ".join(sys.argv[1:])
        pred, conf = classify(email_text, model)
        label = "🚨 PHISHING" if pred == "phishing" else "✅ SAFE"
        print(f"{label}  (confidence: {conf:.2%})")
        return

    examples = [
        "Subject: Bank Account Locked\n\nDear customer, your account has "
        "been locked due to suspicious activity. Verify now at "
        "http://secure-bank-alert.info/login or lose access permanently.",

        "Subject: Weekly sync notes\n\nHi team, attaching notes from "
        "today's sync. Let's follow up on the open items next week.",

        "Subject: Update your payment method\n\nYour subscription payment "
        "failed. Click http://bit.ly/renewnow to update your card details "
        "within 24 hours to avoid cancellation.",
    ]
    for email in examples:
        pred, conf = classify(email, model)
        label = "🚨 PHISHING" if pred == "phishing" else "✅ SAFE"
        print(f"{email.splitlines()[0]:45s} -> {label} ({conf:.2%})")


if __name__ == "__main__":
    main()
