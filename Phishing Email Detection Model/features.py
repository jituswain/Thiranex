"""
features.py
------------
Hand-engineered features that capture common phishing signals, used
alongside TF-IDF text features. These are combined with the raw text
using a scikit-learn Pipeline + FeatureUnion in model.py.
"""

import re
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin

URL_REGEX = re.compile(r"https?://[^\s)>\]]+", re.IGNORECASE)
IP_URL_REGEX = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}", re.IGNORECASE)
SHORTENER_DOMAINS = ("bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly")

SUSPICIOUS_KEYWORDS = [
    "urgent", "verify", "suspend", "suspended", "confirm", "click here",
    "act now", "immediately", "password", "update your", "account",
    "security alert", "limited time", "winner", "won", "prize", "claim",
    "bank", "credit card", "ssn", "social security", "login", "restricted",
    "unusual activity", "final notice", "expire", "expires", "reactivate",
]


def _count_occurrences(text, keywords):
    text_lower = text.lower()
    return sum(text_lower.count(k) for k in keywords)


class EmailFeatureExtractor(BaseEstimator, TransformerMixin):
    """
    Extracts numeric, hand-engineered features from raw email text:

      - num_urls: total count of URLs in the email
      - has_ip_url: whether any URL uses a raw IP address (classic phishing sign)
      - has_shortener: whether a known URL-shortening service is used
      - suspicious_keyword_count: count of urgency/credential-harvesting terms
      - num_exclamations: count of '!' characters
      - uppercase_ratio: fraction of alphabetic characters that are uppercase
      - text_length: total character length of the email
      - has_attachment_word: mentions of "attachment"/"attached" (weak signal)
      - num_dollar_signs: count of '$' characters (prize/money bait)
    """

    def fit(self, X, y=None):
        # No parameters are learned from data, but we set an attribute
        # so sklearn's check_is_fitted() recognizes this as "fitted".
        self.n_features_ = 9
        return self

    def transform(self, X):
        feats = []
        for text in X:
            text = text or ""
            urls = URL_REGEX.findall(text)
            num_urls = len(urls)
            has_ip_url = 1 if IP_URL_REGEX.search(text) else 0
            has_shortener = 1 if any(d in text for d in SHORTENER_DOMAINS) else 0
            suspicious_count = _count_occurrences(text, SUSPICIOUS_KEYWORDS)
            num_exclaim = text.count("!")
            letters = [c for c in text if c.isalpha()]
            uppercase_ratio = (
                sum(1 for c in letters if c.isupper()) / len(letters)
                if letters else 0.0
            )
            text_length = len(text)
            has_attachment_word = 1 if re.search(
                r"attach(ed|ment)", text, re.IGNORECASE) else 0
            num_dollar = text.count("$")

            feats.append([
                num_urls,
                has_ip_url,
                has_shortener,
                suspicious_count,
                num_exclaim,
                uppercase_ratio,
                text_length,
                has_attachment_word,
                num_dollar,
            ])
        return np.array(feats, dtype=float)

    def get_feature_names_out(self, input_features=None):
        return np.array([
            "num_urls", "has_ip_url", "has_shortener",
            "suspicious_keyword_count", "num_exclamations",
            "uppercase_ratio", "text_length", "has_attachment_word",
            "num_dollar_signs",
        ])
