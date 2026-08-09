"""
model.py
--------
Trains a phishing email classifier combining:
  1. TF-IDF features over the raw email text
  2. Hand-engineered features (URL patterns, suspicious keywords, etc.)

Usage:
    python model.py

Outputs:
    - Printed accuracy, classification report
    - confusion_matrix.png
    - phishing_model.joblib  (trained pipeline, reusable for new emails)
"""

import os
import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")  # headless backend for saving plots to file
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    classification_report,
    ConfusionMatrixDisplay,
)

from features import EmailFeatureExtractor
from generate_dataset import generate_dataset

RANDOM_STATE = 42


class TextSelector(BaseEstimator, TransformerMixin):
    """Pass raw text straight through — used so TfidfVectorizer and
    EmailFeatureExtractor can both sit inside one FeatureUnion on the
    same input column."""
    def fit(self, X, y=None):
        self.fitted_ = True
        return self

    def transform(self, X):
        return X


def load_or_generate_dataset(csv_path="emails_dataset.csv"):
    if os.path.exists(csv_path):
        df = pd.read_csv(csv_path)
    else:
        df = generate_dataset()
        df.to_csv(csv_path, index=False)
    return df


def build_pipeline():
    """
    Combines TF-IDF text features with engineered numeric features,
    then feeds them into a RandomForestClassifier.
    """
    text_features = Pipeline([
        ("selector", TextSelector()),
        ("tfidf", TfidfVectorizer(
            max_features=3000,
            ngram_range=(1, 2),
            stop_words="english",
            min_df=2,
        )),
    ])

    engineered_features = Pipeline([
        ("extractor", EmailFeatureExtractor()),
    ])

    combined_features = FeatureUnion([
        ("text", text_features),
        ("engineered", engineered_features),
    ])

    pipeline = Pipeline([
        ("features", combined_features),
        ("clf", RandomForestClassifier(
            n_estimators=300,
            max_depth=None,
            random_state=RANDOM_STATE,
            n_jobs=-1,
            class_weight="balanced",
        )),
    ])
    return pipeline


def plot_confusion_matrix(y_test, y_pred, labels, out_path="confusion_matrix.png"):
    cm = confusion_matrix(y_test, y_pred, labels=labels)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=labels)
    fig, ax = plt.subplots(figsize=(5, 5))
    disp.plot(ax=ax, cmap="Blues", colorbar=False)
    ax.set_title("Phishing Detection — Confusion Matrix")
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close(fig)
    return cm


def main():
    print("Loading dataset...")
    df = load_or_generate_dataset()
    print(f"Dataset size: {len(df)}  |  Class balance:\n{df['label'].value_counts()}\n")

    X = df["text"].values
    y = df["label"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=RANDOM_STATE, stratify=y
    )

    print("Building and training pipeline (TF-IDF + engineered features + RandomForest)...")
    pipeline = build_pipeline()
    pipeline.fit(X_train, y_train)

    print("Evaluating on held-out test set...")
    y_pred = pipeline.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    print(f"\nAccuracy: {acc:.4f}\n")
    print("Classification Report:")
    print(classification_report(y_test, y_pred, digits=3))

    labels = sorted(df["label"].unique())
    cm = plot_confusion_matrix(y_test, y_pred, labels)
    print(f"Confusion Matrix (rows=true, cols=predicted), labels={labels}:")
    print(cm)
    print("\nSaved confusion matrix plot -> confusion_matrix.png")

    joblib.dump(pipeline, "phishing_model.joblib")
    print("Saved trained model -> phishing_model.joblib")

    # ---- Quick demo on a few new, unseen example emails ----
    demo_emails = [
        "Subject: Verify your account now\n\nDear customer, we detected "
        "suspicious login attempts. Click http://192.168.1.5/verify "
        "immediately to avoid permanent suspension of your account!!!",

        "Subject: Team lunch Friday\n\nHi everyone, let's grab lunch this "
        "Friday at noon near the office. Let me know if you can make it.",

        "Subject: Your Amazon package update\n\nYour package could not be "
        "delivered. Click http://amaz0n-support.net/redeliver and confirm "
        "your payment details within 24 hours.",
    ]
    demo_preds = pipeline.predict(demo_emails)
    demo_proba = pipeline.predict_proba(demo_emails)
    print("\n--- Demo predictions on new emails ---")
    for email, pred, proba in zip(demo_emails, demo_preds, demo_proba):
        subject_line = email.split("\n")[0]
        confidence = max(proba)
        label_str = "🚨 PHISHING" if pred == "phishing" else "✅ SAFE"
        print(f"{subject_line}  ->  {label_str}  (confidence: {confidence:.2%})")


if __name__ == "__main__":
    main()
