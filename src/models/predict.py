from pathlib import Path
import json
from urllib.parse import urlparse

import joblib
import numpy as np
import pandas as pd

from src.features.url_features import extract_url_features


# ============================================================
# PROJECT PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

MODEL_PATH = (
    PROJECT_ROOT
    / "models"
    / "final_phishing_model.joblib"
)

METADATA_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "final_model_metadata.json"
)


# ============================================================
# VERIFY REQUIRED FILES
# ============================================================

if not MODEL_PATH.exists():
    raise FileNotFoundError(
        f"Final model not found: {MODEL_PATH}"
    )

if not METADATA_PATH.exists():
    raise FileNotFoundError(
        f"Model metadata not found: {METADATA_PATH}"
    )


# ============================================================
# LOAD MODEL METADATA
# ============================================================

with open(
    METADATA_PATH,
    "r",
    encoding="utf-8"
) as file:
    MODEL_METADATA = json.load(file)


FINAL_MODEL_NAME = MODEL_METADATA["model_name"]

FINAL_THRESHOLD = float(
    MODEL_METADATA["decision_threshold"]
)

FEATURE_COLUMNS = MODEL_METADATA["features"]

FEATURE_COUNT = int(
    MODEL_METADATA["feature_count"]
)


# ============================================================
# LOAD TRAINED MODEL
# ============================================================

FINAL_MODEL = joblib.load(
    MODEL_PATH
)


# ============================================================
# SAFETY CHECKS
# ============================================================

if FINAL_MODEL_NAME != "HistGradientBoosting":
    raise ValueError(
        f"Unexpected model: {FINAL_MODEL_NAME}"
    )

if FEATURE_COUNT != 22:
    raise ValueError(
        f"Expected 22 features, found {FEATURE_COUNT}"
    )

if len(FEATURE_COLUMNS) != FEATURE_COUNT:
    raise ValueError(
        "Feature metadata count does not match feature list."
    )

if FINAL_MODEL.n_features_in_ != FEATURE_COUNT:
    raise ValueError(
        "Saved model feature count does not match metadata."
    )


# ============================================================
# URL NORMALIZATION
# ============================================================

def normalize_input_url(url):
    """
    Normalize a user-entered URL for parsing.

    Example:
        google.com
    becomes:
        http://google.com
    """

    if url is None:
        raise ValueError("URL cannot be None.")

    url = str(url).strip()

    if not url:
        raise ValueError("URL cannot be empty.")

    if not url.startswith(
        ("http://", "https://")
    ):
        url = "http://" + url

    return url


# ============================================================
# BASIC URL VALIDATION
# ============================================================

def validate_url(url):
    """
    Perform basic structural validation.
    """

    normalized_url = normalize_input_url(url)

    parsed = urlparse(
        normalized_url
    )

    if not parsed.hostname:
        raise ValueError(
            "Invalid URL: hostname could not be identified."
        )

    return normalized_url


# ============================================================
# PREPARE MODEL FEATURES
# ============================================================

def prepare_features(url):
    """
    Convert one URL into the same 22 features
    used during model training.
    """

    normalized_url = validate_url(url)

    feature_dict = extract_url_features(
        normalized_url
    )

    missing_features = [
        feature
        for feature in FEATURE_COLUMNS
        if feature not in feature_dict
    ]

    if missing_features:
        raise ValueError(
            "Missing required features: "
            f"{missing_features}"
        )

    feature_df = pd.DataFrame(
        [
            {
                feature: feature_dict[feature]
                for feature in FEATURE_COLUMNS
            }
        ]
    )

    if feature_df.shape[1] != FEATURE_COUNT:
        raise ValueError(
            "Generated feature count does not match "
            "the trained model."
        )

    if feature_df.isnull().sum().sum() != 0:
        raise ValueError(
            "Generated features contain missing values."
        )

    if np.isinf(
        feature_df.to_numpy(
            dtype=float
        )
    ).any():
        raise ValueError(
            "Generated features contain infinite values."
        )

    return (
        normalized_url,
        feature_df
    )


# ============================================================
# PREDICT ONE URL
# ============================================================

def predict_url(url):
    """
    Predict whether a URL is phishing or legitimate.
    """

    original_url = str(url).strip()

    (
        normalized_url,
        feature_df
    ) = prepare_features(url)

    probabilities = FINAL_MODEL.predict_proba(
        feature_df
    )

    phishing_probability = float(
        probabilities[0, 1]
    )

    prediction = int(
        phishing_probability
        >= FINAL_THRESHOLD
    )

    if prediction == 1:
        label = "Phishing"
    else:
        label = "Legitimate"

    risk_score = (
        phishing_probability
        * 100
    )

    result = {
        "url": original_url,
        "normalized_url": normalized_url,
        "prediction": prediction,
        "label": label,
        "phishing_probability":
            phishing_probability,
        "risk_score":
            risk_score,
        "threshold":
            FINAL_THRESHOLD,
        "model":
            FINAL_MODEL_NAME
    }

    return result


# ============================================================
# PREDICT MULTIPLE URLS
# ============================================================

def predict_urls(urls):
    """
    Predict multiple URLs.
    """

    results = []

    for url in urls:

        try:
            result = predict_url(url)

        except Exception as error:
            result = {
                "url": url,
                "error": str(error)
            }

        results.append(
            result
        )

    return results


# ============================================================
# DISPLAY RESULT
# ============================================================

def print_prediction(result):
    """
    Print one prediction in readable form.
    """

    print("=" * 60)
    print("PHISHING URL DETECTION")
    print("=" * 60)

    if "error" in result:

        print(
            "URL:",
            result.get("url")
        )

        print(
            "ERROR:",
            result["error"]
        )

        return

    print(
        "Original URL :",
        result["url"]
    )

    print(
        "Normalized   :",
        result["normalized_url"]
    )

    print(
        "Model        :",
        result["model"]
    )

    print(
        "Prediction   :",
        result["label"]
    )

    print(
        "Risk Score   :",
        f"{result['risk_score']:.2f}%"
    )

    print(
        "Probability  :",
        f"{result['phishing_probability']:.6f}"
    )

    print(
        "Threshold    :",
        result["threshold"]
    )


# ============================================================
# MANUAL TESTS
# ============================================================

if __name__ == "__main__":

    print("\nMODEL CONFIGURATION")
    print("-" * 60)

    print(
        "Model:",
        FINAL_MODEL_NAME
    )

    print(
        "Threshold:",
        FINAL_THRESHOLD
    )

    print(
        "Features:",
        FEATURE_COUNT
    )

    print()

    test_urls = [
        "https://www.google.com",
        "https://github.com",
        "https://www.wikipedia.org",

        (
            "http://secure-login-verify.example/"
            "account/update"
        ),

        (
            "http://192.0.2.10/"
            "login/verify/account"
        ),

        (
            "http://paypal-security-check.example/"
            "verify"
        )
    ]

    for test_url in test_urls:

        try:
            result = predict_url(
                test_url
            )

            print_prediction(
                result
            )

        except Exception as error:

            print("=" * 60)

            print(
                "URL:",
                test_url
            )

            print(
                "ERROR:",
                error
            )

        print()