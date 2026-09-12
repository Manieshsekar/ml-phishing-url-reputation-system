import numpy as np
import pytest

from src.models.predict import (
    FINAL_MODEL_NAME,
    FINAL_THRESHOLD,
    FEATURE_COLUMNS,
    FEATURE_COUNT,
    normalize_input_url,
    validate_url,
    prepare_features,
    predict_url,
    predict_urls,
)


# ============================================================
# MODEL CONFIGURATION TESTS
# ============================================================

def test_final_model_name():
    assert FINAL_MODEL_NAME == "HistGradientBoosting"


def test_final_threshold():
    assert FINAL_THRESHOLD == 0.14


def test_feature_count():
    assert FEATURE_COUNT == 22
    assert len(FEATURE_COLUMNS) == 22


# ============================================================
# URL NORMALIZATION TESTS
# ============================================================

def test_normalize_url_with_https():

    url = "https://www.google.com"

    normalized = normalize_input_url(url)

    assert normalized == url


def test_normalize_url_without_scheme():

    url = "google.com"

    normalized = normalize_input_url(url)

    assert normalized == "http://google.com"


def test_normalize_url_removes_spaces():

    url = "   https://www.google.com   "

    normalized = normalize_input_url(url)

    assert normalized == "https://www.google.com"


# ============================================================
# INVALID INPUT TESTS
# ============================================================

def test_none_url():

    with pytest.raises(ValueError):
        normalize_input_url(None)


def test_empty_url():

    with pytest.raises(ValueError):
        normalize_input_url("")


def test_spaces_only_url():

    with pytest.raises(ValueError):
        normalize_input_url("     ")


# ============================================================
# FEATURE EXTRACTION TESTS
# ============================================================

def test_prepare_features():

    url = "https://www.google.com"

    normalized_url, feature_df = prepare_features(
        url
    )

    assert normalized_url == url

    assert feature_df.shape == (
        1,
        FEATURE_COUNT
    )

    assert list(
        feature_df.columns
    ) == FEATURE_COLUMNS


def test_features_have_no_missing_values():

    _, feature_df = prepare_features(
        "https://www.google.com"
    )

    assert (
        feature_df
        .isnull()
        .sum()
        .sum()
        == 0
    )


def test_features_have_no_infinity():

    _, feature_df = prepare_features(
        "https://www.google.com"
    )

    values = feature_df.to_numpy(
        dtype=float
    )

    assert not np.isinf(
        values
    ).any()


# ============================================================
# SINGLE PREDICTION TEST
# ============================================================

def test_predict_url():

    result = predict_url(
        "https://www.google.com"
    )

    required_keys = {
        "url",
        "normalized_url",
        "prediction",
        "label",
        "phishing_probability",
        "risk_score",
        "threshold",
        "model",
    }

    assert required_keys.issubset(
        result.keys()
    )

    assert result["prediction"] in [
        0,
        1
    ]

    assert result["label"] in [
        "Legitimate",
        "Phishing"
    ]

    assert (
        0.0
        <= result["phishing_probability"]
        <= 1.0
    )

    assert (
        0.0
        <= result["risk_score"]
        <= 100.0
    )

    assert (
        result["threshold"]
        == FINAL_THRESHOLD
    )

    assert (
        result["model"]
        == FINAL_MODEL_NAME
    )


# ============================================================
# THRESHOLD CONSISTENCY TEST
# ============================================================

def test_prediction_matches_threshold():

    result = predict_url(
        "https://www.google.com"
    )

    expected_prediction = int(
        result["phishing_probability"]
        >= FINAL_THRESHOLD
    )

    assert (
        result["prediction"]
        == expected_prediction
    )


# ============================================================
# BATCH PREDICTION TEST
# ============================================================

def test_batch_prediction():

    urls = [
        "https://www.google.com",
        "https://www.wikipedia.org",
        (
            "http://secure-login-verify.example/"
            "account/update"
        ),
    ]

    results = predict_urls(
        urls
    )

    assert len(results) == len(urls)

    for result in results:
        assert "url" in result


# ============================================================
# BATCH ERROR HANDLING TEST
# ============================================================

def test_batch_handles_invalid_url():

    urls = [
        "https://www.google.com",
        "",
    ]

    results = predict_urls(
        urls
    )

    assert len(results) == 2

    assert "error" not in results[0]

    assert "error" in results[1]