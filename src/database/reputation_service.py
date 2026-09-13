from urllib.parse import urlparse

from src.models.predict import (
    predict_url,
    validate_url,
)

from src.database.db_manager import (
    DEFAULT_DB_PATH,
    initialize_database,
    get_reputation,
    upsert_model_reputation,
    increment_scan_count,
    set_verified_reputation,
    clear_verified_reputation,
    log_scan,
    get_scan_history,
    get_database_stats,
)


# ============================================================
# HELPER — GET HOSTNAME
# ============================================================

def get_hostname(
    normalized_url
):
    """
    Extract lowercase hostname from a normalized URL.
    """

    parsed = urlparse(
        normalized_url
    )

    hostname = (
        parsed.hostname
        or ""
    ).lower()

    if not hostname:
        raise ValueError(
            "Unable to determine URL hostname."
        )

    return hostname


# ============================================================
# MAIN SQL-BACKED URL SCAN
# ============================================================

def scan_url(
    url,
    db_path=DEFAULT_DB_PATH
):
    """
    Scan one URL using:

    1. SQL verified reputation lookup
    2. ML inference if no verified result exists
    3. SQL reputation update
    4. Scan-history logging
    """

    initialize_database(
        db_path
    )

    original_url = str(
        url
    ).strip()

    normalized_url = validate_url(
        url
    )

    hostname = get_hostname(
        normalized_url
    )

    reputation = get_reputation(
        normalized_url,
        db_path
    )

    # ========================================================
    # VERIFIED REPUTATION PATH
    # ========================================================

    if (
        reputation is not None
        and
        reputation["verified_label"]
        is not None
    ):

        verified_label = (
            reputation[
                "verified_label"
            ]
        )

        if verified_label == "phishing":
            final_label = "Phishing"
        else:
            final_label = "Legitimate"

        increment_scan_count(
            normalized_url,
            db_path
        )

        log_scan(
            input_url=original_url,
            normalized_url=normalized_url,
            hostname=hostname,
            final_label=final_label,
            result_source=
                "verified_reputation",
            phishing_probability=
                reputation[
                    "phishing_probability"
                ],
            risk_score=
                reputation[
                    "risk_score"
                ],
            decision_threshold=
                reputation[
                    "decision_threshold"
                ],
            model_name=
                reputation[
                    "model_name"
                ],
            db_path=db_path,
        )

        return {
            "url":
                original_url,

            "normalized_url":
                normalized_url,

            "hostname":
                hostname,

            "label":
                final_label,

            "source":
                "verified_reputation",

            "verified":
                True,

            "verification_source":
                reputation[
                    "verification_source"
                ],

            "verification_notes":
                reputation[
                    "verification_notes"
                ],

            "phishing_probability":
                reputation[
                    "phishing_probability"
                ],

            "risk_score":
                reputation[
                    "risk_score"
                ],

            "threshold":
                reputation[
                    "decision_threshold"
                ],

            "model":
                reputation[
                    "model_name"
                ],
        }

    # ========================================================
    # ML INFERENCE PATH
    # ========================================================

    ml_result = predict_url(
        url
    )

    upsert_model_reputation(
        normalized_url=
            ml_result[
                "normalized_url"
            ],

        hostname=
            hostname,

        model_label=
            ml_result[
                "label"
            ],

        phishing_probability=
            ml_result[
                "phishing_probability"
            ],

        risk_score=
            ml_result[
                "risk_score"
            ],

        decision_threshold=
            ml_result[
                "threshold"
            ],

        model_name=
            ml_result[
                "model"
            ],

        db_path=
            db_path,
    )

    log_scan(
        input_url=
            original_url,

        normalized_url=
            ml_result[
                "normalized_url"
            ],

        hostname=
            hostname,

        final_label=
            ml_result[
                "label"
            ],

        result_source=
            "ml_model",

        phishing_probability=
            ml_result[
                "phishing_probability"
            ],

        risk_score=
            ml_result[
                "risk_score"
            ],

        decision_threshold=
            ml_result[
                "threshold"
            ],

        model_name=
            ml_result[
                "model"
            ],

        db_path=
            db_path,
    )

    return {
        **ml_result,

        "hostname":
            hostname,

        "source":
            "ml_model",

        "verified":
            False,
    }


# ============================================================
# VERIFY A URL
# ============================================================

def verify_url(
    url,
    label,
    source="manual_verification",
    notes=None,
    db_path=DEFAULT_DB_PATH
):
    """
    Add trusted reputation information for a URL.
    """

    initialize_database(
        db_path
    )

    normalized_url = validate_url(
        url
    )

    hostname = get_hostname(
        normalized_url
    )

    set_verified_reputation(
        normalized_url=
            normalized_url,

        hostname=
            hostname,

        verified_label=
            label,

        verification_source=
            source,

        verification_notes=
            notes,

        db_path=
            db_path,
    )

    return get_reputation(
        normalized_url,
        db_path
    )


# ============================================================
# REMOVE VERIFIED OVERRIDE
# ============================================================

def remove_verification(
    url,
    db_path=DEFAULT_DB_PATH
):
    """
    Remove trusted override for one URL.
    """

    initialize_database(
        db_path
    )

    normalized_url = validate_url(
        url
    )

    clear_verified_reputation(
        normalized_url,
        db_path
    )


# ============================================================
# DISPLAY SCAN RESULT
# ============================================================

def print_scan_result(
    result
):
    """
    Display SQL-backed scan result.
    """

    print("=" * 65)
    print(
        "SQL-BACKED PHISHING URL REPUTATION SYSTEM"
    )
    print("=" * 65)

    print(
        "URL        :",
        result[
            "normalized_url"
        ]
    )

    print(
        "Hostname   :",
        result[
            "hostname"
        ]
    )

    print(
        "Prediction :",
        result[
            "label"
        ]
    )

    print(
        "Source     :",
        result[
            "source"
        ]
    )

    print(
        "Verified   :",
        result[
            "verified"
        ]
    )

    probability = result.get(
        "phishing_probability"
    )

    risk_score = result.get(
        "risk_score"
    )

    if probability is not None:

        print(
            "Probability:",
            f"{probability:.6f}"
        )

    if risk_score is not None:

        print(
            "Risk Score :",
            f"{risk_score:.2f}%"
        )

    threshold = result.get(
        "threshold"
    )

    if threshold is not None:

        print(
            "Threshold  :",
            threshold
        )


# ============================================================
# MANUAL PHASE 8 TEST
# ============================================================

if __name__ == "__main__":

    initialize_database()

    test_urls = [
        "https://www.google.com",
        "https://www.wikipedia.org",
        (
            "http://secure-login-verify.example/"
            "account/update"
        ),
    ]

    for test_url in test_urls:

        result = scan_url(
            test_url
        )

        print_scan_result(
            result
        )

        print()

    print("=" * 65)
    print("DATABASE STATISTICS")
    print("=" * 65)

    stats = get_database_stats()

    for key, value in stats.items():

        print(
            f"{key}: {value}"
        )

    print()

    print("=" * 65)
    print("LATEST SCAN HISTORY")
    print("=" * 65)

    history = get_scan_history(
        limit=5
    )

    for record in history:

        print(record)