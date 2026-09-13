import sqlite3

from src.database.db_manager import (
    initialize_database,
    get_reputation,
    get_scan_history,
    get_database_stats,
)

from src.database.reputation_service import (
    scan_url,
    verify_url,
    remove_verification,
)


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def test_database_initialization(
    tmp_path
):

    db_path = (
        tmp_path
        / "test_reputation.db"
    )

    initialize_database(
        db_path
    )

    assert db_path.exists()

    connection = sqlite3.connect(
        db_path
    )

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type='table'
        """
    )

    tables = {
        row[0]
        for row in cursor.fetchall()
    }

    connection.close()

    assert (
        "url_reputation"
        in tables
    )

    assert (
        "scan_history"
        in tables
    )


# ============================================================
# ML SCAN IS SAVED
# ============================================================

def test_ml_scan_saved_to_database(
    tmp_path
):

    db_path = (
        tmp_path
        / "test_reputation.db"
    )

    result = scan_url(
        "https://www.google.com",
        db_path=db_path
    )

    assert (
        result["source"]
        == "ml_model"
    )

    assert (
        result["verified"]
        is False
    )

    reputation = get_reputation(
        result[
            "normalized_url"
        ],
        db_path
    )

    assert reputation is not None

    assert (
        reputation[
            "model_label"
        ]
        in {
            "Legitimate",
            "Phishing",
        }
    )


# ============================================================
# SCAN HISTORY TEST
# ============================================================

def test_scan_history_saved(
    tmp_path
):

    db_path = (
        tmp_path
        / "test_reputation.db"
    )

    scan_url(
        "https://www.google.com",
        db_path=db_path
    )

    scan_url(
        "https://www.wikipedia.org",
        db_path=db_path
    )

    history = get_scan_history(
        limit=10,
        db_path=db_path
    )

    assert len(history) == 2


# ============================================================
# VERIFIED REPUTATION OVERRIDE
# ============================================================

def test_verified_reputation_override(
    tmp_path
):

    db_path = (
        tmp_path
        / "test_reputation.db"
    )

    test_url = (
        "https://trusted-demo.example"
    )

    verify_url(
        test_url,
        label="legitimate",
        source="unit_test",
        notes=
            "Trusted test URL",
        db_path=db_path
    )

    result = scan_url(
        test_url,
        db_path=db_path
    )

    assert (
        result["source"]
        == "verified_reputation"
    )

    assert (
        result["verified"]
        is True
    )

    assert (
        result["label"]
        == "Legitimate"
    )


# ============================================================
# REMOVE VERIFIED OVERRIDE
# ============================================================

def test_remove_verification(
    tmp_path
):

    db_path = (
        tmp_path
        / "test_reputation.db"
    )

    test_url = (
        "https://trusted-demo.example"
    )

    verify_url(
        test_url,
        label="legitimate",
        source="unit_test",
        db_path=db_path
    )

    remove_verification(
        test_url,
        db_path=db_path
    )

    result = scan_url(
        test_url,
        db_path=db_path
    )

    assert (
        result["source"]
        == "ml_model"
    )

    assert (
        result["verified"]
        is False
    )


# ============================================================
# DATABASE STATISTICS
# ============================================================

def test_database_statistics(
    tmp_path
):

    db_path = (
        tmp_path
        / "test_reputation.db"
    )

    scan_url(
        "https://www.google.com",
        db_path=db_path
    )

    scan_url(
        "https://www.wikipedia.org",
        db_path=db_path
    )

    stats = get_database_stats(
        db_path
    )

    assert (
        stats["total_urls"]
        == 2
    )

    assert (
        stats["total_scans"]
        == 2
    )