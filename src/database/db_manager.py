from pathlib import Path
import sqlite3


# ============================================================
# PROJECT PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATABASE_DIR = (
    PROJECT_ROOT
    / "database"
)

DEFAULT_DB_PATH = (
    DATABASE_DIR
    / "phishing_reputation.db"
)

SCHEMA_PATH = (
    DATABASE_DIR
    / "schema.sql"
)


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_connection(
    db_path=DEFAULT_DB_PATH
):
    """
    Create and return a SQLite database connection.
    """

    db_path = Path(db_path)

    db_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    connection = sqlite3.connect(
        db_path
    )

    connection.row_factory = (
        sqlite3.Row
    )

    connection.execute(
        "PRAGMA foreign_keys = ON;"
    )

    return connection


# ============================================================
# INITIALIZE DATABASE
# ============================================================

def initialize_database(
    db_path=DEFAULT_DB_PATH
):
    """
    Create database tables using schema.sql.
    """

    if not SCHEMA_PATH.exists():
        raise FileNotFoundError(
            f"Database schema not found: "
            f"{SCHEMA_PATH}"
        )

    with open(
        SCHEMA_PATH,
        "r",
        encoding="utf-8"
    ) as file:
        schema = file.read()

    connection = get_connection(
        db_path
    )

    try:

        connection.executescript(
            schema
        )

        connection.commit()

    finally:

        connection.close()


# ============================================================
# GET URL REPUTATION
# ============================================================

def get_reputation(
    normalized_url,
    db_path=DEFAULT_DB_PATH
):
    """
    Retrieve the reputation record for one URL.
    """

    connection = get_connection(
        db_path
    )

    try:

        cursor = connection.execute(
            """
            SELECT *
            FROM url_reputation
            WHERE normalized_url = ?
            """,
            (
                normalized_url,
            )
        )

        row = cursor.fetchone()

        if row is None:
            return None

        return dict(row)

    finally:

        connection.close()


# ============================================================
# SAVE / UPDATE MODEL REPUTATION
# ============================================================

def upsert_model_reputation(
    normalized_url,
    hostname,
    model_label,
    phishing_probability,
    risk_score,
    decision_threshold,
    model_name,
    db_path=DEFAULT_DB_PATH
):
    """
    Insert a new URL reputation record or update
    the latest ML result for an existing URL.
    """

    connection = get_connection(
        db_path
    )

    try:

        connection.execute(
            """
            INSERT INTO url_reputation (
                normalized_url,
                hostname,
                model_label,
                phishing_probability,
                risk_score,
                decision_threshold,
                model_name,
                scan_count
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, 1)

            ON CONFLICT(normalized_url)
            DO UPDATE SET

                hostname =
                    excluded.hostname,

                model_label =
                    excluded.model_label,

                phishing_probability =
                    excluded.phishing_probability,

                risk_score =
                    excluded.risk_score,

                decision_threshold =
                    excluded.decision_threshold,

                model_name =
                    excluded.model_name,

                scan_count =
                    url_reputation.scan_count + 1,

                last_seen =
                    CURRENT_TIMESTAMP
            """,
            (
                normalized_url,
                hostname,
                model_label,
                phishing_probability,
                risk_score,
                decision_threshold,
                model_name,
            )
        )

        connection.commit()

    finally:

        connection.close()


# ============================================================
# TOUCH VERIFIED REPUTATION
# ============================================================

def increment_scan_count(
    normalized_url,
    db_path=DEFAULT_DB_PATH
):
    """
    Increment scan count for a known verified URL.
    """

    connection = get_connection(
        db_path
    )

    try:

        connection.execute(
            """
            UPDATE url_reputation
            SET
                scan_count = scan_count + 1,
                last_seen = CURRENT_TIMESTAMP
            WHERE normalized_url = ?
            """,
            (
                normalized_url,
            )
        )

        connection.commit()

    finally:

        connection.close()


# ============================================================
# SET VERIFIED REPUTATION
# ============================================================

def set_verified_reputation(
    normalized_url,
    hostname,
    verified_label,
    verification_source,
    verification_notes=None,
    db_path=DEFAULT_DB_PATH
):
    """
    Set a trusted human/external verified reputation.

    verified_label must be:
        legitimate
        phishing
    """

    verified_label = (
        str(verified_label)
        .strip()
        .lower()
    )

    if verified_label not in {
        "legitimate",
        "phishing",
    }:
        raise ValueError(
            "verified_label must be "
            "'legitimate' or 'phishing'."
        )

    connection = get_connection(
        db_path
    )

    try:

        connection.execute(
            """
            INSERT INTO url_reputation (
                normalized_url,
                hostname,
                verified_label,
                verification_source,
                verification_notes
            )

            VALUES (?, ?, ?, ?, ?)

            ON CONFLICT(normalized_url)
            DO UPDATE SET

                hostname =
                    excluded.hostname,

                verified_label =
                    excluded.verified_label,

                verification_source =
                    excluded.verification_source,

                verification_notes =
                    excluded.verification_notes,

                last_seen =
                    CURRENT_TIMESTAMP
            """,
            (
                normalized_url,
                hostname,
                verified_label,
                verification_source,
                verification_notes,
            )
        )

        connection.commit()

    finally:

        connection.close()


# ============================================================
# CLEAR VERIFIED REPUTATION
# ============================================================

def clear_verified_reputation(
    normalized_url,
    db_path=DEFAULT_DB_PATH
):
    """
    Remove verified reputation without deleting
    the URL's ML reputation/history.
    """

    connection = get_connection(
        db_path
    )

    try:

        connection.execute(
            """
            UPDATE url_reputation
            SET
                verified_label = NULL,
                verification_source = NULL,
                verification_notes = NULL,
                last_seen = CURRENT_TIMESTAMP
            WHERE normalized_url = ?
            """,
            (
                normalized_url,
            )
        )

        connection.commit()

    finally:

        connection.close()


# ============================================================
# LOG SCAN
# ============================================================

def log_scan(
    input_url,
    normalized_url,
    hostname,
    final_label,
    result_source,
    phishing_probability=None,
    risk_score=None,
    decision_threshold=None,
    model_name=None,
    db_path=DEFAULT_DB_PATH
):
    """
    Store one scan event in scan_history.
    """

    reputation = get_reputation(
        normalized_url,
        db_path
    )

    reputation_id = None

    if reputation is not None:
        reputation_id = reputation["id"]

    connection = get_connection(
        db_path
    )

    try:

        connection.execute(
            """
            INSERT INTO scan_history (
                reputation_id,
                input_url,
                normalized_url,
                hostname,
                final_label,
                result_source,
                phishing_probability,
                risk_score,
                decision_threshold,
                model_name
            )

            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                reputation_id,
                input_url,
                normalized_url,
                hostname,
                final_label,
                result_source,
                phishing_probability,
                risk_score,
                decision_threshold,
                model_name,
            )
        )

        connection.commit()

    finally:

        connection.close()


# ============================================================
# GET SCAN HISTORY
# ============================================================

def get_scan_history(
    limit=100,
    db_path=DEFAULT_DB_PATH
):
    """
    Return the latest scan history.
    """

    connection = get_connection(
        db_path
    )

    try:

        cursor = connection.execute(
            """
            SELECT *
            FROM scan_history
            ORDER BY id DESC
            LIMIT ?
            """,
            (
                int(limit),
            )
        )

        rows = cursor.fetchall()

        return [
            dict(row)
            for row in rows
        ]

    finally:

        connection.close()


# ============================================================
# DATABASE STATISTICS
# ============================================================

def get_database_stats(
    db_path=DEFAULT_DB_PATH
):
    """
    Return basic database statistics.
    """

    connection = get_connection(
        db_path
    )

    try:

        total_urls = connection.execute(
            """
            SELECT COUNT(*)
            FROM url_reputation
            """
        ).fetchone()[0]

        total_scans = connection.execute(
            """
            SELECT COUNT(*)
            FROM scan_history
            """
        ).fetchone()[0]

        verified_urls = connection.execute(
            """
            SELECT COUNT(*)
            FROM url_reputation
            WHERE verified_label IS NOT NULL
            """
        ).fetchone()[0]

        phishing_results = connection.execute(
            """
            SELECT COUNT(*)
            FROM scan_history
            WHERE final_label = 'Phishing'
            """
        ).fetchone()[0]

        legitimate_results = connection.execute(
            """
            SELECT COUNT(*)
            FROM scan_history
            WHERE final_label = 'Legitimate'
            """
        ).fetchone()[0]

        return {
            "total_urls": total_urls,
            "total_scans": total_scans,
            "verified_urls": verified_urls,
            "phishing_results":
                phishing_results,
            "legitimate_results":
                legitimate_results,
        }

    finally:

        connection.close()