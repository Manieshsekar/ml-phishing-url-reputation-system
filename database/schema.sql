PRAGMA foreign_keys = ON;


-- ============================================================
-- URL REPUTATION TABLE
-- ============================================================

CREATE TABLE IF NOT EXISTS url_reputation (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    normalized_url TEXT NOT NULL UNIQUE,

    hostname TEXT NOT NULL,

    verified_label TEXT
        CHECK (
            verified_label IN (
                'legitimate',
                'phishing'
            )
            OR verified_label IS NULL
        ),

    verification_source TEXT,

    verification_notes TEXT,

    model_label TEXT
        CHECK (
            model_label IN (
                'Legitimate',
                'Phishing'
            )
            OR model_label IS NULL
        ),

    phishing_probability REAL
        CHECK (
            phishing_probability
            BETWEEN 0.0 AND 1.0
            OR phishing_probability IS NULL
        ),

    risk_score REAL
        CHECK (
            risk_score
            BETWEEN 0.0 AND 100.0
            OR risk_score IS NULL
        ),

    decision_threshold REAL,

    model_name TEXT,

    scan_count INTEGER
        NOT NULL
        DEFAULT 0,

    first_seen TEXT
        NOT NULL
        DEFAULT CURRENT_TIMESTAMP,

    last_seen TEXT
        NOT NULL
        DEFAULT CURRENT_TIMESTAMP
);


-- ============================================================
-- SCAN HISTORY TABLE
-- ============================================================

CREATE TABLE IF NOT EXISTS scan_history (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    reputation_id INTEGER,

    input_url TEXT NOT NULL,

    normalized_url TEXT NOT NULL,

    hostname TEXT NOT NULL,

    final_label TEXT NOT NULL
        CHECK (
            final_label IN (
                'Legitimate',
                'Phishing'
            )
        ),

    result_source TEXT NOT NULL
        CHECK (
            result_source IN (
                'ml_model',
                'verified_reputation'
            )
        ),

    phishing_probability REAL,

    risk_score REAL,

    decision_threshold REAL,

    model_name TEXT,

    scanned_at TEXT
        NOT NULL
        DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (reputation_id)
        REFERENCES url_reputation(id)
        ON DELETE SET NULL
);


-- ============================================================
-- INDEXES
-- ============================================================

CREATE INDEX IF NOT EXISTS
idx_url_reputation_hostname
ON url_reputation(hostname);


CREATE INDEX IF NOT EXISTS
idx_scan_history_normalized_url
ON scan_history(normalized_url);


CREATE INDEX IF NOT EXISTS
idx_scan_history_hostname
ON scan_history(hostname);


CREATE INDEX IF NOT EXISTS
idx_scan_history_scanned_at
ON scan_history(scanned_at);