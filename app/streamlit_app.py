import sys
from pathlib import Path

import pandas as pd
import streamlit as st


# ============================================================
# PROJECT ROOT
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(PROJECT_ROOT)
    )


# ============================================================
# PROJECT IMPORTS
# ============================================================

from src.database.reputation_service import (
    scan_url,
)

from src.database.db_manager import (
    initialize_database,
    get_scan_history,
    get_database_stats,
)


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title=
        "Phishing URL Reputation System",

    page_icon=
        "🛡️",

    layout=
        "wide",

    initial_sidebar_state=
        "expanded",
)


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

initialize_database()


# ============================================================
# SESSION STATE
# ============================================================

if "last_result" not in st.session_state:
    st.session_state.last_result = None

if "last_url" not in st.session_state:
    st.session_state.last_url = ""


# ============================================================
# HEADER
# ============================================================

st.title(
    "🛡️ ML Phishing URL Reputation System"
)

st.caption(
    "SQL-backed phishing detection using "
    "deployment-safe URL features and "
    "machine learning."
)

st.divider()


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.header(
        "System Information"
    )

    st.write(
        "**ML Model:** "
        "HistGradientBoosting"
    )

    st.write(
        "**Decision Threshold:** "
        "0.14"
    )

    st.write(
        "**Features:** "
        "22 URL-based features"
    )

    st.write(
        "**Database:** "
        "SQLite"
    )

    st.write(
        "**Detection Mode:** "
        "URL-string analysis"
    )

    st.info(
        "The system analyzes the URL "
        "string itself and does not "
        "automatically visit the website."
    )


# ============================================================
# DATABASE STATISTICS
# ============================================================

stats = get_database_stats()

st.subheader(
    "📊 Database Overview"
)

col1, col2, col3, col4 = st.columns(
    4
)

with col1:
    st.metric(
        "Unique URLs",
        stats[
            "total_urls"
        ],
    )

with col2:
    st.metric(
        "Total Scans",
        stats[
            "total_scans"
        ],
    )

with col3:
    st.metric(
        "Verified URLs",
        stats[
            "verified_urls"
        ],
    )

with col4:
    st.metric(
        "Phishing Results",
        stats[
            "phishing_results"
        ],
    )

st.divider()


# ============================================================
# URL SCANNER
# ============================================================

st.subheader(
    "🔍 Scan a URL"
)

url_input = st.text_input(
    "Enter a URL",
    placeholder=
        "https://example.com/login",
    value=
        st.session_state.last_url,
)


scan_button = st.button(
    "Scan URL",
    type="primary",
    use_container_width=True,
)


# ============================================================
# SCAN ACTION
# ============================================================

if scan_button:

    if not url_input.strip():

        st.warning(
            "Please enter a URL "
            "before scanning."
        )

    else:

        try:

            with st.spinner(
                "Analyzing URL..."
            ):

                result = scan_url(
                    url_input
                )

            st.session_state.last_result = (
                result
            )

            st.session_state.last_url = (
                url_input
            )
            
            st.rerun()

        except Exception as error:

            st.session_state.last_result = (
                None
            )

            st.error(
                f"Scan failed: {error}"
            )


# ============================================================
# DISPLAY SCAN RESULT
# ============================================================

result = st.session_state.last_result

if result is not None:

    st.divider()

    st.subheader(
        "🧪 Scan Result"
    )

    label = result[
        "label"
    ]

    if label == "Phishing":

        st.error(
            "🚨 PHISHING DETECTED"
        )

    else:

        st.success(
            "✅ LEGITIMATE"
        )


    result_col1, result_col2 = (
        st.columns(
            2
        )
    )


    # ========================================================
    # LEFT RESULT COLUMN
    # ========================================================

    with result_col1:

        st.write(
            "**Normalized URL**"
        )

        st.code(
            result[
                "normalized_url"
            ]
        )

        st.write(
            "**Hostname:**",
            result[
                "hostname"
            ],
        )

        st.write(
            "**Result Source:**",
            result[
                "source"
            ],
        )

        st.write(
            "**Verified Reputation:**",
            "Yes"
            if result[
                "verified"
            ]
            else "No",
        )


    # ========================================================
    # RIGHT RESULT COLUMN
    # ========================================================

    with result_col2:

        probability = result.get(
            "phishing_probability"
        )

        risk_score = result.get(
            "risk_score"
        )

        threshold = result.get(
            "threshold"
        )

        model = result.get(
            "model"
        )


        if risk_score is not None:

            st.metric(
                "Risk Score",
                f"{risk_score:.2f}%"
            )


        if probability is not None:

            st.metric(
                "Phishing Probability",
                f"{probability:.6f}"
            )


        if threshold is not None:

            st.write(
                "**Threshold:**",
                threshold,
            )


        if model is not None:

            st.write(
                "**Model:**",
                model,
            )


    # ========================================================
    # VERIFIED SOURCE DETAILS
    # ========================================================

    if result[
        "verified"
    ]:

        st.info(
            "This result came from "
            "verified reputation data."
        )

        verification_source = (
            result.get(
                "verification_source"
            )
        )

        verification_notes = (
            result.get(
                "verification_notes"
            )
        )

        if verification_source:

            st.write(
                "**Verification Source:**",
                verification_source,
            )

        if verification_notes:

            st.write(
                "**Verification Notes:**",
                verification_notes,
            )

    else:

        st.caption(
            "This result was generated "
            "by the ML model because no "
            "verified reputation record "
            "was available."
        )


# ============================================================
# SCAN HISTORY
# ============================================================

st.divider()

st.subheader(
    "🕘 Recent Scan History"
)

history = get_scan_history(
    limit=20
)

if history:

    history_df = pd.DataFrame(
        history
    )

    history_columns = [
        "scanned_at",
        "normalized_url",
        "final_label",
        "result_source",
        "risk_score",
    ]

    available_columns = [
        column
        for column in history_columns
        if column in history_df.columns
    ]

    display_history = (
        history_df[
            available_columns
        ]
    )

    display_history = (
        display_history.rename(
            columns={
                "scanned_at":
                    "Scanned At",

                "normalized_url":
                    "URL",

                "final_label":
                    "Result",

                "result_source":
                    "Source",

                "risk_score":
                    "Risk Score",
            }
        )
    )

    st.dataframe(
        display_history,
        use_container_width=True,
        hide_index=True,
    )

else:

    st.info(
        "No scans have been recorded yet."
    )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "ML Phishing URL Reputation System | "
    "Final Year Project"
)