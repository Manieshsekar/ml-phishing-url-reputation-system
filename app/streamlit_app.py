import sys
from pathlib import Path

import pandas as pd
import streamlit as st


# ============================================================
# PROJECT PATH
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ============================================================
# PROJECT IMPORTS
# ============================================================

from src.database.reputation_service import scan_url

from src.database.db_manager import (
    initialize_database,
    get_database_stats,
    get_scan_history,
)


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="PhishGuard AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)


# ============================================================
# CSS
#
# IMPORTANT:
# This is the ONLY HTML used in the entire application.
# There are NO custom <div> blocks anywhere in the UI.
# ============================================================

st.markdown(
    """
<style>
    .stApp {
        background:
            radial-gradient(
                circle at 10% 0%,
                rgba(37, 99, 235, 0.16),
                transparent 28%
            ),
            linear-gradient(
                180deg,
                #07101d 0%,
                #091321 50%,
                #07101d 100%
            );
    }

    .block-container {
        max-width: 1250px;
        padding-top: 2rem;
        padding-bottom: 4rem;
    }

    h1, h2, h3 {
        color: #f8fbff !important;
    }

    p {
        color: #a7b4c7;
    }

    [data-testid="stMetric"] {
        background:
            linear-gradient(
                180deg,
                rgba(18, 31, 51, 0.95),
                rgba(11, 21, 36, 0.95)
            );

        border:
            1px solid rgba(255,255,255,0.08);

        border-radius: 18px;

        padding: 1rem 1.2rem;

        box-shadow:
            0 12px 30px rgba(0,0,0,0.15);
    }

    [data-testid="stMetricLabel"] {
        color: #8796ab;
    }

    [data-testid="stMetricValue"] {
        color: #ffffff;
        font-weight: 800;
    }

    [data-testid="stTextInput"] input {
        min-height: 50px;

        color: #f8fbff !important;

        background:
            #0c1728 !important;

        border-radius:
            14px !important;
    }

    .stButton > button {
        width: 100%;

        min-height: 50px;

        border-radius: 14px;

        border: none;

        background:
            linear-gradient(
                135deg,
                #2563eb,
                #60a5fa
            );

        color: white;

        font-weight: 800;

        box-shadow:
            0 12px 28px
            rgba(37, 99, 235, 0.25);
    }

    .stButton > button:hover {
        color: white;

        border: none;

        transform: translateY(-1px);
    }

    [data-testid="stDataFrame"] {
        border:
            1px solid rgba(255,255,255,0.08);

        border-radius: 16px;

        overflow: hidden;
    }

    [data-testid="stAlert"] {
        border-radius: 16px;
    }

    div[data-testid="stExpander"] {
        border:
            1px solid rgba(255,255,255,0.07);

        border-radius: 16px;

        background:
            rgba(15,26,43,0.55);
    }

    #MainMenu {
        visibility: hidden;
    }

    footer {
        visibility: hidden;
    }

    header {
        background: transparent !important;
    }
</style>
    """,
    unsafe_allow_html=True,
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

header_left, header_right = st.columns(
    [5, 1]
)

with header_left:

    st.title(
        "🛡️ PhishGuard AI"
    )

    st.caption(
        "SQL-Backed Machine Learning URL Reputation System"
    )


with header_right:

    st.success(
        "● System Online"
    )


# ============================================================
# HERO
# ============================================================

with st.container(
    border=True
):

    st.subheader(
        "Know before you click."
    )

    st.write(
        """
        Analyze suspicious URLs using machine learning and
        SQL-backed reputation intelligence without opening
        the submitted website.
        """
    )

    tag1, tag2, tag3, tag4 = st.columns(
        4
    )

    with tag1:

        st.caption(
            "🤖 HistGradientBoosting"
        )

    with tag2:

        st.caption(
            "🧬 22 URL Features"
        )

    with tag3:

        st.caption(
            "🗄️ SQL Reputation"
        )

    with tag4:

        st.caption(
            "🔒 No Site Visit"
        )


st.write("")


# ============================================================
# DATABASE OVERVIEW
# ============================================================

stats = get_database_stats()

metric1, metric2, metric3, metric4 = st.columns(
    4
)


with metric1:

    st.metric(
        "URLs Analyzed",
        stats["total_urls"],
    )


with metric2:

    st.metric(
        "Total Scans",
        stats["total_scans"],
    )


with metric3:

    st.metric(
        "Verified URLs",
        stats["verified_urls"],
    )


with metric4:

    st.metric(
        "Threat Detections",
        stats["phishing_results"],
    )


st.write("")


# ============================================================
# MAIN TABS
# ============================================================

scanner_tab, history_tab = st.tabs(
    [
        "🔍 URL Scanner",
        "📊 History & System",
    ]
)


# ============================================================
# URL SCANNER TAB
# ============================================================

with scanner_tab:

    st.subheader(
        "Scan a suspicious URL"
    )

    st.caption(
        """
        Reputation data is checked first.
        The ML classifier is used when no verified
        reputation record is available.
        """
    )


    # --------------------------------------------------------
    # INPUT
    # --------------------------------------------------------

    input_column, button_column = st.columns(
        [5, 1.4]
    )


    with input_column:

        url_input = st.text_input(
            "URL to analyze",
            value=st.session_state.last_url,
            placeholder=
                "https://example.com/login",
            label_visibility="collapsed",
        )


    with button_column:

        scan_button = st.button(
            "Analyze URL",
            type="primary",
            use_container_width=True,
        )


    # --------------------------------------------------------
    # SCAN ACTION
    # --------------------------------------------------------

    if scan_button:

        if not url_input.strip():

            st.warning(
                "Please enter a URL before starting the analysis."
            )

        else:

            try:

                with st.spinner(
                    "Analyzing URL reputation and phishing risk..."
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
                    f"Analysis failed: {error}"
                )


    # --------------------------------------------------------
    # RESULT
    # --------------------------------------------------------

    result = st.session_state.last_result


    if result is None:

        st.info(
            """
            Enter a URL above to begin analysis.
            The website will not be opened or visited.
            """
        )


    else:

        st.divider()


        label = result[
            "label"
        ]


        verified = result.get(
            "verified",
            False
        )


        risk_score = result.get(
            "risk_score"
        )


        probability = result.get(
            "phishing_probability"
        )


        threshold = result.get(
            "threshold"
        )


        model = result.get(
            "model"
        )


        # ----------------------------------------------------
        # CLASSIFICATION
        # ----------------------------------------------------

        if label == "Phishing":

            st.error(
                "🚨 Potential Phishing Detected"
            )

            st.write(
                """
                The submitted URL crossed the phishing
                decision threshold used by the detection system.
                """
            )


        else:

            st.success(
                "✅ No Phishing Signal Detected"
            )

            st.write(
                """
                The submitted URL is currently classified
                as legitimate by this detection system.
                """
            )


        # ----------------------------------------------------
        # RESULT METRICS
        # ----------------------------------------------------

        result1, result2, result3 = st.columns(
            3
        )


        with result1:

            st.metric(
                "Risk Score",
                (
                    f"{risk_score:.2f}%"
                    if risk_score is not None
                    else "Verified"
                ),
            )


        with result2:

            st.metric(
                "Phishing Probability",
                (
                    f"{probability:.4f}"
                    if probability is not None
                    else "N/A"
                ),
            )


        with result3:

            st.metric(
                "Decision Source",
                (
                    "Verified Reputation"
                    if verified
                    else "ML Model"
                ),
            )


        # ----------------------------------------------------
        # RISK BAR
        # ----------------------------------------------------

        if risk_score is not None:

            st.caption(
                "Risk level"
            )


            bounded_risk = max(
                0,
                min(
                    int(round(risk_score)),
                    100
                )
            )


            st.progress(
                bounded_risk
            )


        # ----------------------------------------------------
        # URL DETAILS
        # ----------------------------------------------------

        st.subheader(
            "Analysis Details"
        )


        detail1, detail2 = st.columns(
            2
        )


        with detail1:

            st.caption(
                "NORMALIZED URL"
            )

            st.code(
                result[
                    "normalized_url"
                ],
                language=None,
            )


        with detail2:

            st.caption(
                "HOSTNAME"
            )

            st.code(
                result[
                    "hostname"
                ],
                language=None,
            )


        detail3, detail4 = st.columns(
            2
        )


        with detail3:

            st.caption(
                "DETECTION ENGINE"
            )

            st.write(
                model
                if model
                else
                "Verified Reputation Database"
            )


        with detail4:

            st.caption(
                "DECISION THRESHOLD"
            )

            st.write(
                threshold
                if threshold is not None
                else
                "Not applicable"
            )


        # ----------------------------------------------------
        # VERIFIED RESULT
        # ----------------------------------------------------

        if verified:

            st.info(
                """
                A verified reputation record was found.
                The final decision was therefore returned
                from the reputation database.
                """
            )


            verification_source = result.get(
                "verification_source"
            )


            verification_notes = result.get(
                "verification_notes"
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


# ============================================================
# HISTORY TAB
# ============================================================

with history_tab:

    st.subheader(
        "Recent URL Analysis"
    )

    st.caption(
        "Latest scans stored by the SQL reputation engine."
    )


    history = get_scan_history(
        limit=15
    )


    if history:

        history_df = pd.DataFrame(
            history
        )


        wanted_columns = [
            "scanned_at",
            "normalized_url",
            "final_label",
            "result_source",
            "risk_score",
        ]


        available_columns = [
            column
            for column in wanted_columns
            if column in history_df.columns
        ]


        history_df = history_df[
            available_columns
        ].copy()


        history_df = history_df.rename(
            columns={
                "scanned_at":
                    "Time",

                "normalized_url":
                    "URL",

                "final_label":
                    "Classification",

                "result_source":
                    "Source",

                "risk_score":
                    "Risk Score",
            }
        )


        if "Source" in history_df.columns:

            history_df[
                "Source"
            ] = (
                history_df[
                    "Source"
                ]
                .replace(
                    {
                        "ml_model":
                            "ML Model",

                        "verified_reputation":
                            "Verified Reputation",
                    }
                )
            )


        if (
            "Risk Score"
            in history_df.columns
        ):

            history_df[
                "Risk Score"
            ] = (
                history_df[
                    "Risk Score"
                ]
                .apply(
                    lambda value:
                    (
                        f"{value:.2f}%"
                        if pd.notna(value)
                        else "Verified"
                    )
                )
            )


        st.dataframe(
            history_df,
            use_container_width=True,
            hide_index=True,
        )


    else:

        st.info(
            "No scan history has been recorded yet."
        )


    st.divider()


    # --------------------------------------------------------
    # SYSTEM INFORMATION
    # --------------------------------------------------------

    st.subheader(
        "Detection System"
    )


    system1, system2 = st.columns(
        2
    )


    with system1:

        with st.container(
            border=True
        ):

            st.markdown(
                "#### Machine Learning"
            )

            st.write(
                "**Model:** HistGradientBoosting"
            )

            st.write(
                "**Predictors:** 22 URL features"
            )

            st.write(
                "**Threshold:** 0.14"
            )

            st.write(
                "**Target:** Phishing / Legitimate"
            )


    with system2:

        with st.container(
            border=True
        ):

            st.markdown(
                "#### Reputation Layer"
            )

            st.write(
                "**Database:** SQLite"
            )

            st.write(
                "**Stored:** Reputation + History"
            )

            st.write(
                "**Verified overrides:** Supported"
            )

            st.write(
                "**Website requests:** Disabled"
            )


    # --------------------------------------------------------
    # HOW IT WORKS
    # --------------------------------------------------------

    st.subheader(
        "How the analysis works"
    )


    workflow1, workflow2, workflow3, workflow4 = st.columns(
        4
    )


    with workflow1:

        with st.container(
            border=True
        ):

            st.markdown(
                "### 01"
            )

            st.markdown(
                "**Normalize**"
            )

            st.caption(
                "Validate and normalize the submitted URL."
            )


    with workflow2:

        with st.container(
            border=True
        ):

            st.markdown(
                "### 02"
            )

            st.markdown(
                "**Reputation**"
            )

            st.caption(
                "Check SQL for trusted existing reputation."
            )


    with workflow3:

        with st.container(
            border=True
        ):

            st.markdown(
                "### 03"
            )

            st.markdown(
                "**ML Analysis**"
            )

            st.caption(
                "Generate features and estimate phishing risk."
            )


    with workflow4:

        with st.container(
            border=True
        ):

            st.markdown(
                "### 04"
            )

            st.markdown(
                "**Store**"
            )

            st.caption(
                "Update reputation and record scan history."
            )


# ============================================================
# RESPONSIBLE USE
# ============================================================

st.write("")


with st.expander(
    "ℹ️ About PhishGuard AI"
):

    st.write(
        """
        PhishGuard AI performs lexical URL analysis using
        a trained machine-learning classifier and a SQL-backed
        reputation layer.

        Submitted websites are not automatically opened or
        visited.

        Machine-learning security systems can still produce
        false positives or false negatives, so results should
        be treated as security guidance rather than an
        absolute guarantee.
        """
    )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "PhishGuard AI • Python • scikit-learn • SQLite • Streamlit"
)