import streamlit

from src.database.reputation_service import (
    scan_url,
)

from src.database.db_manager import (
    get_database_stats,
    get_scan_history,
)


def test_streamlit_available():

    assert (
        streamlit.__version__
        is not None
    )


def test_app_backend_imports():

    assert callable(
        scan_url
    )

    assert callable(
        get_database_stats
    )

    assert callable(
        get_scan_history
    )