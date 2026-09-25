"""Tests for Streamlit application startup and session state flow."""
from unittest.mock import patch, MagicMock
import pytest
import streamlit as st

from app import initialize_platform
from database.connection import MongoDBConnection, DatabaseConnectionError


def test_app_initialize_platform_success():
    """Verify platform initializes cleanly when MongoDB is active."""
    with patch.dict(st.session_state, {}, clear=True):
        success = initialize_platform()
        assert success is True
        assert st.session_state.get("db_seeded") is True


def test_app_initialize_platform_loud_failure():
    """Verify initialize_platform stops loudly when MongoDB connection fails."""
    with patch.dict(st.session_state, {}, clear=True):
        with patch.object(
            MongoDBConnection,
            "check_health",
            side_effect=DatabaseConnectionError("Simulated DB Down"),
        ):
            with patch("streamlit.error") as mock_st_error, patch("streamlit.stop") as mock_st_stop:
                initialize_platform()
                mock_st_error.assert_called_once()
                mock_st_stop.assert_called_once()
