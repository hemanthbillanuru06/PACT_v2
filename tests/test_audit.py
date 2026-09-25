"""Tests for Audit Logging Service and thread safety against DB write failures."""
from unittest.mock import patch
import pytest
from pymongo.database import Database
from pymongo.errors import PyMongoError, AutoReconnect

from config.settings import settings
from services.audit_service import AuditService


def test_audit_logs_all_event_types(seeded_db: Database):
    """Verify all required audit event types are logged accurately."""
    audit_col = seeded_db[settings.COLLECTION_AUDIT_LOGS]

    events_to_test = [
        settings.AUDIT_LOGIN_SUCCESS,
        settings.AUDIT_LOGIN_FAILED,
        settings.AUDIT_LOGOUT,
        settings.AUDIT_UNAUTHORIZED_ACCESS,
        settings.AUDIT_ACCOUNT_LOCKED,
    ]

    for ev in events_to_test:
        success = AuditService.log_event(
            event_type=ev,
            officer_id="TS-TEST-99",
            role="SP",
            details={"action": f"testing_{ev}"},
            db=seeded_db,
        )
        assert success is True

    for ev in events_to_test:
        doc = audit_col.find_one({"event_type": ev, "officer_id": "TS-TEST-99"})
        assert doc is not None
        assert doc["role"] == "SP"


def test_audit_logging_failsafe_on_pymongo_error(seeded_db: Database):
    """Verify that if MongoDB raises a PyMongoError during audit logging,

    the audit service does NOT crash the application thread, but catches
    the error safely and returns False.
    """
    with patch.object(
        seeded_db[settings.COLLECTION_AUDIT_LOGS],
        "insert_one",
        side_effect=AutoReconnect("Simulated network timeout during audit write"),
    ):
        # Call must not raise any exception
        result = AuditService.log_event(
            event_type=settings.AUDIT_LOGIN_FAILED,
            officer_id="TS-FAILSAFE-01",
            details={"test": "failsafe"},
            db=seeded_db,
        )
        assert result is False  # Safely handled without crashing
