"""Idempotent index creation for PACT MongoDB collections (Phase 1 & Phase 2)."""
import logging
from typing import Dict, List, Optional
import pymongo
from pymongo.database import Database
from pymongo.errors import PyMongoError

from database.connection import (
    get_db,
    get_users_col,
    get_audit_logs_col,
    get_login_attempts_col,
    get_officers_col,
    get_police_registry_col,
    get_firs_col,
    get_cases_col,
    get_evidence_col,
    get_investigation_timeline_col,
    get_case_notes_col,
    get_case_assignments_col,
    get_notifications_col,
    get_property_items_col,
    get_suspects_col,
    get_witnesses_col,
    get_victims_col,
    get_complainants_col,
    get_ai_analysis_history_col,
)

logger = logging.getLogger("pact.database.indexes")


def ensure_indexes(db: Optional[Database] = None) -> Dict[str, List[str]]:
    """Idempotently create required indexes on all collections.

    Maintains Phase 1 indexes:
      - users.email (unique)
      - users.officer_id (unique)
      - audit_logs.user_id
      - login_attempts.identifier

    Adds Phase 2 indexes:
      - firs.fir_number (unique), firs.station_id
      - cases.case_id (unique), cases.station_id, cases.io_officer_id
      - evidence.evidence_id (unique), evidence.case_id
      - investigation_timeline.case_id
      - case_notes.case_id
      - notifications.recipient_officer_id
      - case_assignments.case_id, case_assignments.officer_id

    Returns a dictionary of created/verified index names by collection.
    """
    target_db = db if db is not None else get_db()
    users_col = get_users_col(target_db)
    officers_col = get_officers_col(target_db)
    registry_col = get_police_registry_col(target_db)
    audit_logs_col = get_audit_logs_col(target_db)
    login_attempts_col = get_login_attempts_col(target_db)

    # Phase 2 collections
    firs_col = get_firs_col(target_db)
    cases_col = get_cases_col(target_db)
    evidence_col = get_evidence_col(target_db)
    timeline_col = get_investigation_timeline_col(target_db)
    notes_col = get_case_notes_col(target_db)
    assignments_col = get_case_assignments_col(target_db)
    notifications_col = get_notifications_col(target_db)

    # Phase 3 collections
    ai_history_col = get_ai_analysis_history_col(target_db)

    results: Dict[str, List[str]] = {
        "users": [],
        "officers": [],
        "police_registry": [],
        "audit_logs": [],
        "login_attempts": [],
        "firs": [],
        "cases": [],
        "evidence": [],
        "investigation_timeline": [],
        "case_notes": [],
        "case_assignments": [],
        "notifications": [],
        "ai_analysis_history": [],
    }

    try:
        # Phase 1: Users indexes
        idx_user_email = users_col.create_index(
            [("email", pymongo.ASCENDING)],
            unique=True,
            name="idx_users_email_unique",
        )
        results["users"].append(idx_user_email)

        idx_user_officer_id = users_col.create_index(
            [("officer_id", pymongo.ASCENDING)],
            unique=True,
            name="idx_users_officer_id_unique",
        )
        results["users"].append(idx_user_officer_id)

        # Officers indexes
        idx_officer_id = officers_col.create_index(
            [("officer_id", pymongo.ASCENDING)],
            unique=True,
            name="idx_officers_officer_id_unique",
        )
        results["officers"].append(idx_officer_id)

        # Police registry indexes (station_id)
        idx_station_id = registry_col.create_index(
            [("station_id", pymongo.ASCENDING)],
            unique=True,
            name="idx_registry_station_id_unique",
        )
        results["police_registry"].append(idx_station_id)

        # Audit logs indexes
        idx_audit_user_id = audit_logs_col.create_index(
            [("user_id", pymongo.ASCENDING)],
            name="idx_audit_logs_user_id",
        )
        results["audit_logs"].append(idx_audit_user_id)

        idx_audit_timestamp = audit_logs_col.create_index(
            [("timestamp", pymongo.DESCENDING)],
            name="idx_audit_logs_timestamp",
        )
        results["audit_logs"].append(idx_audit_timestamp)

        # Login attempts indexes
        idx_attempt_identifier = login_attempts_col.create_index(
            [("identifier", pymongo.ASCENDING)],
            name="idx_login_attempts_identifier",
        )
        results["login_attempts"].append(idx_attempt_identifier)

        idx_attempt_timestamp = login_attempts_col.create_index(
            [("timestamp", pymongo.DESCENDING)],
            name="idx_login_attempts_timestamp",
        )
        results["login_attempts"].append(idx_attempt_timestamp)

        # Phase 2: FIRs indexes
        idx_fir_number = firs_col.create_index(
            [("fir_number", pymongo.ASCENDING)],
            unique=True,
            name="idx_firs_fir_number_unique",
        )
        results["firs"].append(idx_fir_number)

        idx_fir_station = firs_col.create_index(
            [("station_id", pymongo.ASCENDING)],
            name="idx_firs_station_id",
        )
        results["firs"].append(idx_fir_station)

        # Phase 2: Cases indexes
        idx_case_id = cases_col.create_index(
            [("case_id", pymongo.ASCENDING)],
            unique=True,
            name="idx_cases_case_id_unique",
        )
        results["cases"].append(idx_case_id)

        idx_case_station = cases_col.create_index(
            [("station_id", pymongo.ASCENDING)],
            name="idx_cases_station_id",
        )
        results["cases"].append(idx_case_station)

        idx_case_io = cases_col.create_index(
            [("io_officer_id", pymongo.ASCENDING)],
            name="idx_cases_io_officer_id",
        )
        results["cases"].append(idx_case_io)

        # Phase 2: Evidence indexes
        idx_evidence_id = evidence_col.create_index(
            [("evidence_id", pymongo.ASCENDING)],
            unique=True,
            name="idx_evidence_evidence_id_unique",
        )
        results["evidence"].append(idx_evidence_id)

        idx_evidence_case = evidence_col.create_index(
            [("case_id", pymongo.ASCENDING)],
            name="idx_evidence_case_id",
        )
        results["evidence"].append(idx_evidence_case)

        # Phase 2: Timeline indexes
        idx_timeline_case = timeline_col.create_index(
            [("case_id", pymongo.ASCENDING), ("timestamp", pymongo.ASCENDING)],
            name="idx_timeline_case_time",
        )
        results["investigation_timeline"].append(idx_timeline_case)

        # Phase 2: Case notes indexes
        idx_notes_case = notes_col.create_index(
            [("case_id", pymongo.ASCENDING), ("created_at", pymongo.DESCENDING)],
            name="idx_notes_case_time",
        )
        results["case_notes"].append(idx_notes_case)

        # Phase 2: Case assignments indexes
        idx_assign_case = assignments_col.create_index(
            [("case_id", pymongo.ASCENDING), ("officer_id", pymongo.ASCENDING)],
            name="idx_assign_case_officer",
        )
        results["case_assignments"].append(idx_assign_case)

        # Phase 2: Notifications indexes
        idx_notif_officer = notifications_col.create_index(
            [("recipient_officer_id", pymongo.ASCENDING), ("is_read", pymongo.ASCENDING)],
            name="idx_notif_recipient_read",
        )
        results["notifications"].append(idx_notif_officer)

        # Phase 3: AI Analysis History indexes
        idx_ai_analysis_id = ai_history_col.create_index(
            [("analysis_id", pymongo.ASCENDING)],
            unique=True,
            name="idx_ai_history_analysis_id_unique",
        )
        results["ai_analysis_history"].append(idx_ai_analysis_id)

        idx_ai_case = ai_history_col.create_index(
            [("case_id", pymongo.ASCENDING)],
            name="idx_ai_history_case_id",
        )
        results["ai_analysis_history"].append(idx_ai_case)

        idx_ai_officer = ai_history_col.create_index(
            [("officer_id", pymongo.ASCENDING)],
            name="idx_ai_history_officer_id",
        )
        results["ai_analysis_history"].append(idx_ai_officer)

        idx_ai_timestamp = ai_history_col.create_index(
            [("timestamp", pymongo.DESCENDING)],
            name="idx_ai_history_timestamp",
        )
        results["ai_analysis_history"].append(idx_ai_timestamp)

        logger.info("Database indexes ensured successfully.")
        return results

    except PyMongoError as err:
        logger.error("Failed to create database indexes: %s", err)
        raise
