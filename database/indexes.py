"""Idempotent index creation for PACT MongoDB collections."""
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
)

logger = logging.getLogger("pact.database.indexes")


def ensure_indexes(db: Optional[Database] = None) -> Dict[str, List[str]]:
    """Idempotently create required indexes on all collections.

    Required DB Indexes:
      - users.email (unique)
      - users.officer_id (unique)
      - audit_logs.user_id
      - login_attempts.identifier

    Returns a dictionary of created/verified index names by collection.
    """
    target_db = db if db is not None else get_db()
    users_col = get_users_col(target_db)
    officers_col = get_officers_col(target_db)
    registry_col = get_police_registry_col(target_db)
    audit_logs_col = get_audit_logs_col(target_db)
    login_attempts_col = get_login_attempts_col(target_db)

    results: Dict[str, List[str]] = {
        "users": [],
        "officers": [],
        "police_registry": [],
        "audit_logs": [],
        "login_attempts": [],
    }

    try:
        # Users indexes
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

        logger.info("Database indexes ensured successfully: %s", results)
        return results

    except PyMongoError as err:
        logger.error("Failed to create database indexes: %s", err)
        raise
