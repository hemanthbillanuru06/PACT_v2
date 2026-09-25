"""Audit logging service for PACT.

Safely writes security events (LOGIN_SUCCESS, LOGIN_FAILED, LOGOUT, UNAUTHORIZED_ACCESS)
to the audit_logs collection without crashing the main application thread if a database error occurs.
"""
from datetime import datetime, timezone
import logging
from typing import Optional, Dict, Any, List
from pymongo.database import Database
from pymongo.errors import PyMongoError

from config.settings import settings
from database.connection import get_db, get_audit_logs_col

logger = logging.getLogger("pact.services.audit")


class AuditService:
    """Central audit service providing safe logging."""

    @staticmethod
    def log_event(
        event_type: str,
        user_id: Optional[str] = None,
        officer_id: Optional[str] = None,
        role: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: str = "127.0.0.1",
        status: str = "SUCCESS",
        db: Optional[Database] = None,
    ) -> bool:
        """Write an audit entry safely to MongoDB.

        Catches PyMongoError so that an audit logging failure does NOT crash
        the caller application thread.
        """
        audit_record = {
            "event_type": event_type,
            "user_id": str(user_id) if user_id is not None else None,
            "officer_id": officer_id,
            "role": role,
            "details": details or {},
            "ip_address": ip_address,
            "status": status,
            "timestamp": datetime.now(timezone.utc),
        }

        try:
            target_db = db if db is not None else get_db()
            audit_col = get_audit_logs_col(target_db)
            audit_col.insert_one(audit_record)
            logger.info("Audit logged [%s] for officer %s (Role: %s)", event_type, officer_id, role)
            return True
        except PyMongoError as err:
            logger.error("Audit log DB write failed for event [%s]: %s", event_type, err)
            return False

    @classmethod
    def log_login_success(cls, user: Dict[str, Any], ip_address: str = "127.0.0.1", db: Optional[Database] = None) -> bool:
        return cls.log_event(
            event_type=settings.AUDIT_LOGIN_SUCCESS,
            user_id=str(user.get("_id", user.get("user_id"))),
            officer_id=user.get("officer_id"),
            role=user.get("role"),
            details={"email": user.get("email"), "action": "login"},
            ip_address=ip_address,
            status="SUCCESS",
            db=db,
        )

    @classmethod
    def log_login_failed(
        cls,
        identifier: str,
        reason: str,
        user_doc: Optional[Dict[str, Any]] = None,
        ip_address: str = "127.0.0.1",
        db: Optional[Database] = None,
    ) -> bool:
        user_id = str(user_doc.get("_id")) if user_doc else None
        officer_id = user_doc.get("officer_id") if user_doc else identifier
        role = user_doc.get("role") if user_doc else None

        return cls.log_event(
            event_type=settings.AUDIT_LOGIN_FAILED,
            user_id=user_id,
            officer_id=officer_id,
            role=role,
            details={"identifier": identifier, "reason": reason},
            ip_address=ip_address,
            status="FAILURE",
            db=db,
        )

    @classmethod
    def log_logout(cls, user: Dict[str, Any], ip_address: str = "127.0.0.1", db: Optional[Database] = None) -> bool:
        return cls.log_event(
            event_type=settings.AUDIT_LOGOUT,
            user_id=str(user.get("_id", user.get("user_id"))),
            officer_id=user.get("officer_id"),
            role=user.get("role"),
            details={"email": user.get("email"), "action": "logout"},
            ip_address=ip_address,
            status="SUCCESS",
            db=db,
        )

    @classmethod
    def log_unauthorized_access(
        cls,
        user: Optional[Dict[str, Any]],
        resource: str,
        ip_address: str = "127.0.0.1",
        db: Optional[Database] = None,
    ) -> bool:
        user_id = str(user.get("_id", user.get("user_id"))) if user else "anonymous"
        officer_id = user.get("officer_id", "unauthenticated") if user else "unauthenticated"
        role = user.get("role", "none") if user else "none"

        return cls.log_event(
            event_type=settings.AUDIT_UNAUTHORIZED_ACCESS,
            user_id=user_id,
            officer_id=officer_id,
            role=role,
            details={"target_resource": resource, "violation": "insufficient_role_permission"},
            ip_address=ip_address,
            status="DENIED",
            db=db,
        )

    @classmethod
    def log_account_locked(
        cls,
        user_doc: Optional[Dict[str, Any]],
        identifier: str,
        ip_address: str = "127.0.0.1",
        db: Optional[Database] = None,
    ) -> bool:
        user_id = str(user_doc.get("_id")) if user_doc else None
        officer_id = user_doc.get("officer_id") if user_doc else identifier
        role = user_doc.get("role") if user_doc else None

        return cls.log_event(
            event_type=settings.AUDIT_ACCOUNT_LOCKED,
            user_id=user_id,
            officer_id=officer_id,
            role=role,
            details={"identifier": identifier, "trigger": "5_consecutive_failed_attempts"},
            ip_address=ip_address,
            status="LOCKED",
            db=db,
        )

    @staticmethod
    def get_recent_logs(
        limit: int = 100,
        event_type: Optional[str] = None,
        officer_id: Optional[str] = None,
        db: Optional[Database] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieve recent audit logs sorted newest first."""
        target_db = db if db is not None else get_db()
        audit_col = get_audit_logs_col(target_db)
        query: Dict[str, Any] = {}
        if event_type:
            query["event_type"] = event_type
        if officer_id:
            query["officer_id"] = officer_id

        try:
            cursor = audit_col.find(query).sort("timestamp", -1).limit(limit)
            return list(cursor)
        except PyMongoError as err:
            logger.error("Failed to query audit logs: %s", err)
            return []
