"""Database-backed account lockout management for PACT.

Locks user accounts after 5 failed login attempts and maintains attempt history.
"""
from datetime import datetime, timezone
import logging
from typing import Optional, Dict, Any
from pymongo.database import Database
from pymongo.errors import PyMongoError

from config.settings import settings
from database.connection import get_db, get_users_col, get_login_attempts_col

logger = logging.getLogger("pact.security.lockout")


class AccountLockedError(Exception):
    """Raised when authentication is attempted on a locked account."""
    pass


class LockoutManager:
    """Handles tracking failed attempts, locking accounts, and checking lockout status."""

    @staticmethod
    def is_account_locked(user_doc: Dict[str, Any]) -> bool:
        """Check if user document indicates a locked account."""
        if not user_doc:
            return False
        return bool(user_doc.get("is_locked", False))

    @staticmethod
    def record_attempt(
        identifier: str,
        success: bool,
        reason: Optional[str] = None,
        ip_address: str = "127.0.0.1",
        db: Optional[Database] = None,
    ) -> None:
        """Record an entry in the login_attempts collection."""
        target_db = db if db is not None else get_db()
        login_attempts_col = get_login_attempts_col(target_db)

        attempt_record = {
            "identifier": identifier,
            "success": success,
            "reason": reason or ("Authentication successful" if success else "Invalid credentials"),
            "ip_address": ip_address,
            "timestamp": datetime.now(timezone.utc),
        }

        try:
            login_attempts_col.insert_one(attempt_record)
        except PyMongoError as err:
            logger.error("Failed to record login attempt for %s: %s", identifier, err)

    @classmethod
    def register_failed_attempt(
        cls,
        user_doc: Optional[Dict[str, Any]],
        identifier: str,
        reason: str = "Invalid credentials",
        ip_address: str = "127.0.0.1",
        db: Optional[Database] = None,
    ) -> bool:
        """Record a failed attempt. If account reaches MAX_LOGIN_ATTEMPTS, lock it.

        Returns True if the account is now locked, False otherwise.
        """
        target_db = db if db is not None else get_db()
        users_col = get_users_col(target_db)

        # Record in attempts collection
        cls.record_attempt(identifier, success=False, reason=reason, ip_address=ip_address, db=target_db)

        if not user_doc:
            return False

        current_attempts = user_doc.get("failed_login_attempts", 0) + 1
        is_now_locked = current_attempts >= settings.MAX_LOGIN_ATTEMPTS

        update_fields: Dict[str, Any] = {
            "failed_login_attempts": current_attempts,
            "last_failed_login": datetime.now(timezone.utc),
        }

        if is_now_locked:
            update_fields["is_locked"] = True
            update_fields["locked_at"] = datetime.now(timezone.utc)
            logger.warning(
                "Account '%s' (officer: %s) has been LOCKED after %d failed attempts.",
                user_doc.get("email"), user_doc.get("officer_id"), current_attempts
            )

        try:
            users_col.update_one(
                {"_id": user_doc["_id"]},
                {"$set": update_fields}
            )
        except PyMongoError as err:
            logger.error("Failed to update failed attempt counter for %s: %s", identifier, err)

        return is_now_locked

    @classmethod
    def reset_failed_attempts(
        cls,
        user_id: Any,
        identifier: str,
        ip_address: str = "127.0.0.1",
        db: Optional[Database] = None,
    ) -> None:
        """Reset failed login attempts to 0 on successful authentication."""
        target_db = db if db is not None else get_db()
        users_col = get_users_col(target_db)

        cls.record_attempt(identifier, success=True, reason="Login success", ip_address=ip_address, db=target_db)

        try:
            users_col.update_one(
                {"_id": user_id},
                {
                    "$set": {
                        "failed_login_attempts": 0,
                        "last_successful_login": datetime.now(timezone.utc),
                    }
                }
            )
        except PyMongoError as err:
            logger.error("Failed to reset failed attempts for %s: %s", user_id, err)

    @staticmethod
    def unlock_account(user_id: Any, db: Optional[Database] = None) -> bool:
        """Unlock a locked account (e.g. administrator override)."""
        target_db = db if db is not None else get_db()
        users_col = get_users_col(target_db)
        try:
            res = users_col.update_one(
                {"_id": user_id},
                {
                    "$set": {
                        "is_locked": False,
                        "failed_login_attempts": 0,
                        "unlocked_at": datetime.now(timezone.utc),
                    }
                }
            )
            return res.modified_count > 0
        except PyMongoError as err:
            logger.error("Failed to unlock account %s: %s", user_id, err)
            return False
