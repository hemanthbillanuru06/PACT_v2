"""Authentication service for PACT.

Coordinates credential verification, lockout enforcement, session generation, and audit logging.
"""
from datetime import datetime, timezone
import logging
from typing import Optional, Dict, Any
from pymongo.database import Database

from config.settings import settings
from database.connection import get_db, get_users_col, get_officers_col
from security.passwords import verify_password
from security.lockout import LockoutManager, AccountLockedError
from services.audit_service import AuditService

logger = logging.getLogger("pact.services.auth")


class AuthenticationError(Exception):
    """Base exception for authentication failures."""
    pass


class InvalidCredentialsError(AuthenticationError):
    """Raised when identifier or password does not match."""
    pass


class InactiveAccountError(AuthenticationError):
    """Raised when an account is marked inactive."""
    pass


class AuthService:
    """Handles officer authentication lifecycle."""

    @classmethod
    def authenticate(
        cls,
        identifier: str,
        password: str,
        ip_address: str = "127.0.0.1",
        db: Optional[Database] = None,
    ) -> Dict[str, Any]:
        """Authenticate user by email or officer_id.

        Enforces:
        - DB-backed account lockout check (fails immediately if already locked)
        - Password verification with bcrypt
        - Incrementing failed counter and auto-locking upon 5 failed attempts
        - Resetting counter on success
        - Audit logging for LOGIN_SUCCESS, LOGIN_FAILED, and ACCOUNT_LOCKED
        """
        clean_identifier = (identifier or "").strip()
        if not clean_identifier or not password:
            raise InvalidCredentialsError("Officer identifier and password are required.")

        target_db = db if db is not None else get_db()
        users_col = get_users_col(target_db)
        officers_col = get_officers_col(target_db)

        # Find user by either officer_id or email
        user_doc = users_col.find_one({
            "$or": [
                {"email": clean_identifier.lower()},
                {"officer_id": clean_identifier.upper()},
            ]
        })

        # Check if already locked
        if user_doc and LockoutManager.is_account_locked(user_doc):
            AuditService.log_login_failed(
                identifier=clean_identifier,
                reason="Login attempt on locked account",
                user_doc=user_doc,
                ip_address=ip_address,
                db=target_db,
            )
            raise AccountLockedError(
                "Account is LOCKED due to repeated failed login attempts. "
                "Contact a System Administrator to restore access."
            )

        # If user does not exist
        if not user_doc:
            LockoutManager.record_attempt(
                identifier=clean_identifier,
                success=False,
                reason="User not found",
                ip_address=ip_address,
                db=target_db,
            )
            AuditService.log_login_failed(
                identifier=clean_identifier,
                reason="User account not found",
                user_doc=None,
                ip_address=ip_address,
                db=target_db,
            )
            raise InvalidCredentialsError("Invalid officer credentials.")

        # Check if active
        if not user_doc.get("is_active", True):
            AuditService.log_login_failed(
                identifier=clean_identifier,
                reason="Inactive account",
                user_doc=user_doc,
                ip_address=ip_address,
                db=target_db,
            )
            raise InactiveAccountError("Account has been deactivated by administration.")

        # Verify password with bcrypt
        stored_hash = user_doc.get("password_hash", "")
        if not verify_password(password, stored_hash):
            is_locked_now = LockoutManager.register_failed_attempt(
                user_doc=user_doc,
                identifier=clean_identifier,
                reason="Incorrect password",
                ip_address=ip_address,
                db=target_db,
            )

            AuditService.log_login_failed(
                identifier=clean_identifier,
                reason="Incorrect password",
                user_doc=user_doc,
                ip_address=ip_address,
                db=target_db,
            )

            if is_locked_now:
                AuditService.log_account_locked(
                    user_doc=user_doc,
                    identifier=clean_identifier,
                    ip_address=ip_address,
                    db=target_db,
                )
                raise AccountLockedError(
                    f"Account has been LOCKED after {settings.MAX_LOGIN_ATTEMPTS} consecutive "
                    f"failed login attempts. Contact a System Administrator."
                )

            remaining = settings.MAX_LOGIN_ATTEMPTS - (user_doc.get("failed_login_attempts", 0) + 1)
            raise InvalidCredentialsError(
                f"Invalid officer credentials. {max(remaining, 0)} attempt(s) remaining before lockout."
            )

        # Successful authentication: reset failed attempts
        LockoutManager.reset_failed_attempts(
            user_id=user_doc["_id"],
            identifier=clean_identifier,
            ip_address=ip_address,
            db=target_db,
        )

        # Enrich with officer details
        officer_doc = officers_col.find_one({"officer_id": user_doc["officer_id"]}) or {}

        # Log successful login
        AuditService.log_login_success(user=user_doc, ip_address=ip_address, db=target_db)

        session_user = {
            "user_id": str(user_doc["_id"]),
            "officer_id": user_doc["officer_id"],
            "email": user_doc["email"],
            "role": user_doc["role"],
            "full_name": officer_doc.get("full_name", user_doc["officer_id"]),
            "badge_number": officer_doc.get("badge_number", "N/A"),
            "station_id": officer_doc.get("station_id", "N/A"),
            "rank": officer_doc.get("rank", user_doc["role"]),
            "contact_phone": officer_doc.get("contact_phone", "N/A"),
            "authenticated_at": datetime.now(timezone.utc).isoformat(),
        }

        return session_user

    @classmethod
    def logout(cls, user: Dict[str, Any], ip_address: str = "127.0.0.1", db: Optional[Database] = None) -> bool:
        """Handle officer logout and log event."""
        if not user:
            return False
        target_db = db if db is not None else get_db()
        return AuditService.log_logout(user=user, ip_address=ip_address, db=target_db)
