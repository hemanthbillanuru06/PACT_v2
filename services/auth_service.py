"""Authentication service for PACT.

Coordinates credential verification, lockout enforcement, session generation, and audit logging.
"""
from datetime import datetime, timezone
import logging
from typing import Optional, Dict, Any
from pymongo.database import Database

from config.settings import settings
from database.connection import get_db, get_users_col, get_officers_col
from security.passwords import verify_password, hash_password, validate_password_policy, PasswordPolicyError
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

    @classmethod
    def register_officer(
        cls,
        full_name: str,
        officer_id: str,
        email: str,
        role: str,
        password: str,
        badge_number: Optional[str] = None,
        station_id: Optional[str] = None,
        rank: Optional[str] = None,
        contact_phone: Optional[str] = None,
        blood_group: Optional[str] = "O+",
        db: Optional[Database] = None,
    ) -> Dict[str, Any]:
        """Register a new law enforcement officer in MongoDB users & officers collections.

        Enforces:
        - Required field validation
        - Strict password policy (12+ chars, uppercase, lowercase, digit, special char)
        - Password hashing with bcrypt
        - Uniqueness check for officer_id and email
        - Idempotent insertion into users collection and officers directory
        - Audit trail logging
        """
        clean_name = (full_name or "").strip()
        clean_id = (officer_id or "").strip().upper()
        clean_email = (email or "").strip().lower()
        clean_role = (role or "").strip().upper()

        if not clean_name:
            raise ValueError("Full Name is required.")
        if not clean_id:
            raise ValueError("Officer ID is required.")
        if not clean_email or "@" not in clean_email:
            raise ValueError("Valid department email is required.")
        if not clean_role:
            raise ValueError("Role designation is required.")

        allowed_roles = [
            settings.ROLE_ADMIN,
            settings.ROLE_SP,
            settings.ROLE_SI,
            settings.ROLE_INVESTIGATING_OFFICER,
            settings.ROLE_CONSTABLE,
        ]
        if clean_role not in allowed_roles:
            raise ValueError(f"Invalid role '{clean_role}'. Allowed roles: {allowed_roles}")

        # Enforce password policy & hash with bcrypt
        is_valid, errors = validate_password_policy(password)
        if not is_valid:
            raise PasswordPolicyError(" ".join(errors))

        pwd_hash = hash_password(password)

        target_db = db if db is not None else get_db()
        users_col = get_users_col(target_db)
        officers_col = get_officers_col(target_db)

        # Check uniqueness in users collection
        existing = users_col.find_one({
            "$or": [
                {"officer_id": clean_id},
                {"email": clean_email},
            ]
        })
        if existing:
            if existing.get("officer_id") == clean_id:
                raise ValueError(f"Officer ID '{clean_id}' is already registered in the system.")
            raise ValueError(f"Email '{clean_email}' is already registered to another officer.")

        now = datetime.now(timezone.utc)
        user_doc = {
            "officer_id": clean_id,
            "email": clean_email,
            "role": clean_role,
            "password_hash": pwd_hash,
            "is_active": True,
            "is_locked": False,
            "failed_login_attempts": 0,
            "created_at": now,
            "updated_at": now,
        }
        res = users_col.insert_one(user_doc)

        clean_badge = (badge_number or "").strip() or f"TS-{clean_role[:3]}-{clean_id[-4:]}"
        clean_station = (station_id or "").strip() or "STN-001"
        clean_rank = (rank or "").strip() or clean_role

        officer_doc = {
            "officer_id": clean_id,
            "badge_number": clean_badge,
            "full_name": clean_name,
            "rank": clean_rank,
            "station_id": clean_station,
            "contact_phone": (contact_phone or "").strip() or "+91-9440-000000",
            "blood_group": (blood_group or "").strip() or "O+",
            "updated_at": now,
        }
        officers_col.update_one(
            {"officer_id": clean_id},
            {"$set": officer_doc, "$setOnInsert": {"created_at": now}},
            upsert=True,
        )

        AuditService.log_event(
            event_type="OFFICER_REGISTERED",
            officer_id=clean_id,
            role=clean_role,
            details={"officer_id": clean_id, "email": clean_email, "station_id": clean_station},
            status="SUCCESS",
            db=target_db,
        )

        return {
            "user_id": str(res.inserted_id),
            "officer_id": clean_id,
            "email": clean_email,
            "role": clean_role,
            "full_name": clean_name,
            "badge_number": clean_badge,
            "station_id": clean_station,
            "rank": clean_rank,
        }
