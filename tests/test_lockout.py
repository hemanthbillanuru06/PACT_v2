"""Tests for DB-backed account lockout after 5 failed login attempts."""
import pytest
from pymongo.database import Database

from config.settings import settings
from security.lockout import AccountLockedError
from services.auth_service import AuthService, InvalidCredentialsError
from services.user_service import UserService


def test_lockout_after_five_failed_attempts(seeded_db: Database, officer_password: str):
    """Verify account is locked after exactly 5 consecutive failed login attempts."""
    officer_id = "TS-POL-006"
    users_col = seeded_db[settings.COLLECTION_USERS]
    attempts_col = seeded_db[settings.COLLECTION_LOGIN_ATTEMPTS]
    audit_col = seeded_db[settings.COLLECTION_AUDIT_LOGS]

    # Attempts 1 to 4 should raise InvalidCredentialsError, not AccountLockedError
    for attempt_num in range(1, 5):
        with pytest.raises(InvalidCredentialsError):
            AuthService.authenticate(
                identifier=officer_id,
                password="WrongPassword@123!",
                db=seeded_db,
            )
        user_doc = users_col.find_one({"officer_id": officer_id})
        assert user_doc["failed_login_attempts"] == attempt_num
        assert user_doc["is_locked"] is False

    # 5th attempt must trigger account lockout
    with pytest.raises(AccountLockedError):
        AuthService.authenticate(
            identifier=officer_id,
            password="WrongPassword@123!",
            db=seeded_db,
        )

    # Verify user doc state in MongoDB
    user_doc = users_col.find_one({"officer_id": officer_id})
    assert user_doc["failed_login_attempts"] == 5
    assert user_doc["is_locked"] is True
    assert user_doc["locked_at"] is not None

    # Verify ACCOUNT_LOCKED audit event was recorded
    locked_audit = audit_col.find_one({
        "officer_id": officer_id,
        "event_type": settings.AUDIT_ACCOUNT_LOCKED,
    })
    assert locked_audit is not None
    assert locked_audit["status"] == "LOCKED"

    # Verify all 5 failed attempts were logged in login_attempts collection
    attempts_count = attempts_col.count_documents({"identifier": officer_id, "success": False})
    assert attempts_count >= 5


def test_locked_account_rejects_valid_password(seeded_db: Database, officer_password: str):
    """Verify locked account cannot login even when providing the correct password."""
    officer_id = "TS-POL-007"
    users_col = seeded_db[settings.COLLECTION_USERS]

    # Manually lock or trigger 5 failures
    for _ in range(5):
        try:
            AuthService.authenticate(identifier=officer_id, password="BadPassword@123!", db=seeded_db)
        except (InvalidCredentialsError, AccountLockedError):
            pass

    user_doc = users_col.find_one({"officer_id": officer_id})
    assert user_doc["is_locked"] is True

    # Now attempt with CORRECT password - must be rejected
    with pytest.raises(AccountLockedError):
        AuthService.authenticate(
            identifier=officer_id,
            password=officer_password,  # Correct password
            db=seeded_db,
        )


def test_successful_login_resets_failed_counter(seeded_db: Database, officer_password: str):
    """Verify that a successful login resets the failed login counter to 0."""
    officer_id = "TS-POL-008"
    users_col = seeded_db[settings.COLLECTION_USERS]

    # 3 failed attempts
    for _ in range(3):
        with pytest.raises(InvalidCredentialsError):
            AuthService.authenticate(identifier=officer_id, password="BadPassword@123!", db=seeded_db)

    user_doc = users_col.find_one({"officer_id": officer_id})
    assert user_doc["failed_login_attempts"] == 3

    # Now successful login
    session = AuthService.authenticate(identifier=officer_id, password=officer_password, db=seeded_db)
    assert session["officer_id"] == officer_id

    # Verify counter reset
    user_doc = users_col.find_one({"officer_id": officer_id})
    assert user_doc["failed_login_attempts"] == 0
    assert user_doc["is_locked"] is False


def test_admin_can_unlock_account(seeded_db: Database, admin_password: str, officer_password: str):
    """Verify ADMIN role can successfully unlock a locked officer account."""
    officer_id = "TS-POL-009"
    admin_id = "TS-POL-012"
    users_col = seeded_db[settings.COLLECTION_USERS]

    # Lock the officer account
    for _ in range(5):
        try:
            AuthService.authenticate(identifier=officer_id, password="BadPassword@123!", db=seeded_db)
        except (InvalidCredentialsError, AccountLockedError):
            pass

    assert users_col.find_one({"officer_id": officer_id})["is_locked"] is True

    # Authenticate admin
    admin_session = AuthService.authenticate(identifier=admin_id, password=admin_password, db=seeded_db)
    assert admin_session["role"] == settings.ROLE_ADMIN

    # Admin unlocks the account
    unlock_success = UserService.unlock_user_account(
        current_user=admin_session,
        target_officer_id=officer_id,
        db=seeded_db,
    )
    assert unlock_success is True

    # Verify account is unlocked
    unlocked_user = users_col.find_one({"officer_id": officer_id})
    assert unlocked_user["is_locked"] is False
    assert unlocked_user["failed_login_attempts"] == 0

    # Officer can now log in
    officer_session = AuthService.authenticate(identifier=officer_id, password=officer_password, db=seeded_db)
    assert officer_session["officer_id"] == officer_id
