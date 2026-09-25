"""Tests for Authentication, Password Policy, and Hashing."""
import pytest
from pymongo.database import Database

from security.passwords import (
    validate_password_policy,
    enforce_password_policy,
    PasswordPolicyError,
    hash_password,
    verify_password,
)
from services.auth_service import AuthService, InvalidCredentialsError, InactiveAccountError
from config.settings import settings


def test_password_policy_valid():
    """Verify strong passwords pass the policy."""
    is_valid, errors = validate_password_policy("Pact@Officer2026!")
    assert is_valid is True
    assert len(errors) == 0

    # Ensure no exception is raised
    enforce_password_policy("Pact@Officer2026!")


def test_password_policy_failures():
    """Verify policy rejects passwords that violate any constraint."""
    # Under 12 chars
    is_valid, errors = validate_password_policy("Pact@2026!")
    assert is_valid is False
    assert any("at least 12 characters" in e for e in errors)

    # Missing uppercase
    is_valid, errors = validate_password_policy("pact@officer2026!")
    assert is_valid is False
    assert any("uppercase" in e for e in errors)

    # Missing lowercase
    is_valid, errors = validate_password_policy("PACT@OFFICER2026!")
    assert is_valid is False
    assert any("lowercase" in e for e in errors)

    # Missing digit
    is_valid, errors = validate_password_policy("Pact@Officer!!!!")
    assert is_valid is False
    assert any("digit" in e for e in errors)

    # Missing special char
    is_valid, errors = validate_password_policy("PactOfficer202678")
    assert is_valid is False
    assert any("special character" in e for e in errors)


def test_password_policy_exception_raised():
    """Verify enforce_password_policy raises PasswordPolicyError on weak passwords."""
    with pytest.raises(PasswordPolicyError) as exc_info:
        enforce_password_policy("weak")
    assert "Password must be at least 12 characters" in str(exc_info.value)


def test_bcrypt_hashing_and_verification():
    """Verify bcrypt hash generation and verification."""
    plain = "Super@SecurePassword2026!"
    hashed = hash_password(plain)

    assert hashed.startswith("$2b$") or hashed.startswith("$2a$")
    assert verify_password(plain, hashed) is True
    assert verify_password("WrongPassword@2026!", hashed) is False
    assert verify_password("", hashed) is False


def test_authenticate_success_by_officer_id(seeded_db: Database, officer_password: str):
    """Verify successful authentication using officer_id."""
    session = AuthService.authenticate(
        identifier="TS-POL-001",
        password=officer_password,
        db=seeded_db,
    )
    assert session["officer_id"] == "TS-POL-001"
    assert session["role"] == settings.ROLE_SP
    assert session["full_name"] == "Vikramaditya Varma, IPS"

    # Verify audit log recorded LOGIN_SUCCESS
    audit_col = seeded_db[settings.COLLECTION_AUDIT_LOGS]
    log = audit_col.find_one({"officer_id": "TS-POL-001", "event_type": settings.AUDIT_LOGIN_SUCCESS})
    assert log is not None
    assert log["status"] == "SUCCESS"


def test_authenticate_success_by_email(seeded_db: Database, officer_password: str):
    """Verify successful authentication using official email."""
    session = AuthService.authenticate(
        identifier="ts-pol-003@police.gov.in",
        password=officer_password,
        db=seeded_db,
    )
    assert session["officer_id"] == "TS-POL-003"
    assert session["role"] == settings.ROLE_SI


def test_authenticate_invalid_password(seeded_db: Database):
    """Verify login with incorrect password raises InvalidCredentialsError and records LOGIN_FAILED."""
    with pytest.raises(InvalidCredentialsError):
        AuthService.authenticate(
            identifier="TS-POL-001",
            password="IncorrectPassword@999!",
            db=seeded_db,
        )

    # Verify audit log
    audit_col = seeded_db[settings.COLLECTION_AUDIT_LOGS]
    log = audit_col.find_one({"officer_id": "TS-POL-001", "event_type": settings.AUDIT_LOGIN_FAILED})
    assert log is not None
    assert log["status"] == "FAILURE"


def test_authenticate_nonexistent_user(seeded_db: Database):
    """Verify login for unknown officer raises InvalidCredentialsError."""
    with pytest.raises(InvalidCredentialsError):
        AuthService.authenticate(
            identifier="TS-UNKNOWN-999",
            password="AnyPassword@2026!",
            db=seeded_db,
        )


def test_authenticate_inactive_account(seeded_db: Database, officer_password: str):
    """Verify inactive account is blocked."""
    users_col = seeded_db[settings.COLLECTION_USERS]
    users_col.update_one({"officer_id": "TS-POL-010"}, {"$set": {"is_active": False}})

    with pytest.raises(InactiveAccountError):
        AuthService.authenticate(
            identifier="TS-POL-010",
            password=officer_password,
            db=seeded_db,
        )


def test_logout_audit(seeded_db: Database, officer_password: str):
    """Verify logout records LOGOUT audit entry."""
    session = AuthService.authenticate(
        identifier="TS-POL-001",
        password=officer_password,
        db=seeded_db,
    )
    AuthService.logout(user=session, db=seeded_db)

    audit_col = seeded_db[settings.COLLECTION_AUDIT_LOGS]
    log = audit_col.find_one({"officer_id": "TS-POL-001", "event_type": settings.AUDIT_LOGOUT})
    assert log is not None
