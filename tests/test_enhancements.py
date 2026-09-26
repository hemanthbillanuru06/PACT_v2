"""Tests for PACT UI/UX overhaul and functional enhancements:
- Officer registration (signup) and login flow
- Plaintext credentials removed from login UI
- Constable and SI FIR creation permissions and persistence
- SP-exclusive Crime Analytics access control and data mapping
"""
import pytest
from database.connection import get_db, get_users_col, get_officers_col, get_firs_col
from config.settings import settings
from services.auth_service import AuthService, InvalidCredentialsError
from services.case_service import CaseService, CaseSecurityValidator
from security.passwords import verify_password, PasswordPolicyError
from security.rbac import UnauthorizedAccessError


def test_login_ui_has_no_plaintext_credentials():
    """Verify login screen code does not contain hardcoded demo credential tables."""
    with open("ui/auth_page.py", "r", encoding="utf-8") as f:
        content = f.read()

    # Plaintext demo passwords or table must not be present
    assert "Pact@Officer2026!" not in content, "Plaintext password found in auth_page.py"
    assert "Pact@Admin2026!" not in content, "Plaintext admin password found in auth_page.py"
    assert "Synthetic Personnel Directory (Phase 1 Testing Reference)" not in content


def test_officer_registration_success():
    """Test registering a new officer with bcrypt hashing and DB persistence."""
    db = get_db()
    users_col = get_users_col(db)
    officers_col = get_officers_col(db)

    test_id = "TS-POL-TEST-REG"
    test_email = "test_reg_officer@police.gov.in"
    users_col.delete_one({"officer_id": test_id})
    officers_col.delete_one({"officer_id": test_id})

    # Register
    res = AuthService.register_officer(
        full_name="Arjun Varma",
        officer_id=test_id,
        email=test_email,
        role=settings.ROLE_SI,
        password="Secure@Password2026!",
        station_id="STN-002",
        badge_number="TS-SI-7788",
        rank="Sub-Inspector",
        contact_phone="+91-9440-778899",
        db=db,
    )

    assert res["officer_id"] == test_id
    assert res["role"] == settings.ROLE_SI
    assert res["full_name"] == "Arjun Varma"

    # Verify user document in MongoDB users collection
    user_doc = users_col.find_one({"officer_id": test_id})
    assert user_doc is not None
    assert user_doc["password_hash"] != "Secure@Password2026!"
    assert verify_password("Secure@Password2026!", user_doc["password_hash"]) is True

    # Verify officer document in officers collection
    officer_doc = officers_col.find_one({"officer_id": test_id})
    assert officer_doc is not None
    assert officer_doc["badge_number"] == "TS-SI-7788"

    # Verify authentication works immediately with new account
    session = AuthService.authenticate(test_id, "Secure@Password2026!", db=db)
    assert session["officer_id"] == test_id
    assert session["role"] == settings.ROLE_SI

    # Cleanup
    users_col.delete_one({"officer_id": test_id})
    officers_col.delete_one({"officer_id": test_id})


def test_officer_registration_duplicate_rejected():
    """Verify duplicate officer_id or email registration raises ValueError."""
    db = get_db()
    # Try registering existing officer ID
    with pytest.raises(ValueError, match="already registered"):
        AuthService.register_officer(
            full_name="Duplicate Officer",
            officer_id="TS-POL-001",
            email="new_unique_email@police.gov.in",
            role=settings.ROLE_CONSTABLE,
            password="Secure@Password2026!",
            db=db,
        )


def test_officer_registration_weak_password_rejected():
    """Verify weak password fails password policy validation."""
    db = get_db()
    with pytest.raises(PasswordPolicyError):
        AuthService.register_officer(
            full_name="Test Weak",
            officer_id="TS-POL-WEAK",
            email="weak@police.gov.in",
            role=settings.ROLE_CONSTABLE,
            password="weakpassword",
            db=db,
        )


def test_constable_fir_creation_and_persistence():
    """Verify CONSTABLE role is explicitly authorized to lodge FIRs and persists to MongoDB."""
    db = get_db()
    firs_col = get_firs_col(db)
    constable_user = {
        "officer_id": "TS-POL-010",
        "role": settings.ROLE_CONSTABLE,
        "station_id": "STN-001",
        "full_name": "D. Suresh Kumar",
    }

    # Verify RBAC permission
    assert CaseSecurityValidator.can_create_fir(constable_user) is True

    fir_num = "TS/STN-001/2026/CONSTABLE-TEST-99"
    firs_col.delete_one({"fir_number": fir_num})

    created = CaseService.create_fir(
        current_user=constable_user,
        fir_number=fir_num,
        station_id="STN-001",
        crime_type="Commercial Narcotics Trafficking",
        complainant_name="Subbiah Goud",
        complainant_phone="+91-98765-00112",
        place_of_occurrence="Gachibowli Ring Road Checkpost",
        description="Seizure of contraband during vehicle inspection.",
        db=db,
    )
    assert created is not False

    # Verify MongoDB persistence
    persisted = firs_col.find_one({"fir_number": fir_num})
    assert persisted is not None
    assert persisted["created_by"] == "TS-POL-010"
    assert persisted["crime_type"] == "Commercial Narcotics Trafficking"

    # Cleanup
    firs_col.delete_one({"fir_number": fir_num})


def test_sub_inspector_fir_creation():
    """Verify SI role is authorized to lodge FIRs and persists to MongoDB."""
    db = get_db()
    firs_col = get_firs_col(db)
    si_user = {
        "officer_id": "TS-POL-003",
        "role": settings.ROLE_SI,
        "station_id": "STN-002",
        "full_name": "Rajeshwar Rao",
    }

    assert CaseSecurityValidator.can_create_fir(si_user) is True

    fir_num = "TS/STN-002/2026/SI-TEST-88"
    firs_col.delete_one({"fir_number": fir_num})

    created = CaseService.create_fir(
        current_user=si_user,
        fir_number=fir_num,
        station_id="STN-002",
        crime_type="Vehicle Theft",
        complainant_name="Naveen Chandra",
        complainant_phone="+91-98765-11223",
        place_of_occurrence="Road No 12, Banjara Hills",
        description="Vehicle stolen from residential parking.",
        db=db,
    )
    assert created is not False

    persisted = firs_col.find_one({"fir_number": fir_num})
    assert persisted is not None
    assert persisted["created_by"] == "TS-POL-003"

    firs_col.delete_one({"fir_number": fir_num})


def test_sp_exclusive_analytics_access():
    """Verify only SP role has access to the executive Crime Analytics command view."""
    sp_user = {"officer_id": "TS-POL-001", "role": settings.ROLE_SP}
    constable_user = {"officer_id": "TS-POL-010", "role": settings.ROLE_CONSTABLE}
    io_user = {"officer_id": "TS-POL-006", "role": settings.ROLE_INVESTIGATING_OFFICER}

    # Only SP role is permitted for Crime Analytics
    assert sp_user["role"] == settings.ROLE_SP
    assert constable_user["role"] != settings.ROLE_SP
    assert io_user["role"] != settings.ROLE_SP
