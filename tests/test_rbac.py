"""Tests for Centralized Backend Role-Based Access Control (RBAC)."""
import pytest
from pymongo.database import Database

from config.settings import settings
from security.rbac import (
    enforce_role,
    require_role,
    UnauthorizedAccessError,
    has_permission,
    get_role_permissions,
)
from services.user_service import UserService
from services.station_service import StationService


def test_role_permissions_assignment():
    """Verify distinct permission sets per role."""
    admin_perms = get_role_permissions(settings.ROLE_ADMIN)
    sp_perms = get_role_permissions(settings.ROLE_SP)
    si_perms = get_role_permissions(settings.ROLE_SI)
    io_perms = get_role_permissions(settings.ROLE_INVESTIGATING_OFFICER)
    constable_perms = get_role_permissions(settings.ROLE_CONSTABLE)

    assert "admin:manage_users" in admin_perms
    assert "admin:manage_users" not in sp_perms
    assert "sensitive_intel:access" in sp_perms
    assert "cases:station_view" in si_perms
    assert "cases:evidence_catalog" in io_perms
    assert "patrol:beat_report_write" in constable_perms


def test_enforce_role_authorized():
    """Verify authorized users pass enforce_role without error."""
    admin_user = {"role": settings.ROLE_ADMIN, "officer_id": "TS-POL-012"}
    sp_user = {"role": settings.ROLE_SP, "officer_id": "TS-POL-001"}

    # Should not raise
    enforce_role(admin_user, [settings.ROLE_ADMIN, settings.ROLE_SP])
    enforce_role(sp_user, [settings.ROLE_ADMIN, settings.ROLE_SP])


def test_enforce_role_unauthorized_raises():
    """Verify unauthorized user role raises UnauthorizedAccessError."""
    constable_user = {"role": settings.ROLE_CONSTABLE, "officer_id": "TS-POL-010"}

    with pytest.raises(UnauthorizedAccessError) as exc_info:
        enforce_role(constable_user, [settings.ROLE_ADMIN, settings.ROLE_SP], resource_name="admin_panel")

    assert "Unauthorized" in str(exc_info.value)
    assert exc_info.value.role == settings.ROLE_CONSTABLE
    assert exc_info.value.resource == "admin_panel"


def test_enforce_role_unauthenticated_raises():
    """Verify None/missing user raises UnauthorizedAccessError."""
    with pytest.raises(UnauthorizedAccessError):
        enforce_role(None, [settings.ROLE_ADMIN])


def test_require_role_decorator():
    """Verify @require_role decorator protects functions."""
    @require_role([settings.ROLE_ADMIN])
    def sensitive_operation(current_user=None):
        return "classified"

    admin_user = {"role": settings.ROLE_ADMIN, "officer_id": "TS-POL-012"}
    io_user = {"role": settings.ROLE_INVESTIGATING_OFFICER, "officer_id": "TS-POL-006"}

    # Admin succeeds
    assert sensitive_operation(current_user=admin_user) == "classified"

    # IO fails
    with pytest.raises(UnauthorizedAccessError):
        sensitive_operation(current_user=io_user)


def test_service_level_rbac_unlock_account(seeded_db: Database):
    """Verify UserService.unlock_user_account is restricted strictly to ADMIN."""
    sp_user = {"role": settings.ROLE_SP, "officer_id": "TS-POL-001", "user_id": "sp1"}
    io_user = {"role": settings.ROLE_INVESTIGATING_OFFICER, "officer_id": "TS-POL-006", "user_id": "io1"}
    admin_user = {"role": settings.ROLE_ADMIN, "officer_id": "TS-POL-012", "user_id": "admin1"}
    audit_col = seeded_db[settings.COLLECTION_AUDIT_LOGS]

    # SP tries to unlock - must be blocked
    with pytest.raises(UnauthorizedAccessError):
        UserService.unlock_user_account(current_user=sp_user, target_officer_id="TS-POL-006", db=seeded_db)

    # Verify UNAUTHORIZED_ACCESS was logged to audit collection
    unauth_log = audit_col.find_one({"officer_id": "TS-POL-001", "event_type": settings.AUDIT_UNAUTHORIZED_ACCESS})
    assert unauth_log is not None
    assert unauth_log["status"] == "DENIED"

    # IO tries to unlock - must be blocked
    with pytest.raises(UnauthorizedAccessError):
        UserService.unlock_user_account(current_user=io_user, target_officer_id="TS-POL-006", db=seeded_db)

    # Admin tries to unlock - succeeds without raising UnauthorizedAccessError
    UserService.unlock_user_account(current_user=admin_user, target_officer_id="TS-POL-006", db=seeded_db)


def test_service_level_rbac_directory_access(seeded_db: Database):
    """Verify officer directory access is permitted for ADMIN, SP, SI but blocked for CONSTABLE."""
    si_user = {"role": settings.ROLE_SI, "officer_id": "TS-POL-003"}
    constable_user = {"role": settings.ROLE_CONSTABLE, "officer_id": "TS-POL-010"}

    # SI can view officers
    officers = UserService.get_officers_list(current_user=si_user, db=seeded_db)
    assert len(officers) >= 12

    # Constable cannot view officers
    with pytest.raises(UnauthorizedAccessError):
        UserService.get_officers_list(current_user=constable_user, db=seeded_db)


def test_service_level_rbac_station_creation(seeded_db: Database):
    """Verify only ADMIN can create police stations."""
    sp_user = {"role": settings.ROLE_SP, "officer_id": "TS-POL-001"}
    admin_user = {"role": settings.ROLE_ADMIN, "officer_id": "TS-POL-012"}

    new_station = {
        "station_id": "STN-TEST-999",
        "name": "Test Border Outpost",
        "station_code": "BORDER-999",
    }

    # SP denied
    with pytest.raises(UnauthorizedAccessError):
        StationService.add_station(current_user=sp_user, station_data=new_station, db=seeded_db)

    # Admin authorized
    success = StationService.add_station(current_user=admin_user, station_data=new_station, db=seeded_db)
    assert success is True
