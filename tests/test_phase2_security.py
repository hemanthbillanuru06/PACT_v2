"""Phase 2 Security & RBAC automated tests.

Validates service-layer access enforcement, station isolation,
and evidence file path traversal prevention.
"""
import os
import pytest
from pymongo.database import Database

from config.settings import settings
from models.user import UserSession
from models.case import FIRRecord, CaseDossier
from services.case_service import CaseService, UnauthorizedAccessError
from security.file_security import (
    validate_evidence_path,
    save_evidence_file,
    read_evidence_file,
    PathTraversalError,
)
from database.seed import seed_database


@pytest.fixture
def auth_sessions():
    """Returns authenticated session objects for various roles."""
    return {
        "admin": UserSession(
            officer_id="TS-POL-001",
            full_name="Rajesh Kumar",
            role=settings.ROLE_ADMIN,
            station_id="STN-001",
            badge_number="TS-HQ-001",
        ),
        "sp": UserSession(
            officer_id="TS-POL-002",
            full_name="Vikram Rao",
            role=settings.ROLE_SP,
            station_id="STN-001",
            badge_number="TS-HQ-002",
        ),
        "si_north": UserSession(
            officer_id="TS-POL-004",
            full_name="Kavita Reddy",
            role=settings.ROLE_SI,
            station_id="STN-002",  # North Station
            badge_number="TS-NORTH-002",
        ),
        "io_north": UserSession(
            officer_id="TS-POL-003",
            full_name="Priya Sharma",
            role=settings.ROLE_INVESTIGATING_OFFICER,
            station_id="STN-002",  # North Station
            badge_number="TS-NORTH-001",
        ),
        "si_south": UserSession(
            officer_id="TS-POL-005",
            full_name="Anand Varma",
            role=settings.ROLE_SI,
            station_id="STN-003",  # South Station
            badge_number="TS-SOUTH-001",
        ),
        "io_south": UserSession(
            officer_id="TS-POL-006",
            full_name="Sunita Rao",
            role=settings.ROLE_INVESTIGATING_OFFICER,
            station_id="STN-003",  # South Station
            badge_number="TS-SOUTH-002",
        ),
        "constable": UserSession(
            officer_id="TS-POL-007",
            full_name="Mohan Lal",
            role=settings.ROLE_CONSTABLE,
            station_id="STN-003",  # South Station
            badge_number="TS-SOUTH-003",
        ),
    }


def test_service_level_rbac_io_cannot_access_other_io_case(test_db: Database, auth_sessions):
    """Officer A (IO South) must NEVER access Officer B's (IO North) case at service layer."""
    case_service = CaseService(db=test_db)

    # 1. Create a case assigned to IO North (TS-POL-003)
    case_north = case_service.create_case(
        session=auth_sessions["io_north"],
        fir_id="TS/NORTH/2026/0101",
        title="North Electronics Heist",
        description="Theft at electronics store",
        crime_type="Burglary",
        station_id="STN-002",
        priority="HIGH",
        assigned_io_id="TS-POL-003",
    )

    # 2. IO South (TS-POL-006) attempts to access case_north
    with pytest.raises(UnauthorizedAccessError):
        case_service.get_case(auth_sessions["io_south"], case_north.case_id)

    # 3. Check audit log has recorded UNAUTHORIZED_ACCESS
    audit_entry = test_db[settings.COLLECTION_AUDIT_LOGS].find_one(
        {"event_type": settings.AUDIT_UNAUTHORIZED_ACCESS, "officer_id": "TS-POL-006"}
    )
    assert audit_entry is not None
    assert audit_entry["status"] == "DENIED"


def test_service_level_rbac_io_cannot_modify_other_io_case(test_db: Database, auth_sessions):
    """Officer A (IO South) cannot update notes or timeline on Officer B's case."""
    case_service = CaseService(db=test_db)

    case_north = case_service.create_case(
        session=auth_sessions["io_north"],
        fir_id="TS/NORTH/2026/0102",
        title="North Jewelry Theft",
        description="Jewelry store broken into",
        crime_type="Theft",
        station_id="STN-002",
        priority="MEDIUM",
        assigned_io_id="TS-POL-003",
    )

    # IO South attempts to add timeline event to North case
    with pytest.raises(UnauthorizedAccessError):
        case_service.add_timeline_event(
            session=auth_sessions["io_south"],
            case_id=case_north.case_id,
            title="Unauthorized Milestone",
            description="Attempted breach",
            event_type="INTERROGATION",
        )

    # IO South attempts to add case note to North case
    with pytest.raises(UnauthorizedAccessError):
        case_service.add_case_note(
            session=auth_sessions["io_south"],
            case_id=case_north.case_id,
            content="Unauthorized note injection",
            is_confidential=False,
        )


def test_service_level_rbac_station_si_scope(test_db: Database, auth_sessions):
    """Station SI can access all cases in their station, but not cases from other stations."""
    case_service = CaseService(db=test_db)

    # Create case in North Station STN-002
    case_north = case_service.create_case(
        session=auth_sessions["io_north"],
        fir_id="TS/NORTH/2026/0103",
        title="North Warehouse Theft",
        description="Cargo stolen from loading dock",
        crime_type="Theft",
        station_id="STN-002",
        priority="LOW",
        assigned_io_id="TS-POL-003",
    )

    # SI North CAN access case_north
    retrieved = case_service.get_case(auth_sessions["si_north"], case_north.case_id)
    assert retrieved.case_id == case_north.case_id

    # SI South CANNOT access case_north
    with pytest.raises(UnauthorizedAccessError):
        case_service.get_case(auth_sessions["si_south"], case_north.case_id)


def test_service_level_rbac_sp_and_admin_jurisdiction(test_db: Database, auth_sessions):
    """SP and ADMIN can access cases across all police stations."""
    case_service = CaseService(db=test_db)

    case_north = case_service.create_case(
        session=auth_sessions["io_north"],
        fir_id="TS/NORTH/2026/0104",
        title="Cross Jurisdiction Robbery",
        description="Bank robbery with escape vehicle",
        crime_type="Robbery",
        station_id="STN-002",
        priority="CRITICAL",
        assigned_io_id="TS-POL-003",
    )

    # SP can view and update
    sp_view = case_service.get_case(auth_sessions["sp"], case_north.case_id)
    assert sp_view is not None

    # Admin can view and update
    admin_view = case_service.get_case(auth_sessions["admin"], case_north.case_id)
    assert admin_view is not None


def test_service_level_rbac_query_filtration(test_db: Database, auth_sessions):
    """list_cases must filter at the query level, not in the UI."""
    case_service = CaseService(db=test_db)

    # Create 2 North cases and 1 South case
    case_service.create_case(
        session=auth_sessions["io_north"],
        fir_id="TS/NORTH/2026/0105",
        title="North Case 1",
        description="Case 1",
        crime_type="Theft",
        station_id="STN-002",
        priority="LOW",
        assigned_io_id="TS-POL-003",
    )
    case_service.create_case(
        session=auth_sessions["io_north"],
        fir_id="TS/NORTH/2026/0106",
        title="North Case 2",
        description="Case 2",
        crime_type="Fraud",
        station_id="STN-002",
        priority="MEDIUM",
        assigned_io_id="TS-POL-003",
    )
    case_service.create_case(
        session=auth_sessions["io_south"],
        fir_id="TS/SOUTH/2026/0101",
        title="South Case 1",
        description="South Case 1",
        crime_type="Assault",
        station_id="STN-003",
        priority="HIGH",
        assigned_io_id="TS-POL-006",
    )

    # IO North should ONLY see 2 cases in list_cases
    north_cases = case_service.list_cases(auth_sessions["io_north"])
    assert len(north_cases) == 2
    for c in north_cases:
        assert c.station_id == "STN-002"
        assert c.assigned_io_id == "TS-POL-003"

    # IO South should ONLY see 1 case
    south_cases = case_service.list_cases(auth_sessions["io_south"])
    assert len(south_cases) == 1
    assert south_cases[0].station_id == "STN-003"

    # SP sees all 3 cases
    sp_cases = case_service.list_cases(auth_sessions["sp"])
    assert len(sp_cases) == 3


def test_path_traversal_rejections():
    """Verify strict path traversal protection rejects all escape sequences."""
    malicious_inputs = [
        "../../etc/passwd",
        r"..\..\windows\system32\cmd.exe",
        "nested/../../../../secret.key",
        "case123/../../../boot.ini",
        "safe_file.pdf\0malicious.exe",
        "/etc/shadow",
        "C:\\Windows\\System32\\calc.exe",
        "..",
        ".",
    ]

    for bad_path in malicious_inputs:
        with pytest.raises(PathTraversalError):
            validate_evidence_path(bad_path)


def test_evidence_file_save_and_read_security(tmp_path):
    """Verify save_evidence_file and read_evidence_file reject path traversal attempts."""
    # Attempting to save outside evidence dir
    with pytest.raises(PathTraversalError):
        save_evidence_file(
            file_bytes=b"dangerous payload",
            original_filename="../../../hacked.txt",
            case_id="PACT-CASE-2026-TEST",
        )

    # Attempting to read outside evidence dir
    with pytest.raises(PathTraversalError):
        read_evidence_file("../../../windows/system32/cmd.exe")
