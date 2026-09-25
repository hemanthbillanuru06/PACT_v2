"""Phase 2 Core Features Automated Tests.

Validates:
1. Mandatory Showcase Case PACT-CASE-2026-0042 data integrity
2. Complete FIR and Case Dossier lifecycle
3. Timeline milestones and Case diary notes
4. Entity tracking (Complainants, Victims, Suspects, Witnesses, Property)
"""
import pytest
from pymongo.database import Database

from config.settings import settings
from models.user import UserSession
from models.entities import Complainant, Victim, Suspect, Witness, PropertyItem
from services.case_service import CaseService
from services.entity_service import EntityService
from database.seed_phase2 import seed_phase2


@pytest.fixture
def io_session():
    """North Station Investigating Officer session."""
    return UserSession(
        officer_id="TS-POL-003",
        full_name="Priya Sharma",
        role=settings.ROLE_INVESTIGATING_OFFICER,
        station_id="STN-002",
        badge_number="TS-NORTH-001",
    )


@pytest.fixture
def admin_session():
    """HQ Admin session."""
    return UserSession(
        officer_id="TS-POL-001",
        full_name="Rajesh Kumar",
        role=settings.ROLE_ADMIN,
        station_id="STN-001",
        badge_number="TS-HQ-001",
    )


def test_mandatory_showcase_case_integrity(test_db: Database, admin_session):
    """Verify mandatory showcase case PACT-CASE-2026-0042 satisfies all required specs."""
    seed_phase2(db=test_db)
    case_service = CaseService(db=test_db)

    showcase_case = case_service.get_case(admin_session, "PACT-CASE-2026-0042")
    assert showcase_case is not None
    assert showcase_case.case_id == "PACT-CASE-2026-0042"
    assert showcase_case.fir_id == "TS/NORTH/2026/0042"
    assert showcase_case.crime_type == "Vehicle Theft"
    assert showcase_case.priority == "HIGH"
    assert showcase_case.status == "UNDER INVESTIGATION"
    assert showcase_case.assigned_io_id == "TS-POL-003"
    assert showcase_case.station_id in ["North Station", "STN-002", "STN-005"]

    # Verify corresponding FIR exists in firs collection
    fir_doc = test_db[settings.COLLECTION_FIRS].find_one({"fir_number": "TS/NORTH/2026/0042"})
    assert fir_doc is not None
    assert fir_doc["crime_type"] == "Vehicle Theft"
    assert fir_doc["station_id"] in ["North Station", "STN-002", "STN-005"]

    # Verify associated timeline milestones exist
    timeline = case_service.get_timeline(admin_session, "PACT-CASE-2026-0042")
    assert len(timeline) >= 2


def test_fir_creation_and_retrieval(test_db: Database, io_session):
    """Test FIR creation with validation, custom/auto numbering, and DB storage."""
    case_service = CaseService(db=test_db)

    fir = case_service.create_fir(
        session=io_session,
        incident_date="2026-03-10",
        place_of_occurrence="Main Bazaar, North Road",
        crime_type="Chain Snatching",
        acts_and_sections="IPC 379 / IPC 356",
        complainant_name="Meera Bai",
        complainant_contact="+91 98765 43210",
        details="Gold chain snatched by two motorcycle riders.",
        fir_number="TS/NORTH/2026/0999",
    )

    assert fir.fir_number == "TS/NORTH/2026/0999"
    assert fir.status == "REGISTERED"

    # Retrieve FIR
    retrieved = case_service.get_fir(io_session, fir.fir_number)
    assert retrieved is not None
    assert retrieved.complainant_name == "Meera Bai"
    assert retrieved.crime_type == "Chain Snatching"


def test_case_dossier_lifecycle(test_db: Database, io_session):
    """Test Case Dossier creation, status updates, and note tracking."""
    case_service = CaseService(db=test_db)

    # 1. Create FIR
    fir = case_service.create_fir(
        session=io_session,
        incident_date="2026-03-11",
        place_of_occurrence="Sector 4 Bank ATM",
        crime_type="ATM Card Skimming",
        acts_and_sections="IT Act Sec 66C",
        complainant_name="Kishore Kumar",
        details="Unauthorized ATM withdrawals.",
        fir_number="TS/NORTH/2026/0888",
    )

    # 2. Create Case Dossier
    case = case_service.create_case(
        session=io_session,
        fir_id=fir.fir_number,
        title="Sector 4 ATM Skimming Syndicate",
        description="Clone card syndicate skimming magnetic strips",
        crime_type="Cybercrime",
        station_id=io_session.station_id,
        priority="HIGH",
        assigned_io_id=io_session.officer_id,
        modus_operandi="Installed magnetic skimmer and pinhole camera on ATM bezel.",
    )

    assert case.case_id.startswith("PACT-CASE-")
    assert case.status == "UNDER INVESTIGATION"

    # 3. Add timeline milestone
    tl_event = case_service.add_timeline_event(
        session=io_session,
        case_id=case.case_id,
        title="ATM CCTV Footage Collected",
        description="Retrieved 4 hours of surveillance video from bank server.",
        event_type="EVIDENCE_ACQUIRED",
        location="Sector 4 Bank Branch",
    )
    assert tl_event.event_id is not None

    timeline = case_service.get_timeline(io_session, case.case_id)
    assert len(timeline) == 1
    assert timeline[0].title == "ATM CCTV Footage Collected"

    # 4. Add case diary note
    note = case_service.add_case_note(
        session=io_session,
        case_id=case.case_id,
        content="Informant reported suspect vehicle was a dark blue sedan with fake plates.",
        is_confidential=True,
    )
    assert note.note_id is not None

    notes = case_service.get_case_notes(io_session, case.case_id)
    assert len(notes) == 1
    assert notes[0].content == note.content
    assert notes[0].is_confidential is True

    # 5. Update case status
    updated_case = case_service.update_case_status(
        session=io_session,
        case_id=case.case_id,
        new_status="CHARGESHEET FILED",
        summary="Chargesheet filed against 2 suspects before Judicial Magistrate.",
    )
    assert updated_case.status == "CHARGESHEET FILED"


def test_entity_tracking_crud(test_db: Database, io_session):
    """Test Complainant, Victim, Suspect, Witness, and Property tracking."""
    case_service = CaseService(db=test_db)
    entity_service = EntityService(db=test_db)

    # Create Case
    case = case_service.create_case(
        session=io_session,
        fir_id="TS/NORTH/2026/0777",
        title="Commercial Warehouse Break-in",
        description="Warehouse break-in and cargo loss",
        crime_type="Burglary",
        station_id=io_session.station_id,
        priority="MEDIUM",
        assigned_io_id=io_session.officer_id,
    )

    # 1. Add Suspect
    suspect = entity_service.add_suspect(
        session=io_session,
        case_id=case.case_id,
        name="Ramesh alias Chotu",
        aliases=["Chotu", "Target 1"],
        age=32,
        gender="Male",
        status="ARRESTED",
        identifying_marks="Scar across left cheek",
        address="Old Town Slums, North Dist",
    )
    assert suspect.entity_id is not None

    # 2. Add Victim
    victim = entity_service.add_victim(
        session=io_session,
        case_id=case.case_id,
        name="Deepak Logistics Pvt Ltd",
        contact_number="+91 40 2345 6789",
        injury_status="NONE",
    )
    assert victim.entity_id is not None

    # 3. Add Witness
    witness = entity_service.add_witness(
        session=io_session,
        case_id=case.case_id,
        name="Gopal Singh",
        statement_summary="Saw two men loading cartons into a white pickup at 02:30 AM.",
        credibility_rating="HIGH",
    )
    assert witness.entity_id is not None

    # 4. Add Property Item
    property_item = entity_service.add_property(
        session=io_session,
        case_id=case.case_id,
        category="ELECTRONICS",
        item_description="20 Cartons of Smartphone Components",
        estimated_value=1500000.0,
        status="RECOVERED",
        storage_location="North Station Malkhana, Shelf B-4",
    )
    assert property_item.property_id is not None

    # Retrieve all entities for this case
    entities = entity_service.get_all_entities_for_case(io_session, case.case_id)
    assert len(entities["suspects"]) == 1
    assert entities["suspects"][0].name == "Ramesh alias Chotu"
    assert len(entities["victims"]) == 1
    assert len(entities["witnesses"]) == 1
    assert len(entities["property_items"]) == 1
    assert entities["property_items"][0].estimated_value == 1500000.0
