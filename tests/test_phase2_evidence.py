"""Phase 2 Evidence Handling & Chain of Custody automated tests.

Validates:
1. Ingestion of physical & digital evidence files into data/evidence/
2. SHA-256 calculation and verification against stored bytes
3. Audit logging of EVIDENCE_ADDED, EVIDENCE_VIEWED, EVIDENCE_DOWNLOADED, EVIDENCE_TRANSFERRED
4. Chain of custody transfers between investigating officers
"""
import hashlib
import os
import pytest
from pymongo.database import Database

from config.settings import settings
from models.user import UserSession
from services.case_service import CaseService
from services.evidence_service import EvidenceService
from security.file_security import read_evidence_file, PathTraversalError


@pytest.fixture
def test_officers():
    return {
        "io_north": {
            "officer_id": "TS-POL-003",
            "role": settings.ROLE_INVESTIGATING_OFFICER,
            "station_id": "STN-002",
        },
        "forensic_officer": {
            "officer_id": "TS-POL-004",
            "role": settings.ROLE_SI,
            "station_id": "STN-002",
        },
        "io_south": {
            "officer_id": "TS-POL-006",
            "role": settings.ROLE_INVESTIGATING_OFFICER,
            "station_id": "STN-003",
        },
    }


def test_evidence_ingestion_and_sha256(test_db: Database, test_officers):
    """Test evidence file ingestion, SHA-256 calculation, and local file storage."""
    # 1. Create case in test_db
    case_service = CaseService(db=test_db)
    session = UserSession(
        officer_id="TS-POL-003",
        full_name="Priya Sharma",
        role=settings.ROLE_INVESTIGATING_OFFICER,
        station_id="STN-002",
        badge_number="TS-NORTH-001",
    )
    case = case_service.create_case(
        session=session,
        fir_id="TS/NORTH/2026/0201",
        title="Armed Jewelry Robbery",
        description="Armed heist at diamond outlet",
        crime_type="Armed Robbery",
        station_id="STN-002",
        priority="CRITICAL",
        assigned_io_id="TS-POL-003",
    )

    # 2. Ingest evidence file
    sample_content = b"EVIDENCE FILE DATA: Surveillance camera stream frame timestamp 2026-03-12 14:22:01"
    expected_sha256 = hashlib.sha256(sample_content).hexdigest()

    evidence_doc = EvidenceService.register_evidence(
        current_user=test_officers["io_north"],
        case_id=case.case_id,
        content=sample_content,
        original_filename="cctv_frame_1422.jpg",
        name="CCTV Camera 2 Frame",
        evidence_type="IMAGE",
        description="Clear frame showing getaway motorcycle license plate.",
        storage_location="Vault A, Locker 3",
        db=test_db,
    )

    # Verify metadata in DB
    assert evidence_doc["sha256_hash"] == expected_sha256
    assert evidence_doc["current_custodian_id"] == "TS-POL-003"
    assert evidence_doc["file_size_bytes"] == len(sample_content)

    # Verify physical file existence and content
    disk_bytes = read_evidence_file(evidence_doc["stored_filename"])
    assert disk_bytes == sample_content

    # Verify audit log recorded EVIDENCE_ADDED
    audit_log = test_db[settings.COLLECTION_AUDIT_LOGS].find_one(
        {"event_type": settings.AUDIT_EVIDENCE_ADDED, "details.evidence_id": evidence_doc["evidence_id"]}
    )
    assert audit_log is not None
    assert audit_log["officer_id"] == "TS-POL-003"
    assert audit_log["status"] == "SUCCESS"


def test_evidence_download_and_view(test_db: Database, test_officers):
    """Test evidence viewing and downloading with audit logs."""
    case_service = CaseService(db=test_db)
    session = UserSession(
        officer_id="TS-POL-003",
        full_name="Priya Sharma",
        role=settings.ROLE_INVESTIGATING_OFFICER,
        station_id="STN-002",
        badge_number="TS-NORTH-001",
    )
    case = case_service.create_case(
        session=session,
        fir_id="TS/NORTH/2026/0202",
        title="Highway Extortion Case",
        description="Extortion on NH-44",
        crime_type="Extortion",
        station_id="STN-002",
        priority="HIGH",
        assigned_io_id="TS-POL-003",
    )

    sample_content = b"PDF FORENSIC REPORT: Toll plaza transit log"
    evidence_doc = EvidenceService.register_evidence(
        current_user=test_officers["io_north"],
        case_id=case.case_id,
        content=sample_content,
        original_filename="toll_log.pdf",
        name="Toll Plaza Log",
        evidence_type="DOCUMENT",
        db=test_db,
    )

    # Test listing case evidence
    evidence_list = EvidenceService.get_case_evidence(
        current_user=test_officers["io_north"],
        case_id=case.case_id,
        db=test_db,
    )
    assert len(evidence_list) == 1

    # Verify EVIDENCE_VIEWED audit log
    view_log = test_db[settings.COLLECTION_AUDIT_LOGS].find_one(
        {"event_type": settings.AUDIT_EVIDENCE_VIEWED, "officer_id": "TS-POL-003"}
    )
    assert view_log is not None

    # Test downloading evidence
    downloaded_bytes, filename, mime = EvidenceService.download_evidence(
        current_user=test_officers["io_north"],
        evidence_id=evidence_doc["evidence_id"],
        db=test_db,
    )
    assert downloaded_bytes == sample_content
    assert filename == "toll_log.pdf"

    # Verify EVIDENCE_DOWNLOADED audit log
    download_log = test_db[settings.COLLECTION_AUDIT_LOGS].find_one(
        {"event_type": settings.AUDIT_EVIDENCE_DOWNLOADED, "officer_id": "TS-POL-003"}
    )
    assert download_log is not None


def test_chain_of_custody_transfer(test_db: Database, test_officers):
    """Test chain of custody transfer between officers and audit logging."""
    case_service = CaseService(db=test_db)
    session = UserSession(
        officer_id="TS-POL-003",
        full_name="Priya Sharma",
        role=settings.ROLE_INVESTIGATING_OFFICER,
        station_id="STN-002",
        badge_number="TS-NORTH-001",
    )
    case = case_service.create_case(
        session=session,
        fir_id="TS/NORTH/2026/0203",
        title="Counterfeit Currency Racket",
        description="Distribution of fake notes",
        crime_type="Counterfeiting",
        station_id="STN-002",
        priority="HIGH",
        assigned_io_id="TS-POL-003",
    )

    evidence_doc = EvidenceService.register_evidence(
        current_user=test_officers["io_north"],
        case_id=case.case_id,
        content=b"SEIZED NOTE SERIAL NUMBERS: 4AA 123456",
        original_filename="counterfeit_notes.txt",
        name="Specimen Counterfeit Notes",
        evidence_type="PHYSICAL",
        db=test_db,
    )

    # Initial custodian is IO North
    assert evidence_doc["current_custodian_id"] == "TS-POL-003"

    # Transfer custody to Forensic Officer TS-POL-004
    transferred = EvidenceService.transfer_custody(
        current_user=test_officers["io_north"],
        evidence_id=evidence_doc["evidence_id"],
        to_officer_id="TS-POL-004",
        reason="Forensic ink and paper analysis",
        notes="Transferred with intact tamper-evident seal #78891",
        db=test_db,
    )
    assert transferred is True

    # Verify current custodian updated in DB
    updated_evidence = test_db[settings.COLLECTION_EVIDENCE].find_one(
        {"evidence_id": evidence_doc["evidence_id"]}
    )
    assert updated_evidence["current_custodian_id"] == "TS-POL-004"

    # Verify custody history records initial + transfer (total 2 records)
    custody_history = EvidenceService.get_custody_history(
        current_user=test_officers["io_north"],
        evidence_id=evidence_doc["evidence_id"],
        db=test_db,
    )
    assert len(custody_history) == 2
    assert custody_history[1]["to_officer_id"] == "TS-POL-004"
    assert custody_history[1]["transfer_reason"] == "Forensic ink and paper analysis"

    # Verify EVIDENCE_TRANSFERRED audit log
    transfer_log = test_db[settings.COLLECTION_AUDIT_LOGS].find_one(
        {"event_type": settings.AUDIT_EVIDENCE_TRANSFERRED, "officer_id": "TS-POL-003"}
    )
    assert transfer_log is not None
    assert transfer_log["details"]["to_officer"] == "TS-POL-004"
