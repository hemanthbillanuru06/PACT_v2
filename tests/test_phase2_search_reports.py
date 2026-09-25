"""Phase 2 Semantic Search, Analytics, Reports, and Notifications automated tests.

Validates:
1. Semantic search finding potentially similar cases by crime type, description, and MO
2. Mandatory disclaimer enforcement ('Potentially Similar Case (Pending Corroboration)')
3. Graceful TF-IDF fallback when SentenceTransformer is unavailable
4. ReportLab PDF case dossier generation (valid PDF stream)
5. CSV case registry export
6. In-app notification creation, unread counts, and mark-as-read
"""
import pytest
from unittest.mock import patch
from pymongo.database import Database

from config.settings import settings
from models.user import UserSession
from services.case_service import CaseService
from services.semantic_search import SemanticSearchEngine
from services.report_service import ReportService
from services.notification_service import NotificationService
from database.seed_phase2 import seed_phase2


@pytest.fixture
def auth_user():
    return {
        "officer_id": "TS-POL-001",
        "role": settings.ROLE_ADMIN,
        "station_id": "STN-001",
    }


def test_semantic_search_with_disclaimer():
    """Verify semantic search returns matches labeled as Potentially Similar with disclaimer."""
    candidate_cases = [
        {
            "case_id": "CASE-001",
            "title": "Nighttime ATM skimming in Sector 1",
            "crime_type": "Cybercrime",
            "summary": "ATM skimming device placed on cash dispenser.",
            "modus_operandi": "Attaches magnetic stripe reader and spy camera to ATM keypad.",
            "station_id": "STN-001",
            "status": "UNDER INVESTIGATION",
            "priority": "HIGH",
            "io_officer_id": "TS-POL-003",
        },
        {
            "case_id": "CASE-002",
            "title": "Daylight ATM tampering in Sector 5",
            "crime_type": "Cybercrime",
            "summary": "Card skimmer found inside ATM card slot.",
            "modus_operandi": "Attaches magnetic stripe reader and pinhole camera.",
            "station_id": "STN-002",
            "status": "OPEN",
            "priority": "HIGH",
            "io_officer_id": "TS-POL-004",
        },
        {
            "case_id": "CASE-003",
            "title": "Residential burglary during daytime",
            "crime_type": "Burglary",
            "summary": "Jewelry stolen from locked apartment.",
            "modus_operandi": "Broke front door lock using crowbar while owners were away.",
            "station_id": "STN-003",
            "status": "OPEN",
            "priority": "LOW",
            "io_officer_id": "TS-POL-006",
        },
    ]

    target_case = {
        "case_id": "TARGET-001",
        "title": "Card skimming device located at North ATM",
        "crime_type": "Cybercrime",
        "summary": "Device detected by bank technician on cash machine.",
        "modus_operandi": "Attaches magnetic stripe skimmer and miniature camera to record PINs.",
    }

    results = SemanticSearchEngine.find_potentially_similar_cases(
        target_case_or_text=target_case,
        candidate_cases=candidate_cases,
        top_k=2,
        min_threshold=0.10,
    )

    assert len(results) > 0
    # The most similar should be ATM skimming cases
    top_match = results[0]
    assert top_match["case_id"] in ["CASE-001", "CASE-002"]
    assert "disclaimer" in top_match
    assert "Pending Corroboration" in top_match["disclaimer"]
    assert "Not Confirmed Connection" in top_match["disclaimer"]


def test_semantic_search_tfidf_fallback():
    """Verify system gracefully falls back to TF-IDF vectorizer if SentenceTransformer fails."""
    # Force get_model to return None (simulating model unavailable)
    with patch.object(SemanticSearchEngine, "get_model", return_value=None):
        candidate_cases = [
            {
                "case_id": "CASE-10",
                "title": "Vehicle theft red sedan",
                "crime_type": "Vehicle Theft",
                "summary": "Red sedan stolen from parking lot.",
                "modus_operandi": "Unlocked car door with wire coat hanger and hotwired ignition.",
            },
            {
                "case_id": "CASE-20",
                "title": "Identity fraud fake passports",
                "crime_type": "Forgery",
                "summary": "Forged passports seized at consulate.",
                "modus_operandi": "Printed counterfeit diplomatic visas using offset press.",
            },
        ]

        results = SemanticSearchEngine.find_potentially_similar_cases(
            target_case_or_text="Red car stolen by hotwiring ignition",
            candidate_cases=candidate_cases,
            top_k=1,
            min_threshold=0.01,
        )

        assert len(results) >= 1
        assert results[0]["case_id"] == "CASE-10"
        assert results[0]["engine_used"] == "tfidf-fallback"
        assert "disclaimer" in results[0]


def test_pdf_report_generation(test_db: Database, auth_user):
    """Test ReportLab PDF Case Dossier generation produces valid PDF bytes."""
    seed_phase2(db=test_db)

    pdf_bytes, filename = ReportService.generate_case_pdf_dossier(
        current_user=auth_user,
        case_id="PACT-CASE-2026-0042",
        db=test_db,
    )

    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 500
    # PDF files strictly start with '%PDF'
    assert pdf_bytes.startswith(b"%PDF")
    assert filename.startswith("dossier_PACT-CASE-2026-0042_")
    assert filename.endswith(".pdf")


def test_csv_cases_export(test_db: Database, auth_user):
    """Test CSV case ledger export returns formatted CSV string."""
    seed_phase2(db=test_db)

    csv_text, filename = ReportService.generate_cases_csv(
        current_user=auth_user,
        db=test_db,
    )

    assert isinstance(csv_text, str)
    assert len(csv_text) > 100
    assert "case_id,fir_number,title,crime_type,priority,status" in csv_text
    assert "PACT-CASE-2026-0042" in csv_text
    assert filename.endswith(".csv")


def test_in_app_notifications_lifecycle(test_db: Database):
    """Test creating notifications, counting unread, and marking them read."""
    # 1. Create notifications for officer TS-POL-003
    n1 = NotificationService.create_notification(
        recipient_officer_id="TS-POL-003",
        title="Case Assigned",
        message="You have been assigned as lead IO for PACT-CASE-2026-0042.",
        event_type="CASE_ASSIGNMENT",
        case_id="PACT-CASE-2026-0042",
        db=test_db,
    )
    n2 = NotificationService.create_notification(
        recipient_officer_id="TS-POL-003",
        title="Evidence Transferred",
        message="Forensic lab transferred custody of item EVD-001.",
        event_type="EVIDENCE_UPDATE",
        case_id="PACT-CASE-2026-0042",
        db=test_db,
    )

    assert n1 is not None
    assert n2 is not None

    # 2. Check unread count is 2
    unread_count = NotificationService.get_unread_count("TS-POL-003", db=test_db)
    assert unread_count == 2

    # 3. Retrieve notifications list
    notifs = NotificationService.get_user_notifications("TS-POL-003", unread_only=True, db=test_db)
    assert len(notifs) == 2

    # 4. Mark first notification as read
    NotificationService.mark_as_read(n1["notification_id"], db=test_db)

    # 5. Check unread count is now 1
    new_unread_count = NotificationService.get_unread_count("TS-POL-003", db=test_db)
    assert new_unread_count == 1
