"""Offline Unit and Security Tests for PACT Phase 3 (Gemini AI Integration).

Verifies Pre-Payload Authorization, Secret Sanitization, Missing-Key Graceful Degradation,
Mandatory Legal Disclaimer compliance, Audit Logging, and History Persistence WITHOUT live network calls.
"""
from datetime import datetime, timezone
import pytest
from unittest.mock import MagicMock
from pymongo.database import Database

from config.settings import settings
from database.connection import get_db, get_cases_col, get_ai_analysis_history_col, get_audit_logs_col
from security.rbac import UnauthorizedAccessError
from security.sanitizer import sanitize_text, sanitize_payload
from services.ai_prompts import AIPromptBuilder, MANDATORY_DISCLAIMER
from services.gemini_service import GeminiService, GeminiAnalysisResult, GeminiKeyMissingError


@pytest.fixture
def mock_genai_client():
    """Mock Google GenAI client returning a valid structured response."""
    client = MagicMock()
    mock_response = MagicMock()
    mock_response.text = (
        "Executive Summary: Targeted keyless vehicle theft executed via CAN-bus injector tool.\n"
        "Suspect: Ravi 'Keyless' Teja remains wanted.\n\n"
        f"*{MANDATORY_DISCLAIMER}*"
    )
    client.models.generate_content.return_value = mock_response
    return client


def test_secret_sanitization_patterns():
    """Verify that credentials, connection strings, and tokens are scrubbed."""
    raw_text = (
        "Connect to mongodb://admin:SecretPass123@cluster0.mongodb.net/pact_db with "
        "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-ID and api_key='AIzaSyD-1234567890abcdef1234567890abcde' "
        "and password = 'SuperSecretOfficerPassword!'"
    )
    sanitized = sanitize_text(raw_text)

    assert "mongodb://" not in sanitized
    assert "SecretPass123" not in sanitized
    assert "[REDACTED_DB_CONNECTION]" in sanitized
    assert "[REDACTED_TOKEN]" in sanitized
    assert "[REDACTED_API_KEY]" in sanitized
    assert "[REDACTED_PASSWORD]" in sanitized


def test_secret_sanitization_payload_dict():
    """Verify that dictionary keys and nested values are properly scrubbed."""
    raw_dict = {
        "case_id": "PACT-CASE-2026-0042",
        "password": "ClearTextPassword123",
        "api_key": "AIzaSyD-sampleKeyHere12345678901234",
        "nested": {
            "token": "secret_token_value",
            "connection_string": "mongodb://localhost:27017/pact_db",
        },
    }
    cleaned = sanitize_payload(raw_dict)

    assert cleaned["case_id"] == "PACT-CASE-2026-0042"
    assert cleaned["password"] == "[REDACTED_SECRET]"
    assert cleaned["api_key"] == "[REDACTED_SECRET]"
    assert cleaned["nested"]["token"] == "[REDACTED_SECRET]"
    assert "[REDACTED_DB_CONNECTION]" in cleaned["nested"]["connection_string"]


def test_prompt_builder_grounding_and_mandatory_disclaimer():
    """Verify that prompt builder injects case context, prohibits hallucination, and requires disclaimer."""
    sample_case_data = {
        "case": {
            "case_id": "PACT-CASE-2026-0042",
            "title": "Midnight Grand Theft of Luxury SUV",
            "crime_type": "Vehicle Theft",
            "priority": "HIGH",
            "status": "UNDER INVESTIGATION",
            "station_id": "North Station",
            "io_officer_id": "TS-POL-003",
            "summary": "Toyota Fortuner stolen using relay amplifier.",
            "modus_operandi": "CAN-bus injector and keyless relay attack.",
        },
        "fir": {"fir_number": "TS/NORTH/2026/0042", "description": "Complainant parked SUV at commercial bay."},
        "suspects": [{"name": "Ravi Teja", "status": "WANTED"}],
        "victims": [],
        "complainants": [{"name": "Arvind Murthy", "contact_phone": "+91-98490-55441"}],
        "witnesses": [],
        "property_items": [{"item_name": "Toyota Fortuner", "custody_status": "UNRECOVERED"}],
        "evidence": [{"evidence_id": "EV-001", "original_filename": "cctv_clip.mp4"}],
        "timeline": [],
        "notes": [],
    }

    prompt = AIPromptBuilder.build_case_summary_prompt(sample_case_data)
    assert "PACT-CASE-2026-0042" in prompt
    assert "Vehicle Theft" in prompt
    assert "CAN-bus injector" in prompt
    assert "Ravi Teja" in prompt
    assert "mandatory disclaimer" in prompt.lower()


def test_gemini_missing_key_graceful_degradation(monkeypatch):
    """Verify that a missing API key gracefully degrades without crashing and audits the failure."""
    test_db = get_db()
    # Unset API key
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    service = GeminiService(db=test_db)
    officer_user = {
        "officer_id": "TS-POL-003",
        "role": settings.ROLE_INVESTIGATING_OFFICER,
        "station_id": "North Station",
    }

    res = service.analyze_case(
        current_user=officer_user,
        case_id="PACT-CASE-2026-0042",
        analysis_type="CASE_SUMMARY",
    )

    assert res.status == "KEY_MISSING"
    assert "Gemini API key is not configured" in res.error_message
    assert res.output == ""

    # Verify audit failure was logged
    audit_col = get_audit_logs_col(test_db)
    fail_audit = audit_col.find_one({
        "event_type": settings.AUDIT_AI_ANALYSIS_FAILED,
        "officer_id": "TS-POL-003",
        "details.error_reason": "GEMINI_API_KEY_NOT_CONFIGURED",
    })
    assert fail_audit is not None


def test_pre_payload_authorization_cross_officer_isolation():
    """Verify that Officer A cannot run AI analysis on Officer B's protected case."""
    test_db = get_db()
    cases_col = get_cases_col(test_db)

    # Ensure a case owned by TS-POL-004 exists
    other_case_id = "PACT-CASE-2026-TEST-ISOLATION"
    cases_col.update_one(
        {"case_id": other_case_id},
        {
            "$set": {
                "case_id": other_case_id,
                "title": "Secret Cyber Extortion",
                "station_id": "Cyberabad Central",
                "io_officer_id": "TS-POL-004",
                "assigned_officers": ["TS-POL-004"],
                "status": "UNDER INVESTIGATION",
                "priority": "HIGH",
            }
        },
        upsert=True,
    )

    # Officer TS-POL-003 attempts to analyze TS-POL-004's case
    unauthorized_officer = {
        "officer_id": "TS-POL-003",
        "role": settings.ROLE_INVESTIGATING_OFFICER,
        "station_id": "North Station",
    }

    service = GeminiService(db=test_db)
    with pytest.raises(UnauthorizedAccessError):
        service.analyze_case(
            current_user=unauthorized_officer,
            case_id=other_case_id,
            analysis_type="CASE_SUMMARY",
        )

    # Verify audit blocked entry
    audit_col = get_audit_logs_col(test_db)
    blocked_audit = audit_col.find_one({
        "event_type": settings.AUDIT_AI_ANALYSIS_FAILED,
        "officer_id": "TS-POL-003",
        "details.error_reason": "UNAUTHORIZED_CASE_ACCESS",
    })
    assert blocked_audit is not None


def test_pre_payload_authorization_history_isolation():
    """Verify that Officer A cannot view Officer B's AI analysis history."""
    test_db = get_db()
    unauthorized_officer = {
        "officer_id": "TS-POL-003",
        "role": settings.ROLE_INVESTIGATING_OFFICER,
        "station_id": "North Station",
    }
    other_case_id = "PACT-CASE-2026-TEST-ISOLATION"

    service = GeminiService(db=test_db)
    with pytest.raises(UnauthorizedAccessError):
        service.get_case_ai_history(
            current_user=unauthorized_officer,
            case_id=other_case_id,
        )


def test_mocked_gemini_generation_and_history_persistence(mock_genai_client):
    """Verify complete AI analysis pipeline, history persistence, and audit trail using mocked SDK client."""
    test_db = get_db()
    service = GeminiService(db=test_db, client=mock_genai_client)

    authorized_officer = {
        "officer_id": "TS-POL-003",
        "role": settings.ROLE_INVESTIGATING_OFFICER,
        "station_id": "North Station",
    }

    result = service.analyze_case(
        current_user=authorized_officer,
        case_id="PACT-CASE-2026-0042",
        analysis_type="INVESTIGATION_BRIEF",
    )

    assert result.status == "SUCCESS"
    assert "Executive Summary" in result.output
    assert MANDATORY_DISCLAIMER in result.output
    assert result.duration_seconds >= 0.0

    # Verify record in ai_analysis_history collection
    history_col = get_ai_analysis_history_col(test_db)
    record = history_col.find_one({"analysis_id": result.analysis_id})
    assert record is not None
    assert record["case_id"] == "PACT-CASE-2026-0042"
    assert record["officer_id"] == "TS-POL-003"
    assert record["analysis_type"] == "INVESTIGATION_BRIEF"
    assert record["status"] == "COMPLETED"

    # Verify retrieval via get_case_ai_history
    history_records = service.get_case_ai_history(authorized_officer, "PACT-CASE-2026-0042")
    assert any(h["analysis_id"] == result.analysis_id for h in history_records)

    # Verify audit events
    audit_col = get_audit_logs_col(test_db)
    req_audit = audit_col.find_one({
        "event_type": settings.AUDIT_AI_ANALYSIS_REQUESTED,
        "details.analysis_id": result.analysis_id,
    })
    comp_audit = audit_col.find_one({
        "event_type": settings.AUDIT_AI_ANALYSIS_COMPLETED,
        "details.analysis_id": result.analysis_id,
    })
    assert req_audit is not None
    assert comp_audit is not None
