"""Live Integration Tests for PACT Phase 3 (Google Gemini AI Integration).

Executes real network calls against the official Google GenAI SDK using GEMINI_API_KEY from .env.
Verifies response generation, grounding, mandatory legal disclaimer, audit logging,
failure recovery, cross-officer RBAC isolation, and history persistence.
"""
import os
import time
import pytest
from dotenv import load_dotenv

load_dotenv(override=True)

from config.settings import settings
from database.connection import get_db, get_cases_col, get_ai_analysis_history_col, get_audit_logs_col
from security.rbac import UnauthorizedAccessError
from services.ai_prompts import MANDATORY_DISCLAIMER
from services.gemini_service import GeminiService


@pytest.fixture(autouse=True)
def ensure_env_key():
    """Ensure GEMINI_API_KEY is configured from environment."""
    key = os.getenv("GEMINI_API_KEY", "").strip()
    if not key:
        pytest.skip("GEMINI_API_KEY is not set in environment or .env. Skipping live tests.")


def test_live_gemini_case_summary_generation_and_disclaimer():
    """Verify live Gemini content generation, parsing, disclaimer enforcement, and DB persistence."""
    test_db = get_db()
    authorized_officer = {
        "officer_id": "TS-POL-003",
        "role": settings.ROLE_INVESTIGATING_OFFICER,
        "station_id": "North Station",
    }

    service = GeminiService(db=test_db)
    result = service.analyze_case(
        current_user=authorized_officer,
        case_id="PACT-CASE-2026-0042",
        analysis_type="CASE_SUMMARY",
    )

    assert result.status == "SUCCESS", f"Expected SUCCESS, got {result.status}: {result.error_message}"
    assert len(result.output) > 50
    assert MANDATORY_DISCLAIMER in result.output
    assert result.duration_seconds > 0.0

    # Verify MongoDB persistence in ai_analysis_history
    history_col = get_ai_analysis_history_col(test_db)
    record = history_col.find_one({"analysis_id": result.analysis_id})
    assert record is not None
    assert record["case_id"] == "PACT-CASE-2026-0042"
    assert record["officer_id"] == "TS-POL-003"
    assert record["analysis_type"] == "CASE_SUMMARY"
    assert record["status"] == "COMPLETED"

    # Verify audit trail
    audit_col = get_audit_logs_col(test_db)
    comp_audit = audit_col.find_one({
        "event_type": settings.AUDIT_AI_ANALYSIS_COMPLETED,
        "details.analysis_id": result.analysis_id,
    })
    assert comp_audit is not None


def test_live_gemini_officer_qa_grounding():
    """Verify live interactive Officer Q&A grounded strictly in case dossier data."""
    time.sleep(2)
    test_db = get_db()
    authorized_officer = {
        "officer_id": "TS-POL-003",
        "role": settings.ROLE_INVESTIGATING_OFFICER,
        "station_id": "North Station",
    }

    service = GeminiService(db=test_db)
    result = service.analyze_case(
        current_user=authorized_officer,
        case_id="PACT-CASE-2026-0042",
        analysis_type="OFFICER_QA",
        officer_query="What make and model of vehicle was reported stolen in this case?",
    )

    assert result.status == "SUCCESS", f"Expected SUCCESS, got {result.status}: {result.error_message}"
    # Grounding check: The stolen vehicle in PACT-CASE-2026-0042 is a Toyota Fortuner
    assert any(term in result.output.lower() for term in ["toyota", "fortuner", "suv"])
    assert MANDATORY_DISCLAIMER in result.output


def test_live_cross_officer_isolation_enforced_before_api_call():
    """Verify that Officer A cannot send Officer B's case data to Gemini."""
    test_db = get_db()
    cases_col = get_cases_col(test_db)

    # Protected case assigned strictly to TS-POL-004
    isolated_case_id = "PACT-CASE-2026-TEST-LIVE-ISOLATION"
    cases_col.update_one(
        {"case_id": isolated_case_id},
        {
            "$set": {
                "case_id": isolated_case_id,
                "title": "Confidential Cyber Extortion",
                "station_id": "STN-001",
                "io_officer_id": "TS-POL-004",
                "assigned_officers": ["TS-POL-004"],
                "status": "UNDER INVESTIGATION",
                "priority": "CRITICAL",
                "summary": "Confidential financial fraud dossier.",
            }
        },
        upsert=True,
    )

    unauthorized_officer = {
        "officer_id": "TS-POL-003",
        "role": settings.ROLE_INVESTIGATING_OFFICER,
        "station_id": "North Station",
    }

    service = GeminiService(db=test_db)
    with pytest.raises(UnauthorizedAccessError):
        service.analyze_case(
            current_user=unauthorized_officer,
            case_id=isolated_case_id,
            analysis_type="CASE_SUMMARY",
        )

    # Verify audit failure
    audit_col = get_audit_logs_col(test_db)
    blocked_audit = audit_col.find_one({
        "event_type": settings.AUDIT_AI_ANALYSIS_FAILED,
        "officer_id": "TS-POL-003",
        "details.case_id": isolated_case_id,
        "details.error_reason": "UNAUTHORIZED_CASE_ACCESS",
    })
    assert blocked_audit is not None


def test_live_failure_recovery_invalid_key(monkeypatch):
    """Verify graceful degradation when an invalid API key is provided."""
    test_db = get_db()
    authorized_officer = {
        "officer_id": "TS-POL-003",
        "role": settings.ROLE_INVESTIGATING_OFFICER,
        "station_id": "North Station",
    }

    # Temporarily set invalid API key
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "AIzaSyInvalidKeyForTesting1234567890abcdef")
    monkeypatch.setenv("GEMINI_API_KEY", "AIzaSyInvalidKeyForTesting1234567890abcdef")

    service = GeminiService(db=test_db)
    result = service.analyze_case(
        current_user=authorized_officer,
        case_id="PACT-CASE-2026-0042",
        analysis_type="CASE_SUMMARY",
    )

    # Should report failure gracefully without crashing PACT
    assert result.status == "FAILED"
    assert "Gemini AI processing error" in result.error_message

    # Verify audit log captures failure
    audit_col = get_audit_logs_col(test_db)
    fail_audit = audit_col.find_one({
        "event_type": settings.AUDIT_AI_ANALYSIS_FAILED,
        "officer_id": "TS-POL-003",
        "details.case_id": "PACT-CASE-2026-0042",
        "status": "FAILED",
    })
    assert fail_audit is not None


def test_live_persistence_across_history_reload():
    """Verify that ai_analysis_history records survive and can be retrieved."""
    test_db = get_db()
    authorized_officer = {
        "officer_id": "TS-POL-003",
        "role": settings.ROLE_INVESTIGATING_OFFICER,
        "station_id": "North Station",
    }

    service = GeminiService(db=test_db)
    history = service.get_case_ai_history(authorized_officer, "PACT-CASE-2026-0042")
    assert isinstance(history, list)
    assert len(history) > 0
    first = history[0]
    assert "analysis_id" in first
    assert first["case_id"] == "PACT-CASE-2026-0042"
    assert "output" in first
