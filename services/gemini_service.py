"""Gemini AI Integration and Investigative Assistance Service for PACT Phase 3."""
from datetime import datetime, timezone
import logging
import os
import time
import uuid
from typing import Dict, Any, List, Optional, Union
from pymongo.database import Database
from pymongo.errors import PyMongoError

from config.settings import settings
from database.connection import get_db, get_ai_analysis_history_col
from security.rbac import UnauthorizedAccessError
from security.sanitizer import sanitize_payload, sanitize_text
from services.ai_prompts import AIPromptBuilder, SYSTEM_INSTRUCTION, MANDATORY_DISCLAIMER
from services.audit_service import AuditService
from services.case_service import CaseService, CaseSecurityValidator
from services.entity_service import EntityService
from services.evidence_service import EvidenceService

logger = logging.getLogger("pact.services.gemini")


class hybridmethod:
    """Descriptor that behaves as an instance method when called on an instance,
    or creates an instance when called on the class."""
    def __init__(self, func):
        self.func = func

    def __get__(self, instance, owner=None):
        if instance is None:
            return lambda *args, **kwargs: self.func(owner(), *args, **kwargs)
        return lambda *args, **kwargs: self.func(instance, *args, **kwargs)


class GeminiServiceError(Exception):
    """Base exception for Gemini AI service errors."""
    pass


class GeminiKeyMissingError(GeminiServiceError):
    """Raised when GEMINI_API_KEY is not configured."""
    pass


class GeminiAnalysisResult:
    """Structured response container for AI analysis output."""

    def __init__(
        self,
        analysis_id: str,
        case_id: str,
        analysis_type: str,
        output: str,
        status: str = "SUCCESS",
        model: str = "",
        duration_seconds: float = 0.0,
        error_message: Optional[str] = None,
    ):
        self.analysis_id = analysis_id
        self.case_id = case_id
        self.analysis_type = analysis_type
        self.output = output
        self.status = status
        self.model = model
        self.duration_seconds = duration_seconds
        self.error_message = error_message

    def to_dict(self) -> Dict[str, Any]:
        return {
            "analysis_id": self.analysis_id,
            "case_id": self.case_id,
            "analysis_type": self.analysis_type,
            "output": self.output,
            "status": self.status,
            "model": self.model,
            "duration_seconds": self.duration_seconds,
            "error_message": self.error_message,
        }


class GeminiService:
    """Central AI investigative assistance service powered by Google GenAI SDK."""

    def __init__(self, db: Optional[Database] = None, client: Optional[Any] = None):
        self.db = db
        self._client = client

    def _get_api_key(self) -> str:
        """Fetch API key from settings or environment variable."""
        key = getattr(settings, "GEMINI_API_KEY", "") or os.getenv("GEMINI_API_KEY", "")
        return key.strip() if key else ""

    def _get_client(self) -> Any:
        """Initialize Google GenAI client if not already provided."""
        if self._client is not None:
            return self._client

        api_key = self._get_api_key()
        if not api_key:
            raise GeminiKeyMissingError(
                "Gemini API key is not configured. Please set GEMINI_API_KEY in your .env file to enable live AI features."
            )

        from google import genai
        return genai.Client(api_key=api_key)

    def _gather_case_bundle(self, current_user: Any, case_id: str, db: Optional[Database] = None) -> Dict[str, Any]:
        """Fetch complete case dossier, FIR, entities, timeline, evidence, and notes,
        strictly enforcing CaseSecurityValidator BEFORE collecting data.
        """
        target_db = db if db is not None else (self.db if self.db is not None else get_db())

        # 1. Fetch raw case doc
        case_doc = CaseService.get_case_by_id(current_user, case_id, db=target_db)
        if not case_doc:
            raise ValueError(f"Case {case_id} not found.")

        # 2. Strict Pre-Payload Authorization check (Officer A cannot access Officer B's case)
        CaseSecurityValidator.enforce_case_access(
            current_user,
            case_doc,
            require_write=False,
            resource_name="ai_analysis_case",
            db=target_db,
        )

        # 3. Retrieve FIR details
        fir_info = {}
        fir_number = case_doc.get("fir_number")
        if fir_number:
            fir_doc = CaseService.get_fir_by_number(current_user, fir_number, db=target_db)
            if fir_doc:
                fir_info = fir_doc

        # 4. Retrieve Entities
        entities = EntityService.get_all_entities_for_case(current_user, case_id, db=target_db)

        # 5. Retrieve Evidence
        evidence_items = EvidenceService.get_case_evidence(current_user, case_id, db=target_db)

        # 6. Retrieve Timeline
        timeline_events = CaseService.get_case_timeline(current_user, case_id, db=target_db)

        # 7. Retrieve Notes
        notes = CaseService.get_case_notes(current_user, case_id, db=target_db)

        # Check if user has clearance for confidential notes
        role = current_user.get("role") if hasattr(current_user, "get") else getattr(current_user, "role", "CONSTABLE")
        include_confidential = role in [settings.ROLE_ADMIN, settings.ROLE_SP, settings.ROLE_SI]

        raw_bundle = {
            "case": case_doc,
            "fir": fir_info,
            "suspects": entities.get("suspects", []),
            "victims": entities.get("victims", []),
            "complainants": entities.get("complainants", []),
            "witnesses": entities.get("witnesses", []),
            "property_items": entities.get("property_items", []),
            "evidence": evidence_items,
            "timeline": timeline_events,
            "notes": notes,
            "include_confidential": include_confidential,
        }

        # 8. Secret sanitization: scrub sensitive database strings, tokens, and secrets
        return sanitize_payload(raw_bundle)

    @hybridmethod
    def analyze_case(
        self,
        current_user: Any,
        case_id: str,
        analysis_type: str,
        officer_query: Optional[str] = None,
        comparison_case_id: Optional[str] = None,
        db: Optional[Database] = None,
    ) -> GeminiAnalysisResult:
        """Run investigative AI analysis on an authorized case dossier.

        Supported analysis_type values:
          - 'CASE_SUMMARY'
          - 'INVESTIGATION_BRIEF'
          - 'EVIDENCE_SUMMARY'
          - 'TIMELINE_ANALYSIS'
          - 'SIMILAR_CASE_EXPLANATION'
          - 'INVESTIGATIVE_QUESTIONS'
          - 'CASE_COMPARISON'
          - 'OFFICER_QA'
        """
        start_time = time.time()
        target_db = db if db is not None else (self.db if self.db is not None else get_db())
        analysis_id = f"AI-{uuid.uuid4().hex[:12].upper()}"

        user_id = current_user.get("user_id") if hasattr(current_user, "get") else getattr(current_user, "user_id", None)
        officer_id = current_user.get("officer_id", "UNKNOWN") if hasattr(current_user, "get") else getattr(current_user, "officer_id", "UNKNOWN")
        user_role = current_user.get("role", "CONSTABLE") if hasattr(current_user, "get") else getattr(current_user, "role", "CONSTABLE")

        # 1. Audit Request Initiation (never log API keys or secrets)
        AuditService.log_event(
            event_type=settings.AUDIT_AI_ANALYSIS_REQUESTED,
            user_id=user_id,
            officer_id=officer_id,
            role=user_role,
            details={
                "analysis_id": analysis_id,
                "case_id": case_id,
                "analysis_type": analysis_type,
                "model": settings.GEMINI_MODEL,
            },
            status="REQUESTED",
            db=target_db,
        )

        try:
            # 2. Strict Pre-Payload Authorization and Data Gathering
            case_bundle = self._gather_case_bundle(current_user, case_id, db=target_db)

            # If comparing with another case, authorize comparison case as well
            comp_bundle = None
            if comparison_case_id:
                comp_bundle = self._gather_case_bundle(current_user, comparison_case_id, db=target_db)

            # 3. Assemble Prompt based on analysis_type
            clean_query = sanitize_text(officer_query or "")
            if analysis_type == "CASE_SUMMARY":
                prompt_text = AIPromptBuilder.build_case_summary_prompt(case_bundle)
            elif analysis_type == "INVESTIGATION_BRIEF":
                prompt_text = AIPromptBuilder.build_investigation_brief_prompt(case_bundle)
            elif analysis_type == "EVIDENCE_SUMMARY":
                prompt_text = AIPromptBuilder.build_evidence_summary_prompt(case_bundle)
            elif analysis_type == "TIMELINE_ANALYSIS":
                prompt_text = AIPromptBuilder.build_timeline_analysis_prompt(case_bundle)
            elif analysis_type == "SIMILAR_CASE_EXPLANATION":
                if not comp_bundle:
                    raise ValueError("Comparison case ID is required for SIMILAR_CASE_EXPLANATION.")
                prompt_text = AIPromptBuilder.build_similar_case_explanation_prompt(case_bundle, comp_bundle)
            elif analysis_type == "INVESTIGATIVE_QUESTIONS":
                prompt_text = AIPromptBuilder.build_investigative_questions_prompt(case_bundle)
            elif analysis_type == "CASE_COMPARISON":
                if not comp_bundle:
                    raise ValueError("Comparison case ID is required for CASE_COMPARISON.")
                prompt_text = AIPromptBuilder.build_case_comparison_prompt(case_bundle, comp_bundle)
            elif analysis_type == "OFFICER_QA":
                if not clean_query:
                    raise ValueError("Officer query is required for OFFICER_QA.")
                prompt_text = AIPromptBuilder.build_officer_qa_prompt(case_bundle, clean_query)
            else:
                raise ValueError(f"Unsupported analysis type: {analysis_type}")

            # 4. Execute AI Generation (with graceful degradation for missing key / network errors)
            client = self._get_client()
            from google.genai import types

            response = client.models.generate_content(
                model=settings.GEMINI_MODEL,
                contents=prompt_text,
                config=types.GenerateContentConfig(
                    system_instruction=SYSTEM_INSTRUCTION,
                    temperature=0.2,
                ),
            )

            raw_output = response.text or ""
            # Ensure mandatory legal disclaimer is present
            if MANDATORY_DISCLAIMER not in raw_output:
                raw_output = f"{raw_output.strip()}\n\n---\n*{MANDATORY_DISCLAIMER}*"

            duration = time.time() - start_time

            # 5. Persist to ai_analysis_history collection
            history_col = get_ai_analysis_history_col(target_db)
            history_doc = {
                "analysis_id": analysis_id,
                "case_id": case_id,
                "user_id": str(user_id) if user_id else None,
                "officer_id": officer_id,
                "analysis_type": analysis_type,
                "prompt_version": AIPromptBuilder.PROMPT_VERSION,
                "model": settings.GEMINI_MODEL,
                "timestamp": datetime.now(timezone.utc),
                "output": raw_output,
                "status": "COMPLETED",
                "duration_seconds": round(duration, 3),
            }
            history_col.insert_one(history_doc)

            # 6. Audit Success (never log API keys or secrets)
            AuditService.log_event(
                event_type=settings.AUDIT_AI_ANALYSIS_COMPLETED,
                user_id=user_id,
                officer_id=officer_id,
                role=user_role,
                details={
                    "analysis_id": analysis_id,
                    "case_id": case_id,
                    "analysis_type": analysis_type,
                    "duration_seconds": round(duration, 3),
                    "model": settings.GEMINI_MODEL,
                    "status": "COMPLETED",
                },
                status="SUCCESS",
                db=target_db,
            )

            return GeminiAnalysisResult(
                analysis_id=analysis_id,
                case_id=case_id,
                analysis_type=analysis_type,
                output=raw_output,
                status="SUCCESS",
                model=settings.GEMINI_MODEL,
                duration_seconds=round(duration, 3),
            )

        except UnauthorizedAccessError as auth_err:
            duration = time.time() - start_time
            logger.warning("AI Analysis blocked by Service RBAC for officer %s on case %s: %s", officer_id, case_id, auth_err)
            AuditService.log_event(
                event_type=settings.AUDIT_AI_ANALYSIS_FAILED,
                user_id=user_id,
                officer_id=officer_id,
                role=user_role,
                details={
                    "analysis_id": analysis_id,
                    "case_id": case_id,
                    "analysis_type": analysis_type,
                    "error_reason": "UNAUTHORIZED_CASE_ACCESS",
                    "status": "BLOCKED",
                },
                status="FAILED",
                db=target_db,
            )
            raise

        except GeminiKeyMissingError as key_err:
            duration = time.time() - start_time
            logger.warning("AI Analysis aborted: %s", key_err)
            AuditService.log_event(
                event_type=settings.AUDIT_AI_ANALYSIS_FAILED,
                user_id=user_id,
                officer_id=officer_id,
                role=user_role,
                details={
                    "analysis_id": analysis_id,
                    "case_id": case_id,
                    "analysis_type": analysis_type,
                    "error_reason": "GEMINI_API_KEY_NOT_CONFIGURED",
                    "status": "OFFLINE",
                },
                status="FAILED",
                db=target_db,
            )
            return GeminiAnalysisResult(
                analysis_id=analysis_id,
                case_id=case_id,
                analysis_type=analysis_type,
                output="",
                status="KEY_MISSING",
                model=settings.GEMINI_MODEL,
                duration_seconds=round(duration, 3),
                error_message="Gemini API key is not configured. Please configure GEMINI_API_KEY in .env to enable live AI investigative features.",
            )

        except Exception as err:
            duration = time.time() - start_time
            sanitized_err = sanitize_text(str(err))
            logger.error("AI Analysis failed on case %s: %s", case_id, sanitized_err)
            AuditService.log_event(
                event_type=settings.AUDIT_AI_ANALYSIS_FAILED,
                user_id=user_id,
                officer_id=officer_id,
                role=user_role,
                details={
                    "analysis_id": analysis_id,
                    "case_id": case_id,
                    "analysis_type": analysis_type,
                    "error_reason": sanitized_err,
                    "status": "FAILED",
                },
                status="FAILED",
                db=target_db,
            )
            return GeminiAnalysisResult(
                analysis_id=analysis_id,
                case_id=case_id,
                analysis_type=analysis_type,
                output="",
                status="FAILED",
                model=settings.GEMINI_MODEL,
                duration_seconds=round(duration, 3),
                error_message=f"Gemini AI processing error: {sanitized_err}",
            )

    @hybridmethod
    def get_case_ai_history(
        self,
        current_user: Any,
        case_id: str,
        limit: int = 20,
        db: Optional[Database] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieve historical AI analysis records for a case, enforcing RBAC authorization."""
        target_db = db if db is not None else (self.db if self.db is not None else get_db())

        # Verify case authorization first (Officer A cannot read Officer B's AI history)
        case_doc = CaseService.get_case_by_id(current_user, case_id, db=target_db)
        if not case_doc:
            return []

        CaseSecurityValidator.enforce_case_access(
            current_user,
            case_doc,
            require_write=False,
            resource_name="ai_analysis_history",
            db=target_db,
        )

        history_col = get_ai_analysis_history_col(target_db)
        cursor = history_col.find({"case_id": case_id}).sort("timestamp", -1).limit(limit)

        records = []
        for doc in cursor:
            doc["_id"] = str(doc["_id"])
            records.append(doc)
        return records
