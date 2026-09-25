"""Application settings and constants for PACT Phase 1 and Phase 2."""
import os
from typing import List, Optional, Tuple
from dotenv import load_dotenv

# Load variables from .env file
load_dotenv()


def _get_secret_or_env(key: str, default: str = "") -> str:
    """Retrieve configuration from OS environment, falling back to Streamlit secrets."""
    val = os.getenv(key)
    if val:
        return val
    try:
        import streamlit as st
        if hasattr(st, "secrets") and key in st.secrets:
            return str(st.secrets[key])
    except Exception:
        pass
    return default


class Settings:
    """Central configuration parameters."""

    _mongo_uri: Optional[str] = None
    _mongo_db_name: Optional[str] = None
    _gemini_api_key: Optional[str] = None

    @property
    def MONGO_URI(self) -> str:
        if self._mongo_uri is not None:
            return self._mongo_uri
        return _get_secret_or_env("MONGO_URI", "mongodb://localhost:27017/")

    @MONGO_URI.setter
    def MONGO_URI(self, value: str) -> None:
        self._mongo_uri = value

    @property
    def MONGO_DB_NAME(self) -> str:
        if self._mongo_db_name is not None:
            return self._mongo_db_name
        return _get_secret_or_env("MONGO_DB_NAME", "pact_db")

    @MONGO_DB_NAME.setter
    def MONGO_DB_NAME(self, value: str) -> None:
        self._mongo_db_name = value

    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")

    # Security Configuration
    MAX_LOGIN_ATTEMPTS: int = int(os.getenv("MAX_LOGIN_ATTEMPTS", "5"))
    PASSWORD_MIN_LENGTH: int = int(os.getenv("PASSWORD_MIN_LENGTH", "12"))
    SESSION_EXPIRY_MINUTES: int = int(os.getenv("SESSION_EXPIRY_MINUTES", "480"))
    MONGO_TIMEOUT_MS: int = int(os.getenv("MONGO_TIMEOUT_MS", "3000"))

    # Evidence File Storage
    EVIDENCE_STORAGE_DIR: str = os.path.abspath(
        os.getenv("EVIDENCE_STORAGE_DIR", os.path.join(os.getcwd(), "data", "evidence"))
    )
    REPORTS_STORAGE_DIR: str = os.path.abspath(
        os.getenv("REPORTS_STORAGE_DIR", os.path.join(os.getcwd(), "data", "reports"))
    )

    # Phase 1 Collections
    COLLECTION_USERS: str = "users"
    COLLECTION_OFFICERS: str = "officers"
    COLLECTION_POLICE_REGISTRY: str = "police_registry"
    COLLECTION_AUDIT_LOGS: str = "audit_logs"
    COLLECTION_LOGIN_ATTEMPTS: str = "login_attempts"

    # Phase 2 Collections
    COLLECTION_FIRS: str = "firs"
    COLLECTION_CASES: str = "cases"
    COLLECTION_COMPLAINANTS: str = "complainants"
    COLLECTION_VICTIMS: str = "victims"
    COLLECTION_SUSPECTS: str = "suspects"
    COLLECTION_WITNESSES: str = "witnesses"
    COLLECTION_PROPERTY_ITEMS: str = "property_items"
    COLLECTION_EVIDENCE: str = "evidence"
    COLLECTION_EVIDENCE_CUSTODY: str = "evidence_custody"
    COLLECTION_INVESTIGATION_TIMELINE: str = "investigation_timeline"
    COLLECTION_CASE_NOTES: str = "case_notes"
    COLLECTION_CASE_ASSIGNMENTS: str = "case_assignments"
    COLLECTION_CASE_RELATIONSHIPS: str = "case_relationships"
    COLLECTION_NOTIFICATIONS: str = "notifications"
    COLLECTION_REPORTS: str = "reports"

    # Phase 3 Collections
    COLLECTION_AI_ANALYSIS_HISTORY: str = "ai_analysis_history"

    ALL_COLLECTIONS: Tuple[str, ...] = (
        COLLECTION_USERS,
        COLLECTION_OFFICERS,
        COLLECTION_POLICE_REGISTRY,
        COLLECTION_AUDIT_LOGS,
        COLLECTION_LOGIN_ATTEMPTS,
        COLLECTION_FIRS,
        COLLECTION_CASES,
        COLLECTION_COMPLAINANTS,
        COLLECTION_VICTIMS,
        COLLECTION_SUSPECTS,
        COLLECTION_WITNESSES,
        COLLECTION_PROPERTY_ITEMS,
        COLLECTION_EVIDENCE,
        COLLECTION_EVIDENCE_CUSTODY,
        COLLECTION_INVESTIGATION_TIMELINE,
        COLLECTION_CASE_NOTES,
        COLLECTION_CASE_ASSIGNMENTS,
        COLLECTION_CASE_RELATIONSHIPS,
        COLLECTION_NOTIFICATIONS,
        COLLECTION_REPORTS,
        COLLECTION_AI_ANALYSIS_HISTORY,
    )

    # Standard Roles
    ROLE_ADMIN: str = "ADMIN"
    ROLE_SP: str = "SP"
    ROLE_SI: str = "SI"
    ROLE_INVESTIGATING_OFFICER: str = "INVESTIGATING_OFFICER"
    ROLE_CONSTABLE: str = "CONSTABLE"

    ALL_ROLES: Tuple[str, ...] = (
        ROLE_ADMIN,
        ROLE_SP,
        ROLE_SI,
        ROLE_INVESTIGATING_OFFICER,
        ROLE_CONSTABLE,
    )

    # Phase 1 Audit Events
    AUDIT_LOGIN_SUCCESS: str = "LOGIN_SUCCESS"
    AUDIT_LOGIN_FAILED: str = "LOGIN_FAILED"
    AUDIT_LOGOUT: str = "LOGOUT"
    AUDIT_UNAUTHORIZED_ACCESS: str = "UNAUTHORIZED_ACCESS"
    AUDIT_ACCOUNT_LOCKED: str = "ACCOUNT_LOCKED"
    AUDIT_SYSTEM_STARTUP: str = "SYSTEM_STARTUP"

    # Phase 2 Audit Events
    AUDIT_FIR_CREATED: str = "FIR_CREATED"
    AUDIT_FIR_UPDATED: str = "FIR_UPDATED"
    AUDIT_FIR_VIEWED: str = "FIR_VIEWED"
    AUDIT_CASE_CREATED: str = "CASE_CREATED"
    AUDIT_CASE_UPDATED: str = "CASE_UPDATED"
    AUDIT_CASE_VIEWED: str = "CASE_VIEWED"
    AUDIT_CASE_ASSIGNED: str = "CASE_ASSIGNED"
    AUDIT_EVIDENCE_ADDED: str = "EVIDENCE_ADDED"
    AUDIT_EVIDENCE_VIEWED: str = "EVIDENCE_VIEWED"
    AUDIT_EVIDENCE_DOWNLOADED: str = "EVIDENCE_DOWNLOADED"
    AUDIT_EVIDENCE_TRANSFERRED: str = "EVIDENCE_TRANSFERRED"
    AUDIT_TIMELINE_UPDATED: str = "TIMELINE_UPDATED"
    AUDIT_REPORT_GENERATED: str = "REPORT_GENERATED"

    # Phase 3 Audit Events
    AUDIT_AI_ANALYSIS_REQUESTED: str = "AI_ANALYSIS_REQUESTED"
    AUDIT_AI_ANALYSIS_COMPLETED: str = "AI_ANALYSIS_COMPLETED"
    AUDIT_AI_ANALYSIS_FAILED: str = "AI_ANALYSIS_FAILED"

    # Semantic Search Configuration
    EMBEDDING_MODEL_NAME: str = "all-MiniLM-L6-v2"
    SEMANTIC_SIMILARITY_THRESHOLD: float = 0.40

    # Phase 3 Gemini Configuration
    @property
    def GEMINI_API_KEY(self) -> str:
        if self._gemini_api_key is not None:
            return self._gemini_api_key
        return _get_secret_or_env("GEMINI_API_KEY", "")

    @GEMINI_API_KEY.setter
    def GEMINI_API_KEY(self, value: str) -> None:
        self._gemini_api_key = value

    GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")
    GEMINI_REQUEST_TIMEOUT_SECONDS: int = int(os.getenv("GEMINI_REQUEST_TIMEOUT_SECONDS", "30"))


settings = Settings()
