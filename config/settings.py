"""Application settings and constants for PACT Phase 1."""
import os
from typing import List, Tuple
from dotenv import load_dotenv

# Load variables from .env file
load_dotenv()


class Settings:
    """Central configuration parameters."""

    MONGO_URI: str = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
    MONGO_DB_NAME: str = os.getenv("MONGO_DB_NAME", "pact_db")
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")

    # Security Configuration
    MAX_LOGIN_ATTEMPTS: int = int(os.getenv("MAX_LOGIN_ATTEMPTS", "5"))
    PASSWORD_MIN_LENGTH: int = int(os.getenv("PASSWORD_MIN_LENGTH", "12"))
    SESSION_EXPIRY_MINUTES: int = int(os.getenv("SESSION_EXPIRY_MINUTES", "480"))
    MONGO_TIMEOUT_MS: int = int(os.getenv("MONGO_TIMEOUT_MS", "3000"))

    # Collections
    COLLECTION_USERS: str = "users"
    COLLECTION_OFFICERS: str = "officers"
    COLLECTION_POLICE_REGISTRY: str = "police_registry"
    COLLECTION_AUDIT_LOGS: str = "audit_logs"
    COLLECTION_LOGIN_ATTEMPTS: str = "login_attempts"

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

    # Audit Events
    AUDIT_LOGIN_SUCCESS: str = "LOGIN_SUCCESS"
    AUDIT_LOGIN_FAILED: str = "LOGIN_FAILED"
    AUDIT_LOGOUT: str = "LOGOUT"
    AUDIT_UNAUTHORIZED_ACCESS: str = "UNAUTHORIZED_ACCESS"
    AUDIT_ACCOUNT_LOCKED: str = "ACCOUNT_LOCKED"
    AUDIT_SYSTEM_STARTUP: str = "SYSTEM_STARTUP"


settings = Settings()
