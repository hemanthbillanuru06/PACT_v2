"""Database module for PACT."""
from database.connection import (
    MongoDBConnection,
    DatabaseConnectionError,
    get_db,
    get_users_col,
    get_officers_col,
    get_police_registry_col,
    get_audit_logs_col,
    get_login_attempts_col,
)
from database.indexes import ensure_indexes
from database.seed import seed_database

__all__ = [
    "MongoDBConnection",
    "DatabaseConnectionError",
    "get_db",
    "get_users_col",
    "get_officers_col",
    "get_police_registry_col",
    "get_audit_logs_col",
    "get_login_attempts_col",
    "ensure_indexes",
    "seed_database",
]
