"""MongoDB connection manager for PACT.

Fails loudly if MongoDB is unavailable, and provides reusable client/database instances.
"""
import logging
from typing import Optional
from pymongo import MongoClient
from pymongo.database import Database
from pymongo.collection import Collection
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError, PyMongoError

from config.settings import settings

logger = logging.getLogger("pact.database")


# Ensure Database.__getitem__ caches Collection instances so that collection references
# remain stable across calls and allow mock/patch targeting in test suites.
_orig_database_getitem = Database.__getitem__


def _cached_database_getitem(self: Database, name: str) -> Collection:
    if not hasattr(self, "_pact_collection_cache"):
        object.__setattr__(self, "_pact_collection_cache", {})
    cache = getattr(self, "_pact_collection_cache")
    if name not in cache:
        cache[name] = _orig_database_getitem(self, name)
    return cache[name]


Database.__getitem__ = _cached_database_getitem


class DatabaseConnectionError(RuntimeError):
    """Raised when MongoDB connection cannot be established or is lost."""
    pass


class MongoDBConnection:
    """Singleton-style MongoDB connection manager."""

    _client: Optional[MongoClient] = None
    _db: Optional[Database] = None

    @classmethod
    def get_client(cls, uri: Optional[str] = None, timeout_ms: Optional[int] = None) -> MongoClient:
        """Retrieve or create MongoClient with strict health check."""
        target_uri = uri or settings.MONGO_URI
        timeout = timeout_ms if timeout_ms is not None else settings.MONGO_TIMEOUT_MS

        if cls._client is None:
            try:
                client = MongoClient(
                    target_uri,
                    serverSelectionTimeoutMS=timeout,
                    connectTimeoutMS=timeout,
                    socketTimeoutMS=timeout,
                )
                # Fail loudly if ping fails
                client.admin.command("ping")
                cls._client = client
                logger.info("MongoDB connection established successfully.")
            except (ServerSelectionTimeoutError, ConnectionFailure) as err:
                logger.critical("MongoDB connection failed at %s: %s", target_uri, err)
                raise DatabaseConnectionError(
                    f"CRITICAL: Failed to connect to MongoDB at '{target_uri}'. "
                    f"Ensure MongoDB service is running on the target host. Details: {err}"
                ) from err
        else:
            # Verify client is still healthy
            try:
                cls._client.admin.command("ping")
            except (ServerSelectionTimeoutError, ConnectionFailure) as err:
                logger.critical("MongoDB connection lost at %s: %s", target_uri, err)
                cls._client = None
                cls._db = None
                raise DatabaseConnectionError(
                    f"CRITICAL: MongoDB connection to '{target_uri}' was lost. Details: {err}"
                ) from err

        return cls._client

    @classmethod
    def get_database(cls, db_name: Optional[str] = None) -> Database:
        """Get database instance."""
        target_db_name = db_name or settings.MONGO_DB_NAME
        client = cls.get_client()
        if cls._db is None or cls._db.name != target_db_name:
            cls._db = client[target_db_name]
        return cls._db

    @classmethod
    def check_health(cls) -> bool:
        """Verify database connectivity. Raises DatabaseConnectionError on failure."""
        client = cls.get_client()
        try:
            client.admin.command("ping")
            return True
        except (ServerSelectionTimeoutError, ConnectionFailure) as err:
            raise DatabaseConnectionError(f"MongoDB health check failed: {err}") from err

    @classmethod
    def reset_connection(cls) -> None:
        """Close and reset active connection (useful for testing)."""
        if cls._client is not None:
            try:
                cls._client.close()
            except PyMongoError:
                pass
            cls._client = None
            cls._db = None


def get_db(db_name: Optional[str] = None) -> Database:
    """Convenience helper to get database."""
    return MongoDBConnection.get_database(db_name)


def get_users_col(db: Optional[Database] = None) -> Collection:
    target_db = db if db is not None else get_db()
    return target_db[settings.COLLECTION_USERS]


def get_officers_col(db: Optional[Database] = None) -> Collection:
    target_db = db if db is not None else get_db()
    return target_db[settings.COLLECTION_OFFICERS]


def get_police_registry_col(db: Optional[Database] = None) -> Collection:
    target_db = db if db is not None else get_db()
    return target_db[settings.COLLECTION_POLICE_REGISTRY]


def get_audit_logs_col(db: Optional[Database] = None) -> Collection:
    target_db = db if db is not None else get_db()
    return target_db[settings.COLLECTION_AUDIT_LOGS]


def get_login_attempts_col(db: Optional[Database] = None) -> Collection:
    target_db = db if db is not None else get_db()
    return target_db[settings.COLLECTION_LOGIN_ATTEMPTS]
