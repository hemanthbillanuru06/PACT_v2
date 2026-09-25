"""Tests for Database connectivity, loud failure, and idempotent indexing."""
import pytest
import pymongo
from pymongo.errors import DuplicateKeyError
from pymongo.database import Database

from database.connection import MongoDBConnection, DatabaseConnectionError, get_db
from database.indexes import ensure_indexes
from config.settings import settings


def test_real_mongodb_connection_and_ping(mongo_client):
    """Verify that real local MongoDB is active and responds to ping."""
    res = mongo_client.admin.command("ping")
    assert res.get("ok") == 1.0


def test_loud_failure_when_mongodb_is_down():
    """Verify that the database connection fails loudly with DatabaseConnectionError if unavailable."""
    # Attempt connection to non-existent port
    invalid_uri = "mongodb://localhost:27999/"
    MongoDBConnection.reset_connection()

    with pytest.raises(DatabaseConnectionError) as exc_info:
        MongoDBConnection.get_client(uri=invalid_uri, timeout_ms=500)

    assert "CRITICAL: Failed to connect to MongoDB" in str(exc_info.value)
    # Clean reset
    MongoDBConnection.reset_connection()


def test_idempotent_index_creation(test_db: Database):
    """Verify ensure_indexes can be run repeatedly without errors or duplicating indexes."""
    # Run once
    res1 = ensure_indexes(test_db)
    assert "users" in res1
    assert "idx_users_email_unique" in res1["users"]
    assert "idx_users_officer_id_unique" in res1["users"]
    assert "idx_audit_logs_user_id" in res1["audit_logs"]
    assert "idx_login_attempts_identifier" in res1["login_attempts"]

    # Run second time - must be fully idempotent
    res2 = ensure_indexes(test_db)
    assert res2 == res1


def test_unique_constraint_on_user_email(test_db: Database):
    """Verify users.email unique index strictly rejects duplicate emails."""
    users_col = test_db[settings.COLLECTION_USERS]
    users_col.insert_one({
        "officer_id": "TS-TEST-001",
        "email": "test.officer@police.gov.in",
        "role": "CONSTABLE",
    })

    with pytest.raises(DuplicateKeyError):
        users_col.insert_one({
            "officer_id": "TS-TEST-002",
            "email": "test.officer@police.gov.in",  # Duplicate email
            "role": "SI",
        })


def test_unique_constraint_on_officer_id(test_db: Database):
    """Verify users.officer_id unique index strictly rejects duplicate officer_ids."""
    users_col = test_db[settings.COLLECTION_USERS]
    users_col.insert_one({
        "officer_id": "TS-TEST-001",
        "email": "officer1@police.gov.in",
        "role": "CONSTABLE",
    })

    with pytest.raises(DuplicateKeyError):
        users_col.insert_one({
            "officer_id": "TS-TEST-001",  # Duplicate officer_id
            "email": "officer2@police.gov.in",
            "role": "SP",
        })
