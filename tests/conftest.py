"""Pytest configuration and fixtures for PACT Phase 1 testing.

Uses real local MongoDB at mongodb://localhost:27017/ with dedicated test database 'pact_test_db'.
"""
import pytest
from pymongo import MongoClient
from pymongo.database import Database

from config.settings import settings
from database.connection import MongoDBConnection
from database.indexes import ensure_indexes
from database.seed import seed_database, DEFAULT_OFFICER_PASSWORD, DEFAULT_ADMIN_PASSWORD

TEST_DB_NAME = "pact_test_db"
TEST_MONGO_URI = "mongodb://localhost:27017/"


@pytest.fixture(scope="session")
def mongo_client() -> MongoClient:
    """Session-scoped real MongoDB client connecting to localhost:27017."""
    client = MongoClient(TEST_MONGO_URI, serverSelectionTimeoutMS=3000)
    # Ping real local MongoDB
    client.admin.command("ping")
    yield client
    client.close()


@pytest.fixture(scope="function")
def test_db(mongo_client: MongoClient) -> Database:
    """Function-scoped clean test database."""
    db = mongo_client[TEST_DB_NAME]
    # Drop existing test collections for isolation
    for col_name in [
        settings.COLLECTION_USERS,
        settings.COLLECTION_OFFICERS,
        settings.COLLECTION_POLICE_REGISTRY,
        settings.COLLECTION_AUDIT_LOGS,
        settings.COLLECTION_LOGIN_ATTEMPTS,
    ]:
        db[col_name].drop()

    # Ensure indexes
    ensure_indexes(db)
    yield db

    # Teardown
    for col_name in [
        settings.COLLECTION_USERS,
        settings.COLLECTION_OFFICERS,
        settings.COLLECTION_POLICE_REGISTRY,
        settings.COLLECTION_AUDIT_LOGS,
        settings.COLLECTION_LOGIN_ATTEMPTS,
    ]:
        db[col_name].drop()


@pytest.fixture(scope="function")
def seeded_db(test_db: Database) -> Database:
    """Function-scoped test database pre-seeded with 10 stations and 12 users."""
    seed_database(db=test_db)
    return test_db


@pytest.fixture
def officer_password() -> str:
    return DEFAULT_OFFICER_PASSWORD


@pytest.fixture
def admin_password() -> str:
    return DEFAULT_ADMIN_PASSWORD
