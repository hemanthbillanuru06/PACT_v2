"""Tests for Idempotent Database Seeding."""
import pytest
from pymongo.database import Database

from database.seed import seed_database
from config.settings import settings


def test_seed_initial_counts(test_db: Database):
    """Verify seeding creates exactly 10 stations and 12 users/officers."""
    res = seed_database(db=test_db)
    assert res["stations"] == 10
    assert res["users"] == 12

    reg_col = test_db[settings.COLLECTION_POLICE_REGISTRY]
    users_col = test_db[settings.COLLECTION_USERS]
    officers_col = test_db[settings.COLLECTION_OFFICERS]

    assert reg_col.count_documents({}) == 10
    assert users_col.count_documents({}) == 12
    assert officers_col.count_documents({}) == 12


def test_seed_roles_coverage(seeded_db: Database):
    """Verify all 5 required roles are seeded properly."""
    users_col = seeded_db[settings.COLLECTION_USERS]
    roles_in_db = set(users_col.distinct("role"))

    expected_roles = {
        settings.ROLE_ADMIN,
        settings.ROLE_SP,
        settings.ROLE_SI,
        settings.ROLE_INVESTIGATING_OFFICER,
        settings.ROLE_CONSTABLE,
    }
    assert expected_roles.issubset(roles_in_db)


def test_seed_is_strictly_idempotent(test_db: Database):
    """Verify rerunning seed_database multiple times does NOT duplicate records or indexes."""
    reg_col = test_db[settings.COLLECTION_POLICE_REGISTRY]
    users_col = test_db[settings.COLLECTION_USERS]
    officers_col = test_db[settings.COLLECTION_OFFICERS]

    # Run 1st time
    seed_database(db=test_db)
    assert reg_col.count_documents({}) == 10
    assert users_col.count_documents({}) == 12
    assert officers_col.count_documents({}) == 12

    # Run 2nd time
    seed_database(db=test_db)
    assert reg_col.count_documents({}) == 10
    assert users_col.count_documents({}) == 12
    assert officers_col.count_documents({}) == 12

    # Run 3rd time
    seed_database(db=test_db)
    assert reg_col.count_documents({}) == 10
    assert users_col.count_documents({}) == 12
    assert officers_col.count_documents({}) == 12
