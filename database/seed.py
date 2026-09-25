"""Idempotent database seeder for PACT Phase 1.

Seeds exactly 10 synthetic police stations and 12 synthetic users/officers.
Rerunning this seed will NOT duplicate records, corrupt existing state, or duplicate indexes.
"""
from datetime import datetime, timezone
import logging
from typing import Dict, Any, List, Optional
from pymongo.database import Database

from config.settings import settings
from database.connection import (
    get_db,
    get_users_col,
    get_officers_col,
    get_police_registry_col,
)
from database.indexes import ensure_indexes
from security.passwords import hash_password

logger = logging.getLogger("pact.database.seed")

DEFAULT_OFFICER_PASSWORD = "Pact@Officer2026!"
DEFAULT_ADMIN_PASSWORD = "Pact@Admin2026!"

# 10 Synthetic Police Stations
SYNTHETIC_STATIONS: List[Dict[str, Any]] = [
    {
        "station_id": "STN-001",
        "station_code": "CYB-CENTRAL",
        "name": "Cyberabad Central Police Station",
        "zone": "West Zone",
        "district": "Cyberabad Commissionerate",
        "address": "Gachibowli Main Rd, Financial District, Hyderabad, Telangana 500032",
        "contact_phone": "+91-40-2785-3401",
        "emergency_contact": "100 / +91-40-2785-3499",
        "latitude": 17.4401,
        "longitude": 78.3489,
        "sanctioned_strength": 85,
        "active": True,
    },
    {
        "station_id": "STN-002",
        "station_code": "HYD-BANJARA",
        "name": "Banjara Hills Police Station",
        "zone": "Central Zone",
        "district": "Hyderabad City Police",
        "address": "Road No. 12, Banjara Hills, Hyderabad, Telangana 500034",
        "contact_phone": "+91-40-2785-2402",
        "emergency_contact": "100 / +91-40-2785-2499",
        "latitude": 17.4156,
        "longitude": 78.4350,
        "sanctioned_strength": 90,
        "active": True,
    },
    {
        "station_id": "STN-003",
        "station_code": "CYB-MADHAPUR",
        "name": "Madhapur IT Corridor Police Station",
        "zone": "West Zone",
        "district": "Cyberabad Commissionerate",
        "address": "Hitech City Main Rd, Madhapur, Hyderabad, Telangana 500081",
        "contact_phone": "+91-40-2785-4403",
        "emergency_contact": "100 / +91-40-2785-4499",
        "latitude": 17.4483,
        "longitude": 78.3915,
        "sanctioned_strength": 75,
        "active": True,
    },
    {
        "station_id": "STN-004",
        "station_code": "CYB-CYBERCRIME",
        "name": "Cyber Crime Division Police Station",
        "zone": "Cyber Special Branch",
        "district": "Cyberabad Commissionerate",
        "address": "Cyberabad Police Commissionerate Complex, Gachibowli, Hyderabad 500032",
        "contact_phone": "+91-40-2785-5404",
        "emergency_contact": "1930 / +91-40-2785-5499",
        "latitude": 17.4390,
        "longitude": 78.3610,
        "sanctioned_strength": 60,
        "active": True,
    },
    {
        "station_id": "STN-005",
        "station_code": "HYD-BEGUMPET",
        "name": "Begumpet Division Police Station",
        "zone": "North Zone",
        "district": "Hyderabad City Police",
        "address": "Sardar Patel Rd, Begumpet, Hyderabad, Telangana 500016",
        "contact_phone": "+91-40-2785-6405",
        "emergency_contact": "100 / +91-40-2785-6499",
        "latitude": 17.4448,
        "longitude": 78.4678,
        "sanctioned_strength": 70,
        "active": True,
    },
    {
        "station_id": "STN-006",
        "station_code": "HYD-SECUNDERABAD",
        "name": "Secunderabad Cantonment Police Station",
        "zone": "North Zone",
        "district": "Hyderabad City Police",
        "address": "MG Road, General Bazar, Secunderabad, Telangana 500003",
        "contact_phone": "+91-40-2785-7406",
        "emergency_contact": "100 / +91-40-2785-7499",
        "latitude": 17.4399,
        "longitude": 78.4983,
        "sanctioned_strength": 65,
        "active": True,
    },
    {
        "station_id": "STN-007",
        "station_code": "HYD-JUBILEE",
        "name": "Jubilee Hills Police Station",
        "zone": "Central Zone",
        "district": "Hyderabad City Police",
        "address": "Road No. 36, Jubilee Hills, Hyderabad, Telangana 500033",
        "contact_phone": "+91-40-2785-8407",
        "emergency_contact": "100 / +91-40-2785-8499",
        "latitude": 17.4319,
        "longitude": 78.4073,
        "sanctioned_strength": 80,
        "active": True,
    },
    {
        "station_id": "STN-008",
        "station_code": "HYD-PUNJAGUTTA",
        "name": "Punjagutta Command Police Station",
        "zone": "Central Zone",
        "district": "Hyderabad City Police",
        "address": "Nagarjuna Circle, Punjagutta, Hyderabad, Telangana 500082",
        "contact_phone": "+91-40-2785-9408",
        "emergency_contact": "100 / +91-40-2785-9499",
        "latitude": 17.4265,
        "longitude": 78.4524,
        "sanctioned_strength": 95,
        "active": True,
    },
    {
        "station_id": "STN-009",
        "station_code": "CYB-KUKATPALLY",
        "name": "Kukatpally Law & Order Police Station",
        "zone": "North Zone",
        "district": "Cyberabad Commissionerate",
        "address": "Mumbai Highway, Kukatpally, Hyderabad, Telangana 500072",
        "contact_phone": "+91-40-2785-1409",
        "emergency_contact": "100 / +91-40-2785-1499",
        "latitude": 17.4938,
        "longitude": 78.3995,
        "sanctioned_strength": 70,
        "active": True,
    },
    {
        "station_id": "STN-010",
        "station_code": "HYD-CHARMINAR",
        "name": "Charminar Historic Division Police Station",
        "zone": "South Zone",
        "district": "Hyderabad City Police",
        "address": "Pathergatti, Near Charminar, Hyderabad, Telangana 500002",
        "contact_phone": "+91-40-2785-0410",
        "emergency_contact": "100 / +91-40-2785-0499",
        "latitude": 17.3616,
        "longitude": 78.4747,
        "sanctioned_strength": 85,
        "active": True,
    },
]

# 12 Synthetic Users & Officers (TS-POL-001 to TS-POL-012)
SYNTHETIC_OFFICERS: List[Dict[str, Any]] = [
    {
        "officer_id": "TS-POL-001",
        "role": settings.ROLE_SP,
        "email": "ts-pol-001@police.gov.in",
        "full_name": "Vikramaditya Varma, IPS",
        "badge_number": "TS-IPS-8801",
        "rank": "Superintendent of Police",
        "station_id": "STN-001",
        "contact_phone": "+91-9440-100001",
        "blood_group": "O+",
        "password": DEFAULT_OFFICER_PASSWORD,
    },
    {
        "officer_id": "TS-POL-002",
        "role": settings.ROLE_SP,
        "email": "ts-pol-002@police.gov.in",
        "full_name": "Dr. Ananya Deshmukh, IPS",
        "badge_number": "TS-IPS-8802",
        "rank": "Superintendent of Police (CID)",
        "station_id": "STN-008",
        "contact_phone": "+91-9440-100002",
        "blood_group": "A+",
        "password": DEFAULT_OFFICER_PASSWORD,
    },
    {
        "officer_id": "TS-POL-003",
        "role": settings.ROLE_SI,
        "email": "ts-pol-003@police.gov.in",
        "full_name": "Rajeshwar Rao",
        "badge_number": "TS-SI-4101",
        "rank": "Sub-Inspector",
        "station_id": "STN-002",
        "contact_phone": "+91-9440-100003",
        "blood_group": "B+",
        "password": DEFAULT_OFFICER_PASSWORD,
    },
    {
        "officer_id": "TS-POL-004",
        "role": settings.ROLE_SI,
        "email": "ts-pol-004@police.gov.in",
        "full_name": "Pradeep K. Reddy",
        "badge_number": "TS-SI-4102",
        "rank": "Sub-Inspector",
        "station_id": "STN-003",
        "contact_phone": "+91-9440-100004",
        "blood_group": "AB+",
        "password": DEFAULT_OFFICER_PASSWORD,
    },
    {
        "officer_id": "TS-POL-005",
        "role": settings.ROLE_SI,
        "email": "ts-pol-005@police.gov.in",
        "full_name": "Sunita G. Naidu",
        "badge_number": "TS-SI-4103",
        "rank": "Sub-Inspector",
        "station_id": "STN-004",
        "contact_phone": "+91-9440-100005",
        "blood_group": "O-",
        "password": DEFAULT_OFFICER_PASSWORD,
    },
    {
        "officer_id": "TS-POL-006",
        "role": settings.ROLE_INVESTIGATING_OFFICER,
        "email": "ts-pol-006@police.gov.in",
        "full_name": "K. Vamsi Krishna",
        "badge_number": "TS-IO-3201",
        "rank": "Investigating Officer (Cyber)",
        "station_id": "STN-004",
        "contact_phone": "+91-9440-100006",
        "blood_group": "B+",
        "password": DEFAULT_OFFICER_PASSWORD,
    },
    {
        "officer_id": "TS-POL-007",
        "role": settings.ROLE_INVESTIGATING_OFFICER,
        "email": "ts-pol-007@police.gov.in",
        "full_name": "Sneha Patel",
        "badge_number": "TS-IO-3202",
        "rank": "Investigating Officer (Financial Fraud)",
        "station_id": "STN-002",
        "contact_phone": "+91-9440-100007",
        "blood_group": "A-",
        "password": DEFAULT_OFFICER_PASSWORD,
    },
    {
        "officer_id": "TS-POL-008",
        "role": settings.ROLE_INVESTIGATING_OFFICER,
        "email": "ts-pol-008@police.gov.in",
        "full_name": "T. Arvind Chary",
        "badge_number": "TS-IO-3203",
        "rank": "Investigating Officer (Special Crime)",
        "station_id": "STN-003",
        "contact_phone": "+91-9440-100008",
        "blood_group": "O+",
        "password": DEFAULT_OFFICER_PASSWORD,
    },
    {
        "officer_id": "TS-POL-009",
        "role": settings.ROLE_INVESTIGATING_OFFICER,
        "email": "ts-pol-009@police.gov.in",
        "full_name": "Meera Varma",
        "badge_number": "TS-IO-3204",
        "rank": "Investigating Officer (Major Cases)",
        "station_id": "STN-007",
        "contact_phone": "+91-9440-100009",
        "blood_group": "B+",
        "password": DEFAULT_OFFICER_PASSWORD,
    },
    {
        "officer_id": "TS-POL-010",
        "role": settings.ROLE_CONSTABLE,
        "email": "ts-pol-010@police.gov.in",
        "full_name": "D. Suresh Kumar",
        "badge_number": "TS-PC-1901",
        "rank": "Head Constable (Beat Patrol)",
        "station_id": "STN-001",
        "contact_phone": "+91-9440-100010",
        "blood_group": "A+",
        "password": DEFAULT_OFFICER_PASSWORD,
    },
    {
        "officer_id": "TS-POL-011",
        "role": settings.ROLE_CONSTABLE,
        "email": "ts-pol-011@police.gov.in",
        "full_name": "B. Ramesh Goud",
        "badge_number": "TS-PC-1902",
        "rank": "Constable (Law & Order)",
        "station_id": "STN-004",
        "contact_phone": "+91-9440-100011",
        "blood_group": "O+",
        "password": DEFAULT_OFFICER_PASSWORD,
    },
    {
        "officer_id": "TS-POL-012",
        "role": settings.ROLE_ADMIN,
        "email": "ts-pol-012@police.gov.in",
        "full_name": "Directorate System Administrator",
        "badge_number": "TS-ADM-0001",
        "rank": "Command Center Administrator",
        "station_id": "STN-008",
        "contact_phone": "+91-9440-100012",
        "blood_group": "AB+",
        "password": DEFAULT_ADMIN_PASSWORD,
    },
]


def seed_database(db: Optional[Database] = None, force_rehash: bool = False) -> Dict[str, int]:
    """Execute idempotent database seeding.

    Ensures:
    1. Indexes exist without error.
    2. 10 synthetic police stations exist in police_registry.
    3. 12 synthetic officers and user accounts exist in officers and users collections.
    4. Passwords adhere to 12-char policy and are hashed with bcrypt.
    5. Safe to run multiple times without duplicating data or indexes.
    """
    target_db = db if db is not None else get_db()

    # 1. Ensure indexes idempotently
    ensure_indexes(target_db)

    registry_col = get_police_registry_col(target_db)
    officers_col = get_officers_col(target_db)
    users_col = get_users_col(target_db)

    stations_seeded = 0
    users_seeded = 0

    # 2. Seed Stations (police_registry)
    for stn in SYNTHETIC_STATIONS:
        stn_doc = {**stn, "updated_at": datetime.now(timezone.utc)}
        res = registry_col.update_one(
            {"station_id": stn["station_id"]},
            {
                "$set": stn_doc,
                "$setOnInsert": {"created_at": datetime.now(timezone.utc)},
            },
            upsert=True,
        )
        if res.upserted_id or res.matched_count:
            stations_seeded += 1

    # 3. Seed Officers & Users
    for off in SYNTHETIC_OFFICERS:
        officer_id = off["officer_id"]
        email = off["email"].lower()
        role = off["role"]
        pwd = off["password"]

        # Officer metadata doc
        officer_doc = {
            "officer_id": officer_id,
            "badge_number": off["badge_number"],
            "full_name": off["full_name"],
            "rank": off["rank"],
            "station_id": off["station_id"],
            "contact_phone": off["contact_phone"],
            "blood_group": off["blood_group"],
            "updated_at": datetime.now(timezone.utc),
        }
        officers_col.update_one(
            {"officer_id": officer_id},
            {
                "$set": officer_doc,
                "$setOnInsert": {"created_at": datetime.now(timezone.utc)},
            },
            upsert=True,
        )

        # Check existing user
        existing_user = users_col.find_one({"officer_id": officer_id})
        if not existing_user or force_rehash:
            pwd_hash = hash_password(pwd)
            user_set_fields = {
                "officer_id": officer_id,
                "email": email,
                "role": role,
                "is_active": True,
                "updated_at": datetime.now(timezone.utc),
            }
            if force_rehash or not existing_user:
                user_set_fields["password_hash"] = pwd_hash

            users_col.update_one(
                {"officer_id": officer_id},
                {
                    "$set": user_set_fields,
                    "$setOnInsert": {
                        "is_locked": False,
                        "failed_login_attempts": 0,
                        "created_at": datetime.now(timezone.utc),
                    },
                },
                upsert=True,
            )
        else:
            # Update role or email if modified, preserve existing password_hash and lock state
            users_col.update_one(
                {"officer_id": officer_id},
                {
                    "$set": {
                        "email": email,
                        "role": role,
                        "is_active": True,
                        "updated_at": datetime.now(timezone.utc),
                    }
                },
            )
        users_seeded += 1

    logger.info("Database seeding complete. Stations: %d, Users/Officers: %d", stations_seeded, users_seeded)
    return {"stations": stations_seeded, "users": users_seeded}


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    seed_database()
