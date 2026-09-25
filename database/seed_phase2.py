"""Idempotent database seeder for PACT Phase 2.

Seeds:
- Mandatory Showcase Case: PACT-CASE-2026-0042 (FIR TS/NORTH/2026/0042, Vehicle Theft, HIGH, North Station, IO: TS-POL-003)
- 150+ realistic synthetic cases across crime types, stations, and statuses
- 40+ rich First Information Reports (FIRs)
- Comprehensive entities: Complainants, Victims, Suspects, Witnesses, Property
- Real dummy evidence files (.mp4, .jpg, .pdf) in data/evidence/
- Investigation timelines, case notes, and Chain of Custody transfers
"""
from datetime import datetime, timezone, timedelta
import logging
import os
import random
from typing import Dict, Any, List, Optional
from pymongo.database import Database

from config.settings import settings
from database.connection import (
    get_db,
    get_firs_col,
    get_cases_col,
    get_complainants_col,
    get_victims_col,
    get_suspects_col,
    get_witnesses_col,
    get_property_items_col,
    get_evidence_col,
    get_evidence_custody_col,
    get_investigation_timeline_col,
    get_case_notes_col,
    get_case_assignments_col,
    get_notifications_col,
    get_police_registry_col,
)
from security.file_security import save_evidence_file, ensure_storage_directories

logger = logging.getLogger("pact.database.seed_phase2")

# Crime types for realistic generation
CRIME_TYPES = [
    "Vehicle Theft",
    "Cyber Crime & Online Fraud",
    "Burglary & House Breaking",
    "Armed Robbery",
    "Commercial Narcotics Trafficking",
    "Corporate Financial Embezzlement",
    "Extortion & Kidnapping",
    "Homicide Investigation",
    "ATM Cash Skimming",
    "Intellectual Property Piracy",
    "Chain Snatching & Street Robbery",
    "SIM Box & VoIP Bypass Fraud",
]

PRIORITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
STATUSES = ["OPEN", "UNDER INVESTIGATION", "UNDER INVESTIGATION", "CHARGESHEETED", "CLOSED", "COLD_CASE"]

STATION_IDS = [f"STN-00{i}" for i in range(1, 10)] + ["STN-010"]
OFFICER_IDS = [f"TS-POL-00{i}" for i in range(1, 10)] + ["TS-POL-010", "TS-POL-011", "TS-POL-012"]

# Modus operandi templates for semantic search clusters
MO_TEMPLATES = [
    ("Keyless Signal Booster & CAN-bus Injection", "Suspects utilized RF signal amplifier targeting smart key transponders parked outside residential villas, bypassing ignition via OBD port in under 180 seconds."),
    ("Phishing SMS & Screen-Share Remote Access", "Perpetrators sent spoofed electricity bill payment warning SMS with APK download link, capturing OTP credentials and draining beneficiary bank accounts via UPI gateway."),
    ("Nighttime Rooftop Skylight Entry", "Burglary gang scaled rear drainage pipes during monsoon rain, cut corrugated rooftop sheets, and targeted digital lockers using tungsten carbide tipped drills."),
    ("Two-Wheeler Pillion Rider Snatching", "Pillion rider on un-registered sports motorcycle grabbed gold chain from pedestrian, fleeing into narrow pedestrian lanes with masked number plates."),
    ("ATM Shimmer & Hidden Pinhole Camera", "Micro-electronic shimmer card inserted directly into ATM card reader slot paired with pinhole camera concealed behind false numeric keypad overlay."),
    ("Fake Crypto Investment Telegram Syndicate", "Lured professionals into Telegram trading groups with doctored profit screenshots, directed funds to mule accounts, and laundered through P2P crypto exchanges."),
    ("Forged Purchase Invoices & Phantom Vendors", "Accounts officer routed internal supplier disbursements into proprietary shell corporate accounts using forged director digital signatures."),
    ("Hydraulic Cutter Commercial Shutter Break-In", "Commercial burglary gang operated between 02:00 and 03:30 hrs using heavy hydraulic cutters on shop center-locks, transporting inventory in covered trucks."),
    ("SIM Swap & Banking Portal Takeover", "Submitted counterfeit voter identification to mobile retail kiosk to execute unauthorized SIM swap, intercepting two-factor banking SMS codes."),
    ("Cold Call Law Enforcement Impersonation Scam", "Scammers called senior citizens claiming their parcel contained narcotics, coerced emergency wire transfers into 'verification escrow accounts'."),
]


def create_dummy_file_bytes(extension: str, label: str) -> bytes:
    """Generate realistic dummy binary data for testing evidence file persistence."""
    if extension == ".pdf":
        return b"%PDF-1.4\n1 0 obj\n<< /Title (" + label.encode() + b") >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n"
    elif extension == ".jpg":
        return b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00\xff\xdb\x00C\x00" + label.encode()[:30] + b"\xff\xd9"
    elif extension == ".mp4":
        return b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom" + label.encode()[:40]
    else:
        return f"PACT Law Enforcement Evidence Record: {label}\nTimestamp: {datetime.now(timezone.utc).isoformat()}".encode("utf-8")


def seed_showcase_case(db: Database) -> str:
    """Seed the mandatory showcase case:

    FIR: TS/NORTH/2026/0042
    Case ID: PACT-CASE-2026-0042
    Crime: Vehicle Theft
    Priority: HIGH
    Status: UNDER INVESTIGATION
    Station: North Station (STN-005)
    IO: TS-POL-003
    """
    cases_col = get_cases_col(db)
    firs_col = get_firs_col(db)
    complainants_col = get_complainants_col(db)
    suspects_col = get_suspects_col(db)
    witnesses_col = get_witnesses_col(db)
    property_col = get_property_items_col(db)
    evidence_col = get_evidence_col(db)
    custody_col = get_evidence_custody_col(db)
    timeline_col = get_investigation_timeline_col(db)
    notes_col = get_case_notes_col(db)
    assignments_col = get_case_assignments_col(db)

    # Ensure station with code/name 'North Station' exists
    reg_col = get_police_registry_col(db)
    reg_col.update_one(
        {"station_id": "STN-005"},
        {"$set": {"alias": "North Station", "name": "Begumpet North Station Police Station"}},
    )

    case_id = "PACT-CASE-2026-0042"
    fir_number = "TS/NORTH/2026/0042"
    io_officer_id = "TS-POL-003"
    station_id = "North Station"

    # 1. FIR
    fir_doc = {
        "fir_number": fir_number,
        "station_id": station_id,
        "incident_date": datetime(2026, 8, 14, 1, 45, tzinfo=timezone.utc),
        "reported_date": datetime(2026, 8, 14, 6, 30, tzinfo=timezone.utc),
        "crime_type": "Vehicle Theft",
        "place_of_occurrence": "Plot 42, Hitech Commercial Bay, Begumpet North Zone",
        "description": "Complainant reported midnight theft of luxury SUV (Toyota Fortuner, White, TS-09-EA-4412) parked outside commercial building. Smart key was with owner in apartment.",
        "status": "INVESTIGATING",
        "complainant_name": "Arvind K. Murthy",
        "complainant_phone": "+91-98490-55441",
        "created_by": io_officer_id,
        "created_at": datetime(2026, 8, 14, 7, 0, tzinfo=timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    firs_col.update_one({"fir_number": fir_number}, {"$set": fir_doc}, upsert=True)

    # 2. Case Dossier
    case_doc = {
        "case_id": case_id,
        "fir_number": fir_number,
        "title": "Midnight Grand Theft of Luxury SUV from Commercial Hub",
        "crime_type": "Vehicle Theft",
        "priority": "HIGH",
        "status": "UNDER INVESTIGATION",
        "station_id": station_id,
        "io_officer_id": io_officer_id,
        "assigned_officers": [io_officer_id, "TS-POL-006"],
        "location": "Plot 42, Commercial Hub, Begumpet North Zone",
        "summary": "Targeted theft of White 2024 Toyota Fortuner 4x4 (TS-09-EA-4412) from external bay. Security camera shows two masked perpetrators carrying RF relay antenna and OBD diagnostic tool.",
        "modus_operandi": "Keyless relay frequency cloning paired with CAN-bus injector tool. Thieves amplified smart key signal from complainant's 2nd-floor balcony, unlocked doors in 45 seconds, and used diagnostic tool to register blank key fob.",
        "created_at": datetime(2026, 8, 14, 7, 15, tzinfo=timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    cases_col.update_one({"case_id": case_id}, {"$set": case_doc}, upsert=True)

    # 3. Complainant
    complainants_col.update_one(
        {"case_id": case_id, "name": "Arvind K. Murthy"},
        {
            "$set": {
                "case_id": case_id,
                "name": "Arvind K. Murthy",
                "contact_phone": "+91-98490-55441",
                "address": "Flat 204, Fortune Residency, Begumpet, Hyderabad",
                "identification_id": "AADHAAR-8834-1122-9011",
                "statement_summary": "Vehicle was securely parked and locked at 23:30 hrs. Smart key remained in bedroom drawer. Discovered vehicle missing at 06:00 hrs.",
                "recorded_at": datetime(2026, 8, 14, 7, 30, tzinfo=timezone.utc),
            }
        },
        upsert=True,
    )

    # 4. Suspects
    suspects_col.update_one(
        {"case_id": case_id, "name": "Ravi 'Keyless' Teja"},
        {
            "$set": {
                "case_id": case_id,
                "name": "Ravi 'Keyless' Teja",
                "alias": "Keyless Ravi",
                "status": "WANTED",
                "physical_description": "Male, approx 32 years, 5ft 9in, athletic build, scar above left eyebrow.",
                "prior_convictions": "3 prior convictions under IPC 379 for high-end vehicle theft in Cyberabad.",
                "alibi_statement": "Unreachable on mobile; absconding from registered residence.",
                "recorded_at": datetime(2026, 8, 14, 9, 0, tzinfo=timezone.utc),
            }
        },
        upsert=True,
    )

    # 5. Witness
    witnesses_col.update_one(
        {"case_id": case_id, "name": "Mohanlal"},
        {
            "$set": {
                "case_id": case_id,
                "name": "Mohanlal",
                "contact_phone": "+91-98491-00223",
                "statement_summary": "Night watchman observed a dark grey Hyundai Creta without front plate circling the avenue at 01:35 hrs.",
                "credibility_notes": "High - eyewitness corroborated by road junction camera timestamp.",
                "is_protected": False,
                "recorded_at": datetime(2026, 8, 14, 10, 0, tzinfo=timezone.utc),
            }
        },
        upsert=True,
    )

    # 6. Property
    property_col.update_one(
        {"case_id": case_id, "serial_or_reg_number": "TS-09-EA-4412"},
        {
            "$set": {
                "case_id": case_id,
                "item_type": "VEHICLE",
                "description": "2024 Toyota Fortuner 4x4, Pearl White, Chasis # MBF441299001",
                "estimated_value_inr": 4250000.0,
                "serial_or_reg_number": "TS-09-EA-4412",
                "recovery_status": "REPORTED_STOLEN",
                "seizure_location": "Commercial Hub Bay 4",
                "recorded_at": datetime(2026, 8, 14, 8, 0, tzinfo=timezone.utc),
            }
        },
        upsert=True,
    )

    # 7. Real Dummy Evidence Files in data/evidence/
    ensure_storage_directories()
    dummy_files = [
        ("showcase_cctv_footage.mp4", ".mp4", "CCTV Camera 4 Video Capture (Perpetrators Entering)", "DIGITAL_MEDIA"),
        ("showcase_crime_scene_photo.jpg", ".jpg", "Exterior Parking Scene Tire Marks Photograph", "FORENSIC"),
        ("showcase_preliminary_forensics.pdf", ".pdf", "Forensic Unit Preliminary Technical Dossier", "DOCUMENT"),
    ]

    for fname, ext, desc, ev_type in dummy_files:
        fbytes = create_dummy_file_bytes(ext, f"Case {case_id} Evidence: {fname}")
        stored_fname, stored_path, sha256_hash, mime_type, file_size = save_evidence_file(
            content=fbytes,
            original_filename=fname,
            case_id=case_id,
        )

        ev_id = f"EVD-{case_id[-4:]}-{fname[:8].upper()}"
        evidence_col.update_one(
            {"evidence_id": ev_id},
            {
                "$set": {
                    "evidence_id": ev_id,
                    "case_id": case_id,
                    "name": fname,
                    "evidence_type": ev_type,
                    "description": desc,
                    "file_path": stored_path,
                    "stored_filename": stored_fname,
                    "original_name": fname,
                    "mime_type": mime_type,
                    "sha256_hash": sha256_hash,
                    "file_size_bytes": file_size,
                    "current_custodian_id": io_officer_id,
                    "storage_location": "North Station Digital Evidence Vault",
                    "uploaded_by": io_officer_id,
                    "uploaded_at": datetime(2026, 8, 14, 11, 0, tzinfo=timezone.utc),
                }
            },
            upsert=True,
        )

        # Initial chain of custody entry
        custody_col.update_one(
            {"evidence_id": ev_id, "transfer_reason": "INITIAL_SEIZURE_AND_EVIDENCE_LOGGING"},
            {
                "$set": {
                    "transfer_id": f"TRF-{ev_id}-001",
                    "evidence_id": ev_id,
                    "from_officer_id": "CRIME_SCENE_TECH",
                    "to_officer_id": io_officer_id,
                    "transfer_reason": "INITIAL_SEIZURE_AND_EVIDENCE_LOGGING",
                    "authorized_by": io_officer_id,
                    "notes": f"Secure ingestion of {fname} into custody.",
                    "timestamp": datetime(2026, 8, 14, 11, 15, tzinfo=timezone.utc),
                }
            },
            upsert=True,
        )

    # 8. Timeline Events
    timeline_events = [
        ("Crime Incident", "INCIDENT", "Vehicle driven out of commercial parking bay towards Outer Ring Road.", datetime(2026, 8, 14, 1, 47, tzinfo=timezone.utc)),
        ("First Information Report", "FIR", "FIR registered and assigned to SI Rajeshwar Rao (TS-POL-003).", datetime(2026, 8, 14, 7, 0, tzinfo=timezone.utc)),
        ("CCTV Retrieval", "EVIDENCE_SEIZED", "High-definition camera footage acquired from perimeter building surveillance.", datetime(2026, 8, 14, 11, 30, tzinfo=timezone.utc)),
        ("Toll Plaza Camera Hit", "LEAD", "Vehicle detected crossing Patancheru Toll Plaza without fastag at 02:24 hrs.", datetime(2026, 8, 14, 14, 0, tzinfo=timezone.utc)),
        ("Suspect Bulletin Issued", "SEARCH", "Statewide Lookout Notice issued for Ravi 'Keyless' Teja.", datetime(2026, 8, 15, 9, 0, tzinfo=timezone.utc)),
    ]

    for title, ev_type, desc, ts in timeline_events:
        timeline_col.update_one(
            {"case_id": case_id, "title": title},
            {
                "$set": {
                    "case_id": case_id,
                    "title": title,
                    "event_type": ev_type,
                    "description": desc,
                    "recorded_by": io_officer_id,
                    "timestamp": ts,
                }
            },
            upsert=True,
        )

    # 9. Case Notes
    notes_col.update_one(
        {"case_id": case_id, "content": {"$regex": "CAN-bus injection tool"}},
        {
            "$set": {
                "case_id": case_id,
                "author_id": io_officer_id,
                "author_name": "Rajeshwar Rao",
                "note_type": "TACTICAL_NOTE",
                "content": "Perpetrators utilized professional CAN-bus injection tool through front left headlight assembly. Coordinated with Cyber Crime Division (TS-POL-006) to analyze device signatures.",
                "is_confidential": False,
                "created_at": datetime(2026, 8, 14, 16, 0, tzinfo=timezone.utc),
            }
        },
        upsert=True,
    )

    # 10. Case Assignment
    assignments_col.update_one(
        {"case_id": case_id, "officer_id": io_officer_id},
        {
            "$set": {
                "case_id": case_id,
                "officer_id": io_officer_id,
                "assigned_by": "TS-POL-001",
                "assignment_role": "LEAD_IO",
                "assigned_at": datetime(2026, 8, 14, 7, 10, tzinfo=timezone.utc),
                "active": True,
            }
        },
        upsert=True,
    )

    logger.info("Mandatory showcase case '%s' seeded successfully.", case_id)
    return case_id


def seed_large_case_dataset(db: Database, target_count: int = 160) -> int:
    """Generate and idempotently seed 150+ realistic synthetic cases, 40+ FIRs, and related entities."""
    cases_col = get_cases_col(db)
    firs_col = get_firs_col(db)
    complainants_col = get_complainants_col(db)
    suspects_col = get_suspects_col(db)
    property_col = get_property_items_col(db)
    timeline_col = get_investigation_timeline_col(db)
    notes_col = get_case_notes_col(db)
    assignments_col = get_case_assignments_col(db)

    # First, seed the showcase case
    seed_showcase_case(db)

    existing_count = cases_col.count_documents({})
    if existing_count >= target_count:
        logger.info("Cases collection already contains %d cases. Skipping bulk generation.", existing_count)
        return existing_count

    random.seed(42)  # Deterministic seed for reproducible testing
    cases_to_create = target_count - existing_count

    cities = ["Cyberabad", "Hyderabad", "Banjara Hills", "Madhapur", "Gachibowli", "Secunderabad", "Begumpet", "Jubilee Hills", "Charminar", "Kukatpally"]
    first_names = ["Kiran", "Suresh", "Lakshmi", "Venkatesh", "Pooja", "Arun", "Deepak", "Sandhya", "Harish", "Anil", "Bhavani", "Manish", "Swathi", "Gopal"]
    last_names = ["Reddy", "Rao", "Varma", "Goud", "Patel", "Naidu", "Sharma", "Deshmukh", "Chary", "Gupta", "Kulkarni", "Babu"]

    logger.info("Generating %d synthetic cases to fulfill 150+ case requirement...", cases_to_create)

    for i in range(1, cases_to_create + 1):
        num_str = f"{i:04d}"
        case_id = f"PACT-CASE-2026-{num_str}"

        # Skip if showcase
        if case_id == "PACT-CASE-2026-0042":
            continue

        c_type = random.choice(CRIME_TYPES)
        priority = random.choice(PRIORITIES)
        status = random.choice(STATUSES)
        station_id = random.choice(STATION_IDS)
        io_id = random.choice(OFFICER_IDS)
        loc = f"{random.choice(cities)} Sector {random.randint(1, 15)}"

        mo_title, mo_desc = random.choice(MO_TEMPLATES)
        fir_number = f"TS/{station_id[-3:]}/2026/{num_str}"

        comp_name = f"{random.choice(first_names)} {random.choice(last_names)}"
        comp_phone = f"+91-9440-{random.randint(100000, 999999)}"

        incident_days_ago = random.randint(5, 300)
        incident_time = datetime.now(timezone.utc) - timedelta(days=incident_days_ago)

        title = f"{c_type} Incident at {loc}"
        summary = f"Investigation into reported {c_type.lower()} occurring near {loc}. {mo_desc[:120]}..."

        # 1. FIR (seed for first 50 cases)
        if i <= 50:
            fir_record = {
                "fir_number": fir_number,
                "station_id": station_id,
                "incident_date": incident_time,
                "reported_date": incident_time + timedelta(hours=random.randint(2, 24)),
                "crime_type": c_type,
                "place_of_occurrence": loc,
                "description": summary,
                "status": "INVESTIGATING" if status == "UNDER INVESTIGATION" else "REGISTERED",
                "complainant_name": comp_name,
                "complainant_phone": comp_phone,
                "created_by": io_id,
                "created_at": incident_time,
                "updated_at": datetime.now(timezone.utc),
            }
            firs_col.update_one({"fir_number": fir_number}, {"$set": fir_record}, upsert=True)

        # 2. Case Dossier
        assigned_officers = [io_id]
        helper = random.choice(OFFICER_IDS)
        if helper != io_id:
            assigned_officers.append(helper)

        case_record = {
            "case_id": case_id,
            "fir_number": fir_number,
            "title": title,
            "crime_type": c_type,
            "priority": priority,
            "status": status,
            "station_id": station_id,
            "io_officer_id": io_id,
            "assigned_officers": assigned_officers,
            "location": loc,
            "summary": summary,
            "modus_operandi": f"{mo_title}: {mo_desc}",
            "created_at": incident_time,
            "updated_at": datetime.now(timezone.utc),
        }
        cases_col.update_one({"case_id": case_id}, {"$set": case_record}, upsert=True)

        # 3. Complainant
        complainants_col.update_one(
            {"case_id": case_id},
            {
                "$set": {
                    "case_id": case_id,
                    "name": comp_name,
                    "contact_phone": comp_phone,
                    "address": f"Residency near {loc}",
                    "statement_summary": f"Reported {c_type} to local station.",
                    "recorded_at": incident_time,
                }
            },
            upsert=True,
        )

        # 4. Suspect for ~50% of cases
        if random.random() > 0.4:
            s_name = f"{random.choice(first_names)} {random.choice(last_names)}"
            suspects_col.update_one(
                {"case_id": case_id, "name": s_name},
                {
                    "$set": {
                        "case_id": case_id,
                        "name": s_name,
                        "alias": f"Alias {s_name.split()[0]}",
                        "status": random.choice(["SUSPECTED", "WANTED", "ARRESTED", "DETAINED"]),
                        "physical_description": "Medium build, approx 30-40 years.",
                        "prior_convictions": "Under investigation",
                        "recorded_at": incident_time + timedelta(days=1),
                    }
                },
                upsert=True,
            )

        # 5. Timeline Event
        timeline_col.update_one(
            {"case_id": case_id, "event_type": "INITIAL_REPORT"},
            {
                "$set": {
                    "case_id": case_id,
                    "title": "Case Intake and IO Assignment",
                    "event_type": "INITIAL_REPORT",
                    "description": f"FIR registered and assigned to IO {io_id}.",
                    "recorded_by": io_id,
                    "timestamp": incident_time,
                }
            },
            upsert=True,
        )

        # 6. Assignment record
        assignments_col.update_one(
            {"case_id": case_id, "officer_id": io_id},
            {
                "$set": {
                    "case_id": case_id,
                    "officer_id": io_id,
                    "assigned_by": "TS-POL-001",
                    "assignment_role": "LEAD_IO",
                    "assigned_at": incident_time,
                    "active": True,
                }
            },
            upsert=True,
        )

    final_count = cases_col.count_documents({})
    logger.info("Phase 2 bulk seeding complete. Total Cases in DB: %d", final_count)
    return final_count


def seed_phase2(db: Optional[Database] = None) -> Dict[str, int]:
    """Execute complete idempotent Phase 2 seeding."""
    target_db = db if db is not None else get_db()
    total_cases = seed_large_case_dataset(target_db, target_count=160)
    total_firs = get_firs_col(target_db).count_documents({})
    total_evidence = get_evidence_col(target_db).count_documents({})

    return {
        "cases": total_cases,
        "firs": total_firs,
        "evidence": total_evidence,
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    seed_phase2()
