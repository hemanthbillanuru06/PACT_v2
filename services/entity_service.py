"""Entity tracking service: Complainants, Victims, Suspects, Witnesses, and Property."""
from datetime import datetime, timezone
import logging
import uuid
from typing import List, Dict, Any, Optional, Union
from pymongo.database import Database
from pymongo.errors import PyMongoError

from database.connection import (
    get_db,
    get_cases_col,
    get_complainants_col,
    get_victims_col,
    get_suspects_col,
    get_witnesses_col,
    get_property_items_col,
)
from models.entities import Complainant, Victim, Suspect, Witness, PropertyItem
from services.case_service import CaseSecurityValidator

logger = logging.getLogger("pact.services.entities")


class hybridmethod:
    """Descriptor that behaves as an instance method when called on an instance,
    or as a class method when called on a class."""
    def __init__(self, func):
        self.func = func

    def __get__(self, instance, owner=None):
        if instance is None:
            return lambda *args, **kwargs: self.func(owner, *args, **kwargs)
        return lambda *args, **kwargs: self.func(instance, *args, **kwargs)


class EntityService:
    """Service for managing people and property associated with cases."""

    def __init__(self, db: Optional[Database] = None):
        self._db = db

    @staticmethod
    def _resolve_db(caller: Any, explicit_db: Optional[Database] = None) -> Database:
        if explicit_db is not None:
            return explicit_db
        if isinstance(caller, EntityService) and getattr(caller, "_db", None) is not None:
            return caller._db
        return get_db()

    # ---------------- Complainants ----------------
    @hybridmethod
    def add_complainant(
        caller,
        current_user: Any = None,
        case_id: str = "",
        data: Optional[Dict[str, Any]] = None,
        db: Optional[Database] = None,
        session: Any = None,
        **kwargs
    ) -> Union[bool, Complainant]:
        user = session or current_user
        target_db = EntityService._resolve_db(caller, db)
        case_doc = get_cases_col(target_db).find_one({"case_id": case_id})
        if not case_doc:
            raise FileNotFoundError(f"Case '{case_id}' does not exist.")
        CaseSecurityValidator.enforce_case_access(user, case_doc, require_write=True, db=target_db)

        payload = {**(data or {}), **kwargs}
        entity_id = f"CMP-{uuid.uuid4().hex[:8].upper()}"
        record = {
            "entity_id": entity_id,
            "case_id": case_id,
            "name": payload.get("name", "Anonymous"),
            "contact_phone": payload.get("contact_phone") or payload.get("contact_number", ""),
            "address": payload.get("address", ""),
            "identification_id": payload.get("identification_id", ""),
            "statement_summary": payload.get("statement_summary", ""),
            "recorded_at": datetime.now(timezone.utc),
        }
        try:
            get_complainants_col(target_db).insert_one(record)
            if kwargs or isinstance(caller, EntityService):
                return Complainant(
                    entity_id=record["entity_id"],
                    case_id=record["case_id"],
                    name=record["name"],
                    contact_phone=record["contact_phone"],
                    address=record["address"],
                    identification_id=record["identification_id"],
                    statement_summary=record["statement_summary"],
                    recorded_at=record["recorded_at"],
                )
            return True
        except PyMongoError as err:
            logger.error("Failed to add complainant: %s", err)
            if kwargs or isinstance(caller, EntityService):
                raise
            return False

    @hybridmethod
    def get_complainants(caller, current_user: Any, case_id: str, db: Optional[Database] = None) -> List[Dict[str, Any]]:
        target_db = EntityService._resolve_db(caller, db)
        case_doc = get_cases_col(target_db).find_one({"case_id": case_id})
        if not case_doc:
            return []
        CaseSecurityValidator.enforce_case_access(current_user, case_doc, require_write=False, db=target_db)

        try:
            return list(get_complainants_col(target_db).find({"case_id": case_id}, {"_id": 0}))
        except PyMongoError as err:
            logger.error("Failed to query complainants: %s", err)
            return []

    # ---------------- Victims ----------------
    @hybridmethod
    def add_victim(
        caller,
        current_user: Any = None,
        case_id: str = "",
        data: Optional[Dict[str, Any]] = None,
        db: Optional[Database] = None,
        session: Any = None,
        **kwargs
    ) -> Union[bool, Victim]:
        user = session or current_user
        target_db = EntityService._resolve_db(caller, db)
        case_doc = get_cases_col(target_db).find_one({"case_id": case_id})
        if not case_doc:
            raise FileNotFoundError(f"Case '{case_id}' does not exist.")
        CaseSecurityValidator.enforce_case_access(user, case_doc, require_write=True, db=target_db)

        payload = {**(data or {}), **kwargs}
        entity_id = f"VIC-{uuid.uuid4().hex[:8].upper()}"
        record = {
            "entity_id": entity_id,
            "case_id": case_id,
            "name": payload.get("name", "Unknown Victim"),
            "age": payload.get("age", 0),
            "gender": payload.get("gender", ""),
            "contact_phone": payload.get("contact_phone") or payload.get("contact_number", ""),
            "contact_number": payload.get("contact_number") or payload.get("contact_phone", ""),
            "address": payload.get("address", ""),
            "injuries_reported": payload.get("injuries_reported") or payload.get("injury_status", "None"),
            "injury_status": payload.get("injury_status") or payload.get("injuries_reported", "NONE"),
            "statement_summary": payload.get("statement_summary", ""),
            "recorded_at": datetime.now(timezone.utc),
        }
        try:
            get_victims_col(target_db).insert_one(record)
            if kwargs or isinstance(caller, EntityService):
                return Victim(
                    entity_id=record["entity_id"],
                    case_id=record["case_id"],
                    name=record["name"],
                    age=record["age"],
                    gender=record["gender"],
                    contact_phone=record["contact_phone"],
                    contact_number=record["contact_number"],
                    address=record["address"],
                    injuries_reported=record["injuries_reported"],
                    injury_status=record["injury_status"],
                    statement_summary=record["statement_summary"],
                    recorded_at=record["recorded_at"],
                )
            return True
        except PyMongoError as err:
            logger.error("Failed to add victim: %s", err)
            if kwargs or isinstance(caller, EntityService):
                raise
            return False

    @hybridmethod
    def get_victims(caller, current_user: Any, case_id: str, db: Optional[Database] = None) -> List[Dict[str, Any]]:
        target_db = EntityService._resolve_db(caller, db)
        case_doc = get_cases_col(target_db).find_one({"case_id": case_id})
        if not case_doc:
            return []
        CaseSecurityValidator.enforce_case_access(current_user, case_doc, require_write=False, db=target_db)

        try:
            return list(get_victims_col(target_db).find({"case_id": case_id}, {"_id": 0}))
        except PyMongoError as err:
            logger.error("Failed to query victims: %s", err)
            return []

    # ---------------- Suspects ----------------
    @hybridmethod
    def add_suspect(
        caller,
        current_user: Any = None,
        case_id: str = "",
        data: Optional[Dict[str, Any]] = None,
        db: Optional[Database] = None,
        session: Any = None,
        **kwargs
    ) -> Union[bool, Suspect]:
        user = session or current_user
        target_db = EntityService._resolve_db(caller, db)
        case_doc = get_cases_col(target_db).find_one({"case_id": case_id})
        if not case_doc:
            raise FileNotFoundError(f"Case '{case_id}' does not exist.")
        CaseSecurityValidator.enforce_case_access(user, case_doc, require_write=True, db=target_db)

        payload = {**(data or {}), **kwargs}
        entity_id = f"SUS-{uuid.uuid4().hex[:8].upper()}"
        aliases = payload.get("aliases", [payload.get("alias")] if payload.get("alias") else [])
        record = {
            "entity_id": entity_id,
            "case_id": case_id,
            "name": payload.get("name", "Unknown Suspect"),
            "alias": payload.get("alias") or (", ".join(aliases) if aliases else ""),
            "aliases": aliases,
            "status": payload.get("status", "SUSPECTED"),
            "physical_description": payload.get("physical_description") or payload.get("identifying_marks", ""),
            "identifying_marks": payload.get("identifying_marks") or payload.get("physical_description", ""),
            "age": payload.get("age"),
            "gender": payload.get("gender", ""),
            "address": payload.get("address", ""),
            "prior_convictions": payload.get("prior_convictions", "None"),
            "alibi_statement": payload.get("alibi_statement", ""),
            "recorded_at": datetime.now(timezone.utc),
        }
        try:
            get_suspects_col(target_db).insert_one(record)
            if kwargs or isinstance(caller, EntityService):
                return Suspect(
                    entity_id=record["entity_id"],
                    case_id=record["case_id"],
                    name=record["name"],
                    alias=record["alias"],
                    aliases=record["aliases"],
                    status=record["status"],
                    physical_description=record["physical_description"],
                    identifying_marks=record["identifying_marks"],
                    age=record["age"],
                    gender=record["gender"],
                    address=record["address"],
                    prior_convictions=record["prior_convictions"],
                    alibi_statement=record["alibi_statement"],
                    recorded_at=record["recorded_at"],
                )
            return True
        except PyMongoError as err:
            logger.error("Failed to add suspect: %s", err)
            if kwargs or isinstance(caller, EntityService):
                raise
            return False

    @hybridmethod
    def get_suspects(caller, current_user: Any, case_id: str, db: Optional[Database] = None) -> List[Dict[str, Any]]:
        target_db = EntityService._resolve_db(caller, db)
        case_doc = get_cases_col(target_db).find_one({"case_id": case_id})
        if not case_doc:
            return []
        CaseSecurityValidator.enforce_case_access(current_user, case_doc, require_write=False, db=target_db)

        try:
            return list(get_suspects_col(target_db).find({"case_id": case_id}, {"_id": 0}))
        except PyMongoError as err:
            logger.error("Failed to query suspects: %s", err)
            return []

    # ---------------- Witnesses ----------------
    @hybridmethod
    def add_witness(
        caller,
        current_user: Any = None,
        case_id: str = "",
        data: Optional[Dict[str, Any]] = None,
        db: Optional[Database] = None,
        session: Any = None,
        **kwargs
    ) -> Union[bool, Witness]:
        user = session or current_user
        target_db = EntityService._resolve_db(caller, db)
        case_doc = get_cases_col(target_db).find_one({"case_id": case_id})
        if not case_doc:
            raise FileNotFoundError(f"Case '{case_id}' does not exist.")
        CaseSecurityValidator.enforce_case_access(user, case_doc, require_write=True, db=target_db)

        payload = {**(data or {}), **kwargs}
        entity_id = f"WIT-{uuid.uuid4().hex[:8].upper()}"
        record = {
            "entity_id": entity_id,
            "case_id": case_id,
            "name": payload.get("name", "Unknown Witness"),
            "contact_phone": payload.get("contact_phone") or payload.get("contact_number", ""),
            "statement_summary": payload.get("statement_summary", ""),
            "credibility_notes": payload.get("credibility_notes") or payload.get("credibility_rating", "HIGH"),
            "credibility_rating": payload.get("credibility_rating") or payload.get("credibility_notes", "HIGH"),
            "is_protected": payload.get("is_protected", False),
            "recorded_at": datetime.now(timezone.utc),
        }
        try:
            get_witnesses_col(target_db).insert_one(record)
            if kwargs or isinstance(caller, EntityService):
                return Witness(
                    entity_id=record["entity_id"],
                    case_id=record["case_id"],
                    name=record["name"],
                    contact_phone=record["contact_phone"],
                    statement_summary=record["statement_summary"],
                    credibility_notes=record["credibility_notes"],
                    credibility_rating=record["credibility_rating"],
                    is_protected=record["is_protected"],
                    recorded_at=record["recorded_at"],
                )
            return True
        except PyMongoError as err:
            logger.error("Failed to add witness: %s", err)
            if kwargs or isinstance(caller, EntityService):
                raise
            return False

    @hybridmethod
    def get_witnesses(caller, current_user: Any, case_id: str, db: Optional[Database] = None) -> List[Dict[str, Any]]:
        target_db = EntityService._resolve_db(caller, db)
        case_doc = get_cases_col(target_db).find_one({"case_id": case_id})
        if not case_doc:
            return []
        CaseSecurityValidator.enforce_case_access(current_user, case_doc, require_write=False, db=target_db)

        try:
            return list(get_witnesses_col(target_db).find({"case_id": case_id}, {"_id": 0}))
        except PyMongoError as err:
            logger.error("Failed to query witnesses: %s", err)
            return []

    # ---------------- Property Items ----------------
    @hybridmethod
    def add_property(
        caller,
        current_user: Any = None,
        case_id: str = "",
        data: Optional[Dict[str, Any]] = None,
        db: Optional[Database] = None,
        session: Any = None,
        **kwargs
    ) -> Union[bool, PropertyItem]:
        """Alias for add_property_item."""
        return caller.add_property_item(current_user=current_user, case_id=case_id, data=data, db=db, session=session, **kwargs)

    @hybridmethod
    def add_property_item(
        caller,
        current_user: Any = None,
        case_id: str = "",
        data: Optional[Dict[str, Any]] = None,
        db: Optional[Database] = None,
        session: Any = None,
        **kwargs
    ) -> Union[bool, PropertyItem]:
        user = session or current_user
        target_db = EntityService._resolve_db(caller, db)
        case_doc = get_cases_col(target_db).find_one({"case_id": case_id})
        if not case_doc:
            raise FileNotFoundError(f"Case '{case_id}' does not exist.")
        CaseSecurityValidator.enforce_case_access(user, case_doc, require_write=True, db=target_db)

        payload = {**(data or {}), **kwargs}
        property_id = f"PROP-{uuid.uuid4().hex[:8].upper()}"
        record = {
            "property_id": property_id,
            "case_id": case_id,
            "item_type": payload.get("item_type") or payload.get("category", "OTHER"),
            "category": payload.get("category") or payload.get("item_type", "OTHER"),
            "description": payload.get("description") or payload.get("item_description", ""),
            "item_description": payload.get("item_description") or payload.get("description", ""),
            "estimated_value_inr": float(payload.get("estimated_value_inr") or payload.get("estimated_value", 0.0)),
            "estimated_value": float(payload.get("estimated_value") or payload.get("estimated_value_inr", 0.0)),
            "serial_or_reg_number": payload.get("serial_or_reg_number", ""),
            "recovery_status": payload.get("recovery_status") or payload.get("status", "REPORTED_STOLEN"),
            "status": payload.get("status") or payload.get("recovery_status", "REPORTED_STOLEN"),
            "seizure_location": payload.get("seizure_location") or payload.get("storage_location", ""),
            "storage_location": payload.get("storage_location") or payload.get("seizure_location", ""),
            "recorded_at": datetime.now(timezone.utc),
        }
        try:
            get_property_items_col(target_db).insert_one(record)
            if kwargs or isinstance(caller, EntityService):
                return PropertyItem(
                    property_id=record["property_id"],
                    case_id=record["case_id"],
                    item_type=record["item_type"],
                    category=record["category"],
                    description=record["description"],
                    item_description=record["item_description"],
                    estimated_value_inr=record["estimated_value_inr"],
                    estimated_value=record["estimated_value"],
                    serial_or_reg_number=record["serial_or_reg_number"],
                    recovery_status=record["recovery_status"],
                    status=record["status"],
                    seizure_location=record["seizure_location"],
                    storage_location=record["storage_location"],
                    recorded_at=record["recorded_at"],
                )
            return True
        except PyMongoError as err:
            logger.error("Failed to add property item: %s", err)
            if kwargs or isinstance(caller, EntityService):
                raise
            return False

    @hybridmethod
    def get_property_items(caller, current_user: Any, case_id: str, db: Optional[Database] = None) -> List[Dict[str, Any]]:
        target_db = EntityService._resolve_db(caller, db)
        case_doc = get_cases_col(target_db).find_one({"case_id": case_id})
        if not case_doc:
            return []
        CaseSecurityValidator.enforce_case_access(current_user, case_doc, require_write=False, db=target_db)

        try:
            return list(get_property_items_col(target_db).find({"case_id": case_id}, {"_id": 0}))
        except PyMongoError as err:
            logger.error("Failed to query property items: %s", err)
            return []

    # ---------------- Aggregation ----------------
    @hybridmethod
    def get_all_entities_for_case(caller, current_user: Any, case_id: str, db: Optional[Database] = None) -> Dict[str, List[Any]]:
        """Retrieve all entity objects for a given case."""
        target_db = EntityService._resolve_db(caller, db)
        case_doc = get_cases_col(target_db).find_one({"case_id": case_id})
        if not case_doc:
            return {"complainants": [], "victims": [], "suspects": [], "witnesses": [], "property_items": []}

        CaseSecurityValidator.enforce_case_access(current_user, case_doc, require_write=False, db=target_db)

        raw_complainants = list(get_complainants_col(target_db).find({"case_id": case_id}, {"_id": 0}))
        raw_victims = list(get_victims_col(target_db).find({"case_id": case_id}, {"_id": 0}))
        raw_suspects = list(get_suspects_col(target_db).find({"case_id": case_id}, {"_id": 0}))
        raw_witnesses = list(get_witnesses_col(target_db).find({"case_id": case_id}, {"_id": 0}))
        raw_props = list(get_property_items_col(target_db).find({"case_id": case_id}, {"_id": 0}))

        return {
            "complainants": [Complainant(**c) for c in raw_complainants],
            "victims": [Victim(**v) for v in raw_victims],
            "suspects": [Suspect(**s) for s in raw_suspects],
            "witnesses": [Witness(**w) for w in raw_witnesses],
            "property_items": [PropertyItem(**p) for p in raw_props],
        }
