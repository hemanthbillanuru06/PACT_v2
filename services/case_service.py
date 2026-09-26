"""Case Dossier, FIR, Timeline, and Investigation Notes Service with Service-Level RBAC."""
from datetime import datetime, timezone
import logging
import uuid
from typing import List, Dict, Any, Optional, Union
from pymongo.database import Database
from pymongo.errors import PyMongoError

from config.settings import settings
from database.connection import (
    get_db,
    get_firs_col,
    get_cases_col,
    get_investigation_timeline_col,
    get_case_notes_col,
    get_case_assignments_col,
)
from models.case import FIRRecord, CaseDossier, TimelineEvent, CaseNote, CaseAssignment
from security.rbac import enforce_role, UnauthorizedAccessError
from services.audit_service import AuditService
from services.notification_service import NotificationService

logger = logging.getLogger("pact.services.case")


class hybridmethod:
    """Descriptor that behaves as an instance method when called on an instance,
    or as a class method when called on a class."""
    def __init__(self, func):
        self.func = func

    def __get__(self, instance, owner=None):
        if instance is None:
            return lambda *args, **kwargs: self.func(owner, *args, **kwargs)
        return lambda *args, **kwargs: self.func(instance, *args, **kwargs)


class CaseSecurityValidator:
    """Central service-level RBAC validator for Case Dossiers."""

    @staticmethod
    def can_access_case(current_user: Any, case_doc: Dict[str, Any], require_write: bool = False) -> bool:
        """Evaluate if an officer has authorization to access or modify a specific case.

        Rules:
        - ADMIN: Full access across all stations and officers.
        - SP: Department-wide oversight across all stations and officers.
        - SI: Oversight over all cases in their assigned station, plus cases assigned to them.
        - INVESTIGATING_OFFICER: Can ONLY access/modify cases where they are the assigned IO
          or in assigned_officers list.
        - CONSTABLE: Can only view cases explicitly assigned to them. Cannot modify.
        """
        if not current_user or not case_doc:
            return False

        user_role = current_user.get("role") if hasattr(current_user, "get") else getattr(current_user, "role", None)
        user_officer_id = current_user.get("officer_id", "") if hasattr(current_user, "get") else getattr(current_user, "officer_id", "")
        user_station_id = current_user.get("station_id", "") if hasattr(current_user, "get") else getattr(current_user, "station_id", "")

        case_station_id = case_doc.get("station_id", "")
        case_io_id = case_doc.get("io_officer_id", "") or case_doc.get("assigned_io_id", "")
        case_assigned = case_doc.get("assigned_officers", [])

        # ADMIN and SP have department-wide clearance
        if user_role in [settings.ROLE_ADMIN, settings.ROLE_SP]:
            return True

        # SI has station-wide clearance and assigned clearance
        if user_role == settings.ROLE_SI:
            if user_station_id and user_station_id == case_station_id:
                return True
            if user_officer_id in [case_io_id] + case_assigned:
                return True
            return False

        # INVESTIGATING_OFFICER strictly sees only cases assigned to them
        if user_role == settings.ROLE_INVESTIGATING_OFFICER:
            return user_officer_id in [case_io_id] + case_assigned

        # CONSTABLE can only view cases explicitly assigned to them
        if user_role == settings.ROLE_CONSTABLE:
            if require_write:
                return False  # Constables cannot modify case dossiers
            return user_officer_id in case_assigned

        return False

    @staticmethod
    def can_create_fir(current_user: Any) -> bool:
        """Check if an officer role is permitted to create FIRs.
        Explicitly permits CONSTABLE and SI roles (along with IO, SP, and ADMIN).
        """
        if not current_user:
            return False
        role = current_user.get("role") if hasattr(current_user, "get") else getattr(current_user, "role", None)
        return role in [
            settings.ROLE_CONSTABLE,
            settings.ROLE_SI,
            settings.ROLE_INVESTIGATING_OFFICER,
            settings.ROLE_SP,
            settings.ROLE_ADMIN,
        ]

    @classmethod
    def enforce_case_access(
        cls,
        current_user: Any,
        case_doc: Dict[str, Any],
        require_write: bool = False,
        resource_name: str = "case_dossier",
        db: Optional[Database] = None,
    ) -> None:
        """Enforce case access, raising UnauthorizedAccessError and writing to audit_logs upon violation."""
        if not cls.can_access_case(current_user, case_doc, require_write=require_write):
            user_id = current_user.get("officer_id", "unknown") if hasattr(current_user, "get") else getattr(current_user, "officer_id", "unknown")
            role = current_user.get("role", "none") if hasattr(current_user, "get") else getattr(current_user, "role", "none")
            case_id = case_doc.get("case_id", "unknown")
            action = "modify" if require_write else "view"

            AuditService.log_unauthorized_access(
                current_user,
                resource=f"case:{case_id}:{action}",
                db=db,
            )
            logger.warning(
                "Access DENIED: Officer %s (Role: %s) tried to %s protected case %s.",
                user_id, role, action, case_id
            )
            raise UnauthorizedAccessError(
                f"Access Denied: Officer '{user_id}' with role '{role}' is not authorized to {action} case '{case_id}'.",
                user_id=user_id,
                role=role,
                resource=f"case:{case_id}",
            )


class CaseService:
    """Complete service management for Cases, FIRs, Timelines, and Notes."""

    def __init__(self, db: Optional[Database] = None):
        self._db = db

    @staticmethod
    def _resolve_db(caller: Any, explicit_db: Optional[Database] = None) -> Database:
        if explicit_db is not None:
            return explicit_db
        if isinstance(caller, CaseService) and getattr(caller, "_db", None) is not None:
            return caller._db
        return get_db()

    # -------------------------------------------------------------
    # FIR Operations
    # -------------------------------------------------------------
    @hybridmethod
    def create_fir(
        caller,
        current_user: Any = None,
        fir_data: Optional[Dict[str, Any]] = None,
        db: Optional[Database] = None,
        session: Any = None,
        **kwargs
    ) -> Union[bool, FIRRecord]:
        """Create a new FIR. Accessible to CONSTABLE, SI, IO, SP, and ADMIN."""
        user = session or current_user
        if user:
            enforce_role(
                user,
                allowed_roles=[
                    settings.ROLE_CONSTABLE,
                    settings.ROLE_SI,
                    settings.ROLE_INVESTIGATING_OFFICER,
                    settings.ROLE_SP,
                    settings.ROLE_ADMIN,
                ],
                resource_name="firs:create",
            )
        target_db = CaseService._resolve_db(caller, db)
        col = get_firs_col(target_db)

        data = {**(fir_data or {}), **kwargs}
        if "fir_number" not in data or not data["fir_number"]:
            station = data.get("station_id") or (user.get("station_id") if hasattr(user, "get") else getattr(user, "station_id", "HQ"))
            seq = col.count_documents({}) + 1
            data["fir_number"] = f"TS/{station}/2026/{seq:04d}"

        user_officer_id = user.get("officer_id", "SYSTEM") if hasattr(user, "get") else getattr(user, "officer_id", "SYSTEM")
        user_role = user.get("role", "") if hasattr(user, "get") else getattr(user, "role", "")
        station_id = data.get("station_id") or (user.get("station_id", "STN-001") if hasattr(user, "get") else getattr(user, "station_id", "STN-001"))

        record = {
            "fir_number": data.get("fir_number"),
            "station_id": station_id,
            "incident_date": data.get("incident_date", datetime.now(timezone.utc)),
            "reported_date": data.get("reported_date", datetime.now(timezone.utc)),
            "crime_type": data.get("crime_type", "General Crime"),
            "description": data.get("description") or data.get("details", ""),
            "place_of_occurrence": data.get("place_of_occurrence", "N/A"),
            "status": data.get("status", "REGISTERED"),
            "complainant_name": data.get("complainant_name", "Anonymous"),
            "complainant_phone": data.get("complainant_phone") or data.get("complainant_contact", "N/A"),
            "acts_and_sections": data.get("acts_and_sections", ""),
            "created_by": user_officer_id,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
        }

        try:
            col.insert_one(record)
            AuditService.log_event(
                event_type=settings.AUDIT_FIR_CREATED,
                officer_id=user_officer_id,
                role=user_role,
                details={"fir_number": record["fir_number"], "station_id": station_id},
                status="SUCCESS",
                db=target_db,
            )
            if kwargs or isinstance(caller, CaseService):
                return FIRRecord(
                    fir_number=record["fir_number"],
                    station_id=record["station_id"],
                    incident_date=record["incident_date"],
                    reported_date=record["reported_date"],
                    crime_type=record["crime_type"],
                    description=record["description"],
                    place_of_occurrence=record["place_of_occurrence"],
                    status=record["status"],
                    complainant_name=record["complainant_name"],
                    complainant_phone=record["complainant_phone"],
                    acts_and_sections=record["acts_and_sections"],
                    created_by=record["created_by"],
                    created_at=record["created_at"],
                    updated_at=record["updated_at"],
                )
            return True
        except PyMongoError as err:
            logger.error("Failed to create FIR: %s", err)
            if kwargs or isinstance(caller, CaseService):
                raise
            return False

    @hybridmethod
    def get_fir(caller, current_user: Any, fir_number: str, db: Optional[Database] = None) -> Optional[FIRRecord]:
        """Retrieve FIR by number returning domain FIRRecord."""
        target_db = CaseService._resolve_db(caller, db)
        doc = caller.get_fir_by_number(current_user, fir_number, db=target_db)
        if not doc:
            return None
        return FIRRecord(
            fir_number=doc.get("fir_number", ""),
            station_id=doc.get("station_id", ""),
            incident_date=doc.get("incident_date"),
            reported_date=doc.get("reported_date"),
            crime_type=doc.get("crime_type", ""),
            description=doc.get("description", ""),
            place_of_occurrence=doc.get("place_of_occurrence", ""),
            status=doc.get("status", "REGISTERED"),
            complainant_name=doc.get("complainant_name", ""),
            complainant_phone=doc.get("complainant_phone", ""),
            acts_and_sections=doc.get("acts_and_sections", ""),
            created_by=doc.get("created_by", "SYSTEM"),
            created_at=doc.get("created_at", datetime.now(timezone.utc)),
            updated_at=doc.get("updated_at", datetime.now(timezone.utc)),
        )

    @hybridmethod
    def get_fir_by_number(caller, current_user: Any, fir_number: str, db: Optional[Database] = None) -> Optional[Dict[str, Any]]:
        """Retrieve FIR by number."""
        target_db = CaseService._resolve_db(caller, db)
        col = get_firs_col(target_db)
        doc = col.find_one({"fir_number": fir_number}, {"_id": 0})
        if doc:
            user_id = current_user.get("officer_id") if hasattr(current_user, "get") else getattr(current_user, "officer_id", None)
            role = current_user.get("role") if hasattr(current_user, "get") else getattr(current_user, "role", None)
            AuditService.log_event(
                event_type=settings.AUDIT_FIR_VIEWED,
                officer_id=user_id,
                role=role,
                details={"fir_number": fir_number},
                status="SUCCESS",
                db=target_db,
            )
        return doc

    @hybridmethod
    def get_firs(caller, current_user: Any, station_id: Optional[str] = None, limit: int = 100, db: Optional[Database] = None) -> List[Dict[str, Any]]:
        """List FIRs with station-level access control."""
        target_db = CaseService._resolve_db(caller, db)
        col = get_firs_col(target_db)
        query: Dict[str, Any] = {}

        role = current_user.get("role") if hasattr(current_user, "get") else getattr(current_user, "role", None)
        user_station = current_user.get("station_id") if hasattr(current_user, "get") else getattr(current_user, "station_id", None)

        if role == settings.ROLE_SI:
            query["station_id"] = user_station
        elif station_id and role in [settings.ROLE_ADMIN, settings.ROLE_SP]:
            query["station_id"] = station_id

        try:
            cursor = col.find(query, {"_id": 0}).sort("reported_date", -1).limit(limit)
            return list(cursor)
        except PyMongoError as err:
            logger.error("Failed to query FIRs: %s", err)
            return []

    # -------------------------------------------------------------
    # Case Dossier Operations (Strict Service-Level RBAC)
    # -------------------------------------------------------------
    @hybridmethod
    def create_case(
        caller,
        current_user: Any = None,
        case_data: Optional[Dict[str, Any]] = None,
        db: Optional[Database] = None,
        session: Any = None,
        **kwargs
    ) -> Union[bool, CaseDossier]:
        """Create a new Case Dossier."""
        user = session or current_user
        target_db = CaseService._resolve_db(caller, db)
        col = get_cases_col(target_db)

        data = {**(case_data or {}), **kwargs}

        case_id = data.get("case_id")
        if not case_id:
            seq = col.count_documents({}) + 1
            case_id = f"PACT-CASE-2026-{seq:04d}"

        fir_num = data.get("fir_id") or data.get("fir_number", "N/A")
        io_id = data.get("assigned_io_id") or data.get("io_officer_id") or (user.get("officer_id") if hasattr(user, "get") else getattr(user, "officer_id", "UNKNOWN"))
        user_officer_id = user.get("officer_id", "SYSTEM") if hasattr(user, "get") else getattr(user, "officer_id", "SYSTEM")
        user_role = user.get("role", "") if hasattr(user, "get") else getattr(user, "role", "")
        station_id = data.get("station_id") or (user.get("station_id", "STN-001") if hasattr(user, "get") else getattr(user, "station_id", "STN-001"))

        record = {
            "case_id": case_id,
            "fir_number": fir_num,
            "title": data.get("title", "Untitled Case"),
            "crime_type": data.get("crime_type", "General Investigation"),
            "station_id": station_id,
            "io_officer_id": io_id,
            "priority": data.get("priority", "MEDIUM"),
            "status": data.get("status", "UNDER INVESTIGATION"),
            "summary": data.get("description") or data.get("summary", ""),
            "description": data.get("description") or data.get("summary", ""),
            "modus_operandi": data.get("modus_operandi", ""),
            "location": data.get("location", "N/A"),
            "assigned_officers": data.get("assigned_officers", [io_id] if io_id else []),
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
        }

        try:
            col.insert_one(record)
            AuditService.log_event(
                event_type=settings.AUDIT_CASE_CREATED,
                officer_id=user_officer_id,
                role=user_role,
                details={"case_id": record["case_id"], "title": record["title"]},
                status="SUCCESS",
                db=target_db,
            )

            # Notify assigned lead IO
            if io_id and io_id != user_officer_id:
                NotificationService.create_notification(
                    recipient_officer_id=io_id,
                    title="New Case Dossier Assigned",
                    message=f"You have been designated Lead IO for case {record['case_id']}: '{record['title']}'.",
                    event_type="CASE_ASSIGNMENT",
                    case_id=record["case_id"],
                    db=target_db,
                )

            if kwargs or isinstance(caller, CaseService):
                return CaseDossier(
                    case_id=record["case_id"],
                    fir_number=record["fir_number"],
                    title=record["title"],
                    crime_type=record["crime_type"],
                    station_id=record["station_id"],
                    io_officer_id=record["io_officer_id"],
                    priority=record["priority"],
                    status=record["status"],
                    summary=record["summary"],
                    description=record["description"],
                    modus_operandi=record["modus_operandi"],
                    location=record["location"],
                    assigned_officers=record["assigned_officers"],
                    created_at=record["created_at"],
                    updated_at=record["updated_at"],
                )
            return True
        except PyMongoError as err:
            logger.error("Failed to insert case: %s", err)
            if kwargs or isinstance(caller, CaseService):
                raise
            return False

    @hybridmethod
    def get_case(caller, current_user: Any, case_id: str, db: Optional[Database] = None) -> CaseDossier:
        """Retrieve full case dossier returning CaseDossier object with strict service-level RBAC."""
        target_db = CaseService._resolve_db(caller, db)
        doc = caller.get_case_by_id(current_user, case_id, db=target_db)
        if not doc:
            raise FileNotFoundError(f"Case '{case_id}' not found.")
        return CaseDossier(
            case_id=doc.get("case_id", ""),
            fir_number=doc.get("fir_number", ""),
            title=doc.get("title", ""),
            crime_type=doc.get("crime_type", ""),
            station_id=doc.get("station_id", ""),
            io_officer_id=doc.get("io_officer_id", ""),
            priority=doc.get("priority", "MEDIUM"),
            status=doc.get("status", "UNDER INVESTIGATION"),
            summary=doc.get("summary", ""),
            description=doc.get("description", doc.get("summary", "")),
            modus_operandi=doc.get("modus_operandi", ""),
            location=doc.get("location", ""),
            assigned_officers=doc.get("assigned_officers", []),
            created_at=doc.get("created_at", datetime.now(timezone.utc)),
            updated_at=doc.get("updated_at", datetime.now(timezone.utc)),
        )

    @hybridmethod
    def get_case_by_id(caller, current_user: Any, case_id: str, db: Optional[Database] = None) -> Optional[Dict[str, Any]]:
        """Retrieve full case dossier dictionary, strictly enforcing service-level access control."""
        target_db = CaseService._resolve_db(caller, db)
        col = get_cases_col(target_db)

        case_doc = col.find_one({"case_id": case_id}, {"_id": 0})
        if not case_doc:
            return None

        # Mandatory Service-Level RBAC check
        CaseSecurityValidator.enforce_case_access(
            current_user,
            case_doc,
            require_write=False,
            resource_name=f"case:{case_id}:view",
            db=target_db,
        )

        user_id = current_user.get("officer_id") if hasattr(current_user, "get") else getattr(current_user, "officer_id", None)
        role = current_user.get("role") if hasattr(current_user, "get") else getattr(current_user, "role", None)

        AuditService.log_event(
            event_type=settings.AUDIT_CASE_VIEWED,
            officer_id=user_id,
            role=role,
            details={"case_id": case_id, "title": case_doc.get("title")},
            status="SUCCESS",
            db=target_db,
        )
        return case_doc

    @hybridmethod
    def list_cases(caller, current_user: Any, status_filter: Optional[str] = None, priority_filter: Optional[str] = None, limit: int = 200, db: Optional[Database] = None) -> List[CaseDossier]:
        """List authorized cases returning domain CaseDossier objects."""
        target_db = CaseService._resolve_db(caller, db)
        raw_list = caller.get_cases(current_user, status_filter=status_filter, priority_filter=priority_filter, limit=limit, db=target_db)
        return [
            CaseDossier(
                case_id=c.get("case_id", ""),
                fir_number=c.get("fir_number", ""),
                title=c.get("title", ""),
                crime_type=c.get("crime_type", ""),
                station_id=c.get("station_id", ""),
                io_officer_id=c.get("io_officer_id", ""),
                priority=c.get("priority", "MEDIUM"),
                status=c.get("status", "UNDER INVESTIGATION"),
                summary=c.get("summary", ""),
                description=c.get("description", c.get("summary", "")),
                modus_operandi=c.get("modus_operandi", ""),
                location=c.get("location", ""),
                assigned_officers=c.get("assigned_officers", []),
                created_at=c.get("created_at", datetime.now(timezone.utc)),
                updated_at=c.get("updated_at", datetime.now(timezone.utc)),
            )
            for c in raw_list
        ]

    @hybridmethod
    def get_cases(
        caller,
        current_user: Any,
        status_filter: Optional[str] = None,
        priority_filter: Optional[str] = None,
        limit: int = 200,
        db: Optional[Database] = None,
    ) -> List[Dict[str, Any]]:
        """Query cases enforcing service-level RBAC filters directly at the DB layer."""
        target_db = CaseService._resolve_db(caller, db)
        col = get_cases_col(target_db)

        role = current_user.get("role") if hasattr(current_user, "get") else getattr(current_user, "role", None)
        officer_id = current_user.get("officer_id", "") if hasattr(current_user, "get") else getattr(current_user, "officer_id", "")
        station_id = current_user.get("station_id", "") if hasattr(current_user, "get") else getattr(current_user, "station_id", "")

        query: Dict[str, Any] = {}

        if role in [settings.ROLE_ADMIN, settings.ROLE_SP]:
            pass  # Unrestricted
        elif role == settings.ROLE_SI:
            query["$or"] = [
                {"station_id": station_id},
                {"io_officer_id": officer_id},
                {"assigned_officers": officer_id},
            ]
        elif role == settings.ROLE_INVESTIGATING_OFFICER:
            query["$or"] = [
                {"io_officer_id": officer_id},
                {"assigned_officers": officer_id},
            ]
        elif role == settings.ROLE_CONSTABLE:
            query["assigned_officers"] = officer_id
        else:
            return []

        if status_filter and status_filter != "ALL":
            query["status"] = status_filter
        if priority_filter and priority_filter != "ALL":
            query["priority"] = priority_filter

        try:
            cursor = col.find(query, {"_id": 0}).sort("updated_at", -1).limit(limit)
            return list(cursor)
        except PyMongoError as err:
            logger.error("Failed to query cases: %s", err)
            return []

    @hybridmethod
    def update_case_status(
        caller,
        current_user: Any = None,
        case_id: str = "",
        new_status: str = "",
        summary: Optional[str] = None,
        db: Optional[Database] = None,
        session: Any = None,
        **kwargs
    ) -> CaseDossier:
        """Update case status and return updated CaseDossier."""
        user = session or current_user
        target_db = CaseService._resolve_db(caller, db)
        updates = {"status": new_status}
        if summary:
            updates["summary"] = summary
        caller.update_case(user, case_id, updates, db=target_db)
        return caller.get_case(user, case_id, db=target_db)

    @hybridmethod
    def update_case(
        caller,
        current_user: Any,
        case_id: str,
        updates: Dict[str, Any],
        db: Optional[Database] = None,
    ) -> bool:
        """Update case fields with strict service-level write authorization."""
        target_db = CaseService._resolve_db(caller, db)
        col = get_cases_col(target_db)

        case_doc = col.find_one({"case_id": case_id})
        if not case_doc:
            return False

        # Enforce write clearance
        CaseSecurityValidator.enforce_case_access(
            current_user,
            case_doc,
            require_write=True,
            resource_name=f"case:{case_id}:update",
            db=target_db,
        )

        update_payload = {**updates, "updated_at": datetime.now(timezone.utc)}

        try:
            col.update_one({"case_id": case_id}, {"$set": update_payload})
            user_id = current_user.get("officer_id") if hasattr(current_user, "get") else getattr(current_user, "officer_id", None)
            role = current_user.get("role") if hasattr(current_user, "get") else getattr(current_user, "role", None)

            AuditService.log_event(
                event_type=settings.AUDIT_CASE_UPDATED,
                officer_id=user_id,
                role=role,
                details={"case_id": case_id, "updated_fields": list(updates.keys())},
                status="SUCCESS",
                db=target_db,
            )

            # Trigger notification if status changed
            if "status" in updates and case_doc.get("io_officer_id"):
                NotificationService.create_notification(
                    recipient_officer_id=case_doc["io_officer_id"],
                    title=f"Case Status Update: {case_id}",
                    message=f"Status changed to '{updates['status']}' by {user_id}.",
                    event_type="STATUS_CHANGE",
                    case_id=case_id,
                    db=target_db,
                )

            return True
        except PyMongoError as err:
            logger.error("Failed to update case %s: %s", case_id, err)
            return False

    @hybridmethod
    def assign_officer_to_case(
        caller,
        current_user: Any,
        case_id: str,
        target_officer_id: str,
        role_type: str = "ASSISTING_IO",
        db: Optional[Database] = None,
    ) -> bool:
        """Assign an officer to a case."""
        enforce_role(
            current_user,
            allowed_roles=[settings.ROLE_ADMIN, settings.ROLE_SP, settings.ROLE_SI],
            resource_name="case:assign_officer",
        )
        target_db = CaseService._resolve_db(caller, db)
        cases_col = get_cases_col(target_db)
        assign_col = get_case_assignments_col(target_db)

        case_doc = cases_col.find_one({"case_id": case_id})
        if not case_doc:
            return False

        user_role = current_user.get("role") if hasattr(current_user, "get") else getattr(current_user, "role", None)
        user_officer_id = current_user.get("officer_id") if hasattr(current_user, "get") else getattr(current_user, "officer_id", "UNKNOWN")
        user_station_id = current_user.get("station_id") if hasattr(current_user, "get") else getattr(current_user, "station_id", None)

        if user_role == settings.ROLE_SI:
            if case_doc.get("station_id") != user_station_id:
                raise UnauthorizedAccessError(
                    f"SI '{user_officer_id}' cannot assign officers to other stations' cases."
                )

        assignment_doc = {
            "case_id": case_id,
            "officer_id": target_officer_id.upper(),
            "assigned_by": user_officer_id,
            "assignment_role": role_type,
            "assigned_at": datetime.now(timezone.utc),
            "active": True,
        }

        try:
            assign_col.insert_one(assignment_doc)
            cases_col.update_one(
                {"case_id": case_id},
                {
                    "$addToSet": {"assigned_officers": target_officer_id.upper()},
                    "$set": {"updated_at": datetime.now(timezone.utc)},
                }
            )

            AuditService.log_event(
                event_type=settings.AUDIT_CASE_ASSIGNED,
                officer_id=user_officer_id,
                role=user_role,
                details={"case_id": case_id, "assigned_to": target_officer_id, "role": role_type},
                status="SUCCESS",
                db=target_db,
            )

            NotificationService.create_notification(
                recipient_officer_id=target_officer_id,
                title=f"Assigned to Case: {case_id}",
                message=f"You have been assigned as {role_type} on case {case_id} by {user_officer_id}.",
                event_type="CASE_ASSIGNMENT",
                case_id=case_id,
                db=target_db,
            )

            return True
        except PyMongoError as err:
            logger.error("Failed to assign officer: %s", err)
            return False

    # -------------------------------------------------------------
    # Timeline Operations
    # -------------------------------------------------------------
    @hybridmethod
    def add_timeline_event(
        caller,
        current_user: Any = None,
        case_id: str = "",
        event_data: Optional[Dict[str, Any]] = None,
        db: Optional[Database] = None,
        session: Any = None,
        **kwargs
    ) -> Union[bool, TimelineEvent]:
        """Add chronological event to case timeline."""
        user = session or current_user
        target_db = CaseService._resolve_db(caller, db)
        cases_col = get_cases_col(target_db)
        timeline_col = get_investigation_timeline_col(target_db)

        case_doc = cases_col.find_one({"case_id": case_id})
        if not case_doc:
            raise FileNotFoundError(f"Case '{case_id}' not found.")

        CaseSecurityValidator.enforce_case_access(user, case_doc, require_write=True, db=target_db)

        data = {**(event_data or {}), **kwargs}
        user_officer_id = user.get("officer_id", "SYSTEM") if hasattr(user, "get") else getattr(user, "officer_id", "SYSTEM")
        user_role = user.get("role", "") if hasattr(user, "get") else getattr(user, "role", "")

        event_id = f"TLE-{uuid.uuid4().hex[:8].upper()}"
        record = {
            "event_id": event_id,
            "case_id": case_id,
            "title": data.get("title", "Milestone"),
            "event_type": data.get("event_type", "INCIDENT"),
            "description": data.get("description", ""),
            "location": data.get("location", ""),
            "recorded_by": user_officer_id,
            "timestamp": data.get("timestamp") or datetime.now(timezone.utc),
        }

        try:
            timeline_col.insert_one(record)
            AuditService.log_event(
                event_type=settings.AUDIT_TIMELINE_UPDATED,
                officer_id=user_officer_id,
                role=user_role,
                details={"case_id": case_id, "event_title": record["title"]},
                status="SUCCESS",
                db=target_db,
            )
            if kwargs or isinstance(caller, CaseService):
                return TimelineEvent(
                    event_id=record["event_id"],
                    case_id=record["case_id"],
                    title=record["title"],
                    event_type=record["event_type"],
                    description=record["description"],
                    recorded_by=record["recorded_by"],
                    location=record["location"],
                    timestamp=record["timestamp"],
                )
            return True
        except PyMongoError as err:
            logger.error("Failed to add timeline event: %s", err)
            if kwargs or isinstance(caller, CaseService):
                raise
            return False

    @hybridmethod
    def get_timeline(caller, current_user: Any, case_id: str, db: Optional[Database] = None) -> List[TimelineEvent]:
        """Retrieve timeline returning list of TimelineEvent domain objects."""
        target_db = CaseService._resolve_db(caller, db)
        raw_list = caller.get_case_timeline(current_user, case_id, db=target_db)
        return [
            TimelineEvent(
                event_id=e.get("event_id", ""),
                case_id=e.get("case_id", ""),
                title=e.get("title", ""),
                event_type=e.get("event_type", "INCIDENT"),
                description=e.get("description", ""),
                recorded_by=e.get("recorded_by", "SYSTEM"),
                location=e.get("location", ""),
                timestamp=e.get("timestamp", datetime.now(timezone.utc)),
            )
            for e in raw_list
        ]

    @hybridmethod
    def get_case_timeline(caller, current_user: Any, case_id: str, db: Optional[Database] = None) -> List[Dict[str, Any]]:
        """Retrieve chronological timeline dictionaries for an authorized case."""
        target_db = CaseService._resolve_db(caller, db)
        cases_col = get_cases_col(target_db)
        timeline_col = get_investigation_timeline_col(target_db)

        case_doc = cases_col.find_one({"case_id": case_id})
        if not case_doc:
            return []

        CaseSecurityValidator.enforce_case_access(current_user, case_doc, require_write=False, db=target_db)

        try:
            cursor = timeline_col.find({"case_id": case_id}, {"_id": 0}).sort("timestamp", 1)
            return list(cursor)
        except PyMongoError as err:
            logger.error("Failed to query timeline: %s", err)
            return []

    # -------------------------------------------------------------
    # Case Notes Operations
    # -------------------------------------------------------------
    @hybridmethod
    def add_case_note(
        caller,
        current_user: Any = None,
        case_id: str = "",
        note_data: Optional[Dict[str, Any]] = None,
        db: Optional[Database] = None,
        session: Any = None,
        **kwargs
    ) -> Union[bool, CaseNote]:
        """Add case diary entry or tactical observation."""
        user = session or current_user
        target_db = CaseService._resolve_db(caller, db)
        cases_col = get_cases_col(target_db)
        notes_col = get_case_notes_col(target_db)

        case_doc = cases_col.find_one({"case_id": case_id})
        if not case_doc:
            raise FileNotFoundError(f"Case '{case_id}' not found.")

        CaseSecurityValidator.enforce_case_access(user, case_doc, require_write=True, db=target_db)

        data = {**(note_data or {}), **kwargs}
        user_officer_id = user.get("officer_id", "SYSTEM") if hasattr(user, "get") else getattr(user, "officer_id", "SYSTEM")
        user_name = user.get("full_name") if hasattr(user, "get") else getattr(user, "full_name", user_officer_id)

        note_id = f"NOTE-{uuid.uuid4().hex[:8].upper()}"
        record = {
            "note_id": note_id,
            "case_id": case_id,
            "author_id": user_officer_id,
            "author_name": user_name or user_officer_id,
            "note_type": data.get("note_type", "DIARY_ENTRY"),
            "content": data.get("content", ""),
            "is_confidential": data.get("is_confidential", False),
            "created_at": datetime.now(timezone.utc),
        }

        try:
            notes_col.insert_one(record)
            if kwargs or isinstance(caller, CaseService):
                return CaseNote(
                    note_id=record["note_id"],
                    case_id=record["case_id"],
                    author_id=record["author_id"],
                    author_name=record["author_name"],
                    note_type=record["note_type"],
                    content=record["content"],
                    is_confidential=record["is_confidential"],
                    created_at=record["created_at"],
                )
            return True
        except PyMongoError as err:
            logger.error("Failed to insert case note: %s", err)
            if kwargs or isinstance(caller, CaseService):
                raise
            return False

    @hybridmethod
    def get_case_notes(caller, current_user: Any, case_id: str, db: Optional[Database] = None) -> List[CaseNote]:
        """Retrieve case diary notes returning domain CaseNote objects."""
        target_db = CaseService._resolve_db(caller, db)
        cases_col = get_cases_col(target_db)
        notes_col = get_case_notes_col(target_db)

        case_doc = cases_col.find_one({"case_id": case_id})
        if not case_doc:
            return []

        CaseSecurityValidator.enforce_case_access(current_user, case_doc, require_write=False, db=target_db)

        try:
            cursor = notes_col.find({"case_id": case_id}, {"_id": 0}).sort("created_at", -1)
            return [
                CaseNote(
                    note_id=n.get("note_id", ""),
                    case_id=n.get("case_id", ""),
                    author_id=n.get("author_id", ""),
                    author_name=n.get("author_name", ""),
                    note_type=n.get("note_type", "DIARY_ENTRY"),
                    content=n.get("content", ""),
                    is_confidential=n.get("is_confidential", False),
                    created_at=n.get("created_at", datetime.now(timezone.utc)),
                )
                for n in cursor
            ]
        except PyMongoError as err:
            logger.error("Failed to query case notes: %s", err)
            return []
