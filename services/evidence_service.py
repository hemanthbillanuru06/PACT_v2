"""Evidence management and auditable Chain of Custody service."""
from datetime import datetime, timezone
import logging
import uuid
from typing import List, Dict, Any, Optional, Tuple
from pymongo.database import Database
from pymongo.errors import PyMongoError

from config.settings import settings
from database.connection import (
    get_db,
    get_cases_col,
    get_evidence_col,
    get_evidence_custody_col,
)
from security.file_security import (
    save_evidence_file,
    read_evidence_file,
    validate_evidence_path,
    PathTraversalError,
    SecurityViolationError,
)
from security.rbac import UnauthorizedAccessError
from services.case_service import CaseSecurityValidator
from services.audit_service import AuditService
from services.notification_service import NotificationService

logger = logging.getLogger("pact.services.evidence")


class EvidenceService:
    """Service handling evidence lifecycle, local file storage, and chain of custody."""

    @classmethod
    def register_evidence(
        cls,
        current_user: Dict[str, Any],
        case_id: str,
        content: bytes,
        original_filename: str,
        name: str,
        evidence_type: str,
        description: str = "",
        storage_location: str = "Central Evidence Locker",
        db: Optional[Database] = None,
    ) -> Dict[str, Any]:
        """Save evidence file locally with path validation, record metadata, and initialize chain of custody."""
        target_db = db if db is not None else get_db()
        cases_col = get_cases_col(target_db)
        evidence_col = get_evidence_col(target_db)
        custody_col = get_evidence_custody_col(target_db)

        case_doc = cases_col.find_one({"case_id": case_id})
        if not case_doc:
            raise ValueError(f"Case '{case_id}' does not exist.")

        # Enforce case write clearance
        CaseSecurityValidator.enforce_case_access(current_user, case_doc, require_write=True, db=target_db)

        # Securely store file locally (guarantees path traversal rejection)
        stored_filename, stored_abs_path, sha256_hash, mime_type, file_size = save_evidence_file(
            content=content,
            original_filename=original_filename,
            case_id=case_id,
        )

        evidence_id = f"EVD-{case_id[-4:]}-{uuid.uuid4().hex[:8].upper()}"
        officer_id = current_user.get("officer_id", "UNKNOWN")

        evidence_doc = {
            "evidence_id": evidence_id,
            "case_id": case_id,
            "name": name,
            "evidence_type": evidence_type,
            "description": description,
            "file_path": stored_abs_path,
            "stored_filename": stored_filename,
            "original_name": original_filename,
            "mime_type": mime_type,
            "sha256_hash": sha256_hash,
            "file_size_bytes": file_size,
            "current_custodian_id": officer_id,
            "storage_location": storage_location,
            "uploaded_by": officer_id,
            "uploaded_at": datetime.now(timezone.utc),
        }

        try:
            evidence_col.insert_one(evidence_doc)

            # Initial chain of custody record
            initial_custody = {
                "transfer_id": f"TRF-{uuid.uuid4().hex[:10].upper()}",
                "evidence_id": evidence_id,
                "from_officer_id": "CRIME_SCENE_COLLECTION",
                "to_officer_id": officer_id,
                "transfer_reason": "INITIAL_SEIZURE_AND_EVIDENCE_LOGGING",
                "authorized_by": officer_id,
                "notes": f"Initial evidence intake logged by {officer_id}.",
                "timestamp": datetime.now(timezone.utc),
            }
            custody_col.insert_one(initial_custody)

            AuditService.log_event(
                event_type=settings.AUDIT_EVIDENCE_ADDED,
                officer_id=officer_id,
                role=current_user.get("role"),
                details={"evidence_id": evidence_id, "case_id": case_id, "sha256": sha256_hash},
                status="SUCCESS",
                db=target_db,
            )

            # Send notification to Lead IO if uploaded by an assisting officer
            io_id = case_doc.get("io_officer_id")
            if io_id and io_id != officer_id:
                NotificationService.create_notification(
                    recipient_officer_id=io_id,
                    title=f"New Evidence Added: {case_id}",
                    message=f"Officer {officer_id} uploaded evidence item '{name}' ({evidence_type}).",
                    event_type="EVIDENCE_UPDATE",
                    case_id=case_id,
                    db=target_db,
                )

            return evidence_doc

        except PyMongoError as err:
            logger.error("Failed to register evidence record: %s", err)
            raise

    @classmethod
    def get_case_evidence(cls, current_user: Dict[str, Any], case_id: str, db: Optional[Database] = None) -> List[Dict[str, Any]]:
        """List all evidence for a case, enforcing RBAC."""
        target_db = db if db is not None else get_db()
        cases_col = get_cases_col(target_db)
        evidence_col = get_evidence_col(target_db)

        case_doc = cases_col.find_one({"case_id": case_id})
        if not case_doc:
            return []

        CaseSecurityValidator.enforce_case_access(current_user, case_doc, require_write=False, db=target_db)

        try:
            items = list(evidence_col.find({"case_id": case_id}, {"_id": 0}))
            AuditService.log_event(
                event_type=settings.AUDIT_EVIDENCE_VIEWED,
                officer_id=current_user.get("officer_id"),
                role=current_user.get("role"),
                details={"case_id": case_id, "count": len(items)},
                status="SUCCESS",
                db=target_db,
            )
            return items
        except PyMongoError as err:
            logger.error("Failed to query evidence: %s", err)
            return []

    @classmethod
    def download_evidence(cls, current_user: Dict[str, Any], evidence_id: str, db: Optional[Database] = None) -> Tuple[bytes, str, str]:
        """Download evidence file content with strict path traversal validation and audit logging."""
        target_db = db if db is not None else get_db()
        cases_col = get_cases_col(target_db)
        evidence_col = get_evidence_col(target_db)

        evidence_doc = evidence_col.find_one({"evidence_id": evidence_id})
        if not evidence_doc:
            raise FileNotFoundError(f"Evidence '{evidence_id}' does not exist.")

        case_id = evidence_doc["case_id"]
        case_doc = cases_col.find_one({"case_id": case_id})
        if not case_doc:
            raise FileNotFoundError(f"Case '{case_id}' does not exist.")

        # Enforce RBAC
        CaseSecurityValidator.enforce_case_access(current_user, case_doc, require_write=False, db=target_db)

        stored_filename = evidence_doc.get("stored_filename") or evidence_doc.get("file_path")
        file_bytes = read_evidence_file(stored_filename)

        AuditService.log_event(
            event_type=settings.AUDIT_EVIDENCE_DOWNLOADED,
            officer_id=current_user.get("officer_id"),
            role=current_user.get("role"),
            details={"evidence_id": evidence_id, "case_id": case_id, "filename": evidence_doc.get("original_name")},
            status="SUCCESS",
            db=target_db,
        )

        return file_bytes, evidence_doc.get("original_name", "evidence_file"), evidence_doc.get("mime_type", "application/octet-stream")

    @classmethod
    def transfer_custody(
        cls,
        current_user: Dict[str, Any],
        evidence_id: str,
        to_officer_id: str,
        reason: str,
        notes: str = "",
        db: Optional[Database] = None,
    ) -> bool:
        """Transfer evidence chain of custody to another officer."""
        target_db = db if db is not None else get_db()
        cases_col = get_cases_col(target_db)
        evidence_col = get_evidence_col(target_db)
        custody_col = get_evidence_custody_col(target_db)

        evidence_doc = evidence_col.find_one({"evidence_id": evidence_id})
        if not evidence_doc:
            raise ValueError(f"Evidence '{evidence_id}' does not exist.")

        case_id = evidence_doc["case_id"]
        case_doc = cases_col.find_one({"case_id": case_id})
        if not case_doc:
            raise ValueError(f"Case '{case_id}' does not exist.")

        # Check authorization: user must have write access to the case
        CaseSecurityValidator.enforce_case_access(current_user, case_doc, require_write=True, db=target_db)

        from_officer = evidence_doc.get("current_custodian_id", current_user.get("officer_id"))
        transfer_record = {
            "transfer_id": f"TRF-{uuid.uuid4().hex[:10].upper()}",
            "evidence_id": evidence_id,
            "from_officer_id": from_officer,
            "to_officer_id": to_officer_id.upper(),
            "transfer_reason": reason,
            "authorized_by": current_user.get("officer_id"),
            "notes": notes,
            "timestamp": datetime.now(timezone.utc),
        }

        try:
            custody_col.insert_one(transfer_record)
            evidence_col.update_one(
                {"evidence_id": evidence_id},
                {"$set": {"current_custodian_id": to_officer_id.upper()}}
            )

            AuditService.log_event(
                event_type=settings.AUDIT_EVIDENCE_TRANSFERRED,
                officer_id=current_user.get("officer_id"),
                role=current_user.get("role"),
                details={
                    "evidence_id": evidence_id,
                    "from_officer": from_officer,
                    "to_officer": to_officer_id.upper(),
                    "reason": reason,
                },
                status="SUCCESS",
                db=target_db,
            )

            # Notify receiving officer
            NotificationService.create_notification(
                recipient_officer_id=to_officer_id.upper(),
                title=f"Evidence Custody Transferred: {evidence_id}",
                message=f"Evidence item '{evidence_doc.get('name')}' transferred to your custody by {current_user.get('officer_id')}. Reason: {reason}.",
                event_type="CUSTODY_TRANSFER",
                case_id=case_id,
                db=target_db,
            )

            return True
        except PyMongoError as err:
            logger.error("Failed to transfer custody: %s", err)
            return False

    @classmethod
    def get_custody_history(cls, current_user: Dict[str, Any], evidence_id: str, db: Optional[Database] = None) -> List[Dict[str, Any]]:
        """Retrieve complete audit trail for an evidence item."""
        target_db = db if db is not None else get_db()
        cases_col = get_cases_col(target_db)
        evidence_col = get_evidence_col(target_db)
        custody_col = get_evidence_custody_col(target_db)

        evidence_doc = evidence_col.find_one({"evidence_id": evidence_id})
        if not evidence_doc:
            return []

        case_doc = cases_col.find_one({"case_id": evidence_doc["case_id"]})
        if not case_doc:
            return []

        CaseSecurityValidator.enforce_case_access(current_user, case_doc, require_write=False, db=target_db)

        try:
            return list(custody_col.find({"evidence_id": evidence_id}, {"_id": 0}).sort("timestamp", 1))
        except PyMongoError as err:
            logger.error("Failed to query custody history: %s", err)
            return []
