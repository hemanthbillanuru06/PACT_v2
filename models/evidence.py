"""Evidence and Chain of Custody domain models."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class EvidenceItem:
    evidence_id: str
    case_id: str
    name: str
    evidence_type: str  # DOCUMENT, PHYSICAL, DIGITAL_MEDIA, FORENSIC, CCTV_FOOTAGE
    description: str
    file_path: Optional[str]  # Absolute path to file in data/evidence/
    stored_filename: Optional[str]
    original_name: Optional[str]
    mime_type: Optional[str]
    sha256_hash: Optional[str]
    file_size_bytes: int = 0
    current_custodian_id: str = ""
    storage_location: str = "Central Evidence Locker"
    uploaded_by: str = ""
    uploaded_at: datetime = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "case_id": self.case_id,
            "name": self.name,
            "evidence_type": self.evidence_type,
            "description": self.description,
            "file_path": self.file_path,
            "stored_filename": self.stored_filename,
            "original_name": self.original_name,
            "mime_type": self.mime_type,
            "sha256_hash": self.sha256_hash,
            "file_size_bytes": self.file_size_bytes,
            "current_custodian_id": self.current_custodian_id,
            "storage_location": self.storage_location,
            "uploaded_by": self.uploaded_by,
            "uploaded_at": self.uploaded_at,
        }


@dataclass
class CustodyTransfer:
    transfer_id: str
    evidence_id: str
    from_officer_id: str
    to_officer_id: str
    transfer_reason: str  # FORENSIC_LAB_EXAMINATION, COURT_PRESENTATION, SECURE_STORAGE_TRANSFER
    authorized_by: str
    notes: str = ""
    timestamp: datetime = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "transfer_id": self.transfer_id,
            "evidence_id": self.evidence_id,
            "from_officer_id": self.from_officer_id,
            "to_officer_id": self.to_officer_id,
            "transfer_reason": self.transfer_reason,
            "authorized_by": self.authorized_by,
            "notes": self.notes,
            "timestamp": self.timestamp,
        }
