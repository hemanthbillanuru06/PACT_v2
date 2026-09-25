"""Case Dossier, FIR, Case Notes, Timeline, and Assignment domain models."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class FIRRecord:
    """First Information Report domain model."""
    fir_number: str
    station_id: str
    incident_date: Any
    reported_date: Any
    crime_type: str
    description: str = ""
    place_of_occurrence: str = ""
    status: str = "REGISTERED"  # REGISTERED, INVESTIGATING, CHARGESHEETED, CLOSED
    complainant_name: str = "Anonymous"
    complainant_phone: str = "N/A"
    complainant_contact: str = ""
    acts_and_sections: str = ""
    details: str = ""
    created_by: str = "SYSTEM"
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)

    def __post_init__(self):
        if not self.complainant_contact and self.complainant_phone:
            self.complainant_contact = self.complainant_phone
        if not self.complainant_phone and self.complainant_contact:
            self.complainant_phone = self.complainant_contact
        if not self.description and self.details:
            self.description = self.details
        if not self.details and self.description:
            self.details = self.description

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fir_number": self.fir_number,
            "station_id": self.station_id,
            "incident_date": self.incident_date,
            "reported_date": self.reported_date,
            "crime_type": self.crime_type,
            "description": self.description,
            "details": self.details,
            "place_of_occurrence": self.place_of_occurrence,
            "status": self.status,
            "complainant_name": self.complainant_name,
            "complainant_phone": self.complainant_phone,
            "complainant_contact": self.complainant_contact,
            "acts_and_sections": self.acts_and_sections,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass
class CaseDossier:
    """Case Dossier domain model."""
    case_id: str
    fir_number: str
    title: str
    crime_type: str
    station_id: str
    io_officer_id: str
    priority: str = "MEDIUM"  # LOW, MEDIUM, HIGH, CRITICAL
    status: str = "UNDER INVESTIGATION"  # OPEN, UNDER INVESTIGATION, CHARGESHEETED, CLOSED, COLD_CASE
    summary: str = ""
    description: str = ""
    modus_operandi: str = ""
    location: str = ""
    assigned_officers: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)

    def __post_init__(self):
        if not self.summary and self.description:
            self.summary = self.description
        if not self.description and self.summary:
            self.description = self.summary

    @property
    def assigned_io_id(self) -> str:
        return self.io_officer_id

    @property
    def fir_id(self) -> str:
        return self.fir_number

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "fir_number": self.fir_number,
            "fir_id": self.fir_number,
            "title": self.title,
            "crime_type": self.crime_type,
            "station_id": self.station_id,
            "io_officer_id": self.io_officer_id,
            "assigned_io_id": self.io_officer_id,
            "priority": self.priority,
            "status": self.status,
            "summary": self.summary,
            "description": self.description,
            "modus_operandi": self.modus_operandi,
            "location": self.location,
            "assigned_officers": self.assigned_officers,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass
class TimelineEvent:
    """Chronological investigation milestone/event."""
    case_id: str
    title: str
    event_type: str  # INCIDENT, ARREST, SEARCH, INTERROGATION, EVIDENCE_SEIZED, CHARGESHEET
    description: str
    recorded_by: str = "SYSTEM"
    event_id: str = ""
    location: str = ""
    timestamp: datetime = field(default_factory=utc_now)

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "case_id": self.case_id,
            "title": self.title,
            "event_type": self.event_type,
            "description": self.description,
            "recorded_by": self.recorded_by,
            "location": self.location,
            "timestamp": self.timestamp,
        }


@dataclass
class CaseNote:
    """Officer case diary note or tactical observation."""
    case_id: str
    author_id: str = "SYSTEM"
    author_name: str = ""
    note_type: str = "DIARY_ENTRY"  # DIARY_ENTRY, LEAD, TACTICAL_NOTE, SUPERVISORY_DIRECTIVE
    content: str = ""
    is_confidential: bool = False
    note_id: str = ""
    created_at: datetime = field(default_factory=utc_now)

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "note_id": self.note_id,
            "case_id": self.case_id,
            "author_id": self.author_id,
            "author_name": self.author_name,
            "note_type": self.note_type,
            "content": self.content,
            "is_confidential": self.is_confidential,
            "created_at": self.created_at,
        }


@dataclass
class CaseAssignment:
    """Case assignment tracking record."""
    case_id: str
    officer_id: str
    assigned_by: str
    assignment_role: str  # LEAD_IO, ASSISTING_IO, SUPERVISING_SI
    assigned_at: datetime = field(default_factory=utc_now)
    active: bool = True

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "officer_id": self.officer_id,
            "assigned_by": self.assigned_by,
            "assignment_role": self.assignment_role,
            "assigned_at": self.assigned_at,
            "active": self.active,
        }
