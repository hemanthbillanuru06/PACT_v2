"""Entity tracking models: Complainants, Victims, Suspects, Witnesses, Property."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class Complainant:
    case_id: str
    name: str
    contact_phone: str = ""
    address: str = ""
    identification_id: str = ""
    statement_summary: str = ""
    entity_id: str = ""
    recorded_at: datetime = field(default_factory=utc_now)

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "case_id": self.case_id,
            "name": self.name,
            "contact_phone": self.contact_phone,
            "address": self.address,
            "identification_id": self.identification_id,
            "statement_summary": self.statement_summary,
            "recorded_at": self.recorded_at,
        }


@dataclass
class Victim:
    case_id: str
    name: str
    age: int = 0
    gender: str = ""
    contact_phone: str = ""
    contact_number: str = ""
    address: str = ""
    injuries_reported: str = "None"
    injury_status: str = "NONE"
    statement_summary: str = ""
    entity_id: str = ""
    recorded_at: datetime = field(default_factory=utc_now)

    def __post_init__(self):
        if not self.contact_phone and self.contact_number:
            self.contact_phone = self.contact_number
        if not self.contact_number and self.contact_phone:
            self.contact_number = self.contact_phone
        if self.injuries_reported == "None" and self.injury_status != "NONE":
            self.injuries_reported = self.injury_status
        if self.injury_status == "NONE" and self.injuries_reported != "None":
            self.injury_status = self.injuries_reported

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "case_id": self.case_id,
            "name": self.name,
            "age": self.age,
            "gender": self.gender,
            "contact_phone": self.contact_phone,
            "contact_number": self.contact_number,
            "address": self.address,
            "injuries_reported": self.injuries_reported,
            "injury_status": self.injury_status,
            "statement_summary": self.statement_summary,
            "recorded_at": self.recorded_at,
        }


@dataclass
class Suspect:
    case_id: str
    name: str
    alias: str = ""
    aliases: List[str] = field(default_factory=list)
    status: str = "SUSPECTED"  # SUSPECTED, WANTED, DETAINED, ARRESTED, CHARGESHEETED, CLEARED
    physical_description: str = ""
    identifying_marks: str = ""
    age: Optional[int] = None
    gender: str = ""
    address: str = ""
    prior_convictions: str = "None"
    alibi_statement: str = ""
    entity_id: str = ""
    recorded_at: datetime = field(default_factory=utc_now)

    def __post_init__(self):
        if self.aliases and not self.alias:
            self.alias = ", ".join(self.aliases)
        elif self.alias and not self.aliases:
            self.aliases = [self.alias]
        if self.identifying_marks and not self.physical_description:
            self.physical_description = self.identifying_marks
        elif self.physical_description and not self.identifying_marks:
            self.identifying_marks = self.physical_description

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "case_id": self.case_id,
            "name": self.name,
            "alias": self.alias,
            "aliases": self.aliases,
            "status": self.status,
            "age": self.age,
            "gender": self.gender,
            "address": self.address,
            "physical_description": self.physical_description,
            "identifying_marks": self.identifying_marks,
            "prior_convictions": self.prior_convictions,
            "alibi_statement": self.alibi_statement,
            "recorded_at": self.recorded_at,
        }


@dataclass
class Witness:
    case_id: str
    name: str
    contact_phone: str = ""
    statement_summary: str = ""
    credibility_notes: str = "Normal"
    credibility_rating: str = "HIGH"
    is_protected: bool = False
    entity_id: str = ""
    recorded_at: datetime = field(default_factory=utc_now)

    def __post_init__(self):
        if self.credibility_rating and self.credibility_notes == "Normal":
            self.credibility_notes = self.credibility_rating
        elif self.credibility_notes and not self.credibility_rating:
            self.credibility_rating = self.credibility_notes

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "case_id": self.case_id,
            "name": self.name,
            "contact_phone": self.contact_phone,
            "statement_summary": self.statement_summary,
            "credibility_notes": self.credibility_notes,
            "credibility_rating": self.credibility_rating,
            "is_protected": self.is_protected,
            "recorded_at": self.recorded_at,
        }


@dataclass
class PropertyItem:
    case_id: str
    item_type: str = "OTHER"  # VEHICLE, ELECTRONIC, CASH, WEAPON, JEWELRY, DOCUMENT, OTHER
    category: str = ""
    description: str = ""
    item_description: str = ""
    estimated_value_inr: float = 0.0
    estimated_value: float = 0.0
    serial_or_reg_number: str = ""
    recovery_status: str = "REPORTED_STOLEN"  # REPORTED_STOLEN, SEIZED, RECOVERED, RETURNED_TO_OWNER
    status: str = ""
    seizure_location: str = ""
    storage_location: str = ""
    property_id: str = ""
    recorded_at: datetime = field(default_factory=utc_now)

    def __post_init__(self):
        if self.category and self.item_type == "OTHER":
            self.item_type = self.category
        elif self.item_type and not self.category:
            self.category = self.item_type
        if self.item_description and not self.description:
            self.description = self.item_description
        elif self.description and not self.item_description:
            self.item_description = self.description
        if self.estimated_value and self.estimated_value_inr == 0.0:
            self.estimated_value_inr = self.estimated_value
        elif self.estimated_value_inr and self.estimated_value == 0.0:
            self.estimated_value = self.estimated_value_inr
        if self.status and self.recovery_status == "REPORTED_STOLEN":
            self.recovery_status = self.status
        elif self.recovery_status and not self.status:
            self.status = self.recovery_status
        if self.storage_location and not self.seizure_location:
            self.seizure_location = self.storage_location
        elif self.seizure_location and not self.storage_location:
            self.storage_location = self.seizure_location

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "property_id": self.property_id,
            "case_id": self.case_id,
            "item_type": self.item_type,
            "category": self.category,
            "description": self.description,
            "item_description": self.item_description,
            "estimated_value_inr": self.estimated_value_inr,
            "estimated_value": self.estimated_value,
            "serial_or_reg_number": self.serial_or_reg_number,
            "recovery_status": self.recovery_status,
            "status": self.status,
            "seizure_location": self.seizure_location,
            "storage_location": self.storage_location,
            "recorded_at": self.recorded_at,
        }
