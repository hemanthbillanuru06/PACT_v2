"""Police station and registry domain models for PACT."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Any, List


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class PoliceStation:
    """Police Station Registry Model."""
    station_id: str
    station_code: str
    name: str
    zone: str
    district: str
    address: str
    contact_phone: str
    emergency_contact: str
    latitude: float
    longitude: float
    sanctioned_strength: int
    active: bool = True
    created_at: datetime = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "station_id": self.station_id,
            "station_code": self.station_code,
            "name": self.name,
            "zone": self.zone,
            "district": self.district,
            "address": self.address,
            "contact_phone": self.contact_phone,
            "emergency_contact": self.emergency_contact,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "sanctioned_strength": self.sanctioned_strength,
            "active": self.active,
            "created_at": self.created_at,
        }
