"""User and Officer domain models for PACT."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Dict, Any


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class OfficerProfile:
    """Officer metadata."""
    officer_id: str
    badge_number: str
    full_name: str
    rank: str
    station_id: str
    contact_phone: str
    blood_group: str
    joined_date: datetime = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "officer_id": self.officer_id,
            "badge_number": self.badge_number,
            "full_name": self.full_name,
            "rank": self.rank,
            "station_id": self.station_id,
            "contact_phone": self.contact_phone,
            "blood_group": self.blood_group,
            "joined_date": self.joined_date,
        }


@dataclass
class UserAccount:
    """System authentication user account."""
    officer_id: str
    email: str
    password_hash: str
    role: str
    is_active: bool = True
    is_locked: bool = False
    failed_login_attempts: int = 0
    created_at: datetime = field(default_factory=utc_now)
    last_successful_login: Optional[datetime] = None
    last_failed_login: Optional[datetime] = None
    locked_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "officer_id": self.officer_id,
            "email": self.email,
            "password_hash": self.password_hash,
            "role": self.role,
            "is_active": self.is_active,
            "is_locked": self.is_locked,
            "failed_login_attempts": self.failed_login_attempts,
            "created_at": self.created_at,
            "last_successful_login": self.last_successful_login,
            "last_failed_login": self.last_failed_login,
            "locked_at": self.locked_at,
        }
