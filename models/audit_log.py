"""Audit log entry domain model for PACT."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Dict, Any


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class AuditLogEntry:
    """Audit log entry representation."""
    event_type: str
    user_id: Optional[str] = None
    officer_id: Optional[str] = None
    role: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    ip_address: str = "127.0.0.1"
    status: str = "SUCCESS"
    timestamp: datetime = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_type": self.event_type,
            "user_id": self.user_id,
            "officer_id": self.officer_id,
            "role": self.role,
            "details": self.details,
            "ip_address": self.ip_address,
            "status": self.status,
            "timestamp": self.timestamp,
        }
