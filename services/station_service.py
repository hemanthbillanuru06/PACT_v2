"""Police station registry service with RBAC enforcement."""
import logging
from typing import List, Dict, Any, Optional
from pymongo.database import Database
from pymongo.errors import PyMongoError

from config.settings import settings
from database.connection import get_db, get_police_registry_col
from security.rbac import require_role, enforce_role, UnauthorizedAccessError
from services.audit_service import AuditService

logger = logging.getLogger("pact.services.station")


class StationService:
    """Service for querying and managing police registry stations."""

    @staticmethod
    def get_stations(current_user: Dict[str, Any], db: Optional[Database] = None) -> List[Dict[str, Any]]:
        """List all police stations. Accessible to all verified roles."""
        try:
            enforce_role(
                current_user,
                allowed_roles=settings.ALL_ROLES,
                resource_name="police_registry:list_stations",
            )
        except UnauthorizedAccessError:
            AuditService.log_unauthorized_access(current_user, "police_registry:list_stations", db=db)
            raise

        target_db = db if db is not None else get_db()
        col = get_police_registry_col(target_db)
        try:
            stations = list(col.find({}, {"_id": 0}).sort("station_id", 1))
            return stations
        except PyMongoError as err:
            logger.error("Failed to query police registry stations: %s", err)
            return []

    @staticmethod
    def get_station_by_id(current_user: Dict[str, Any], station_id: str, db: Optional[Database] = None) -> Optional[Dict[str, Any]]:
        """Fetch station by station_id."""
        try:
            enforce_role(
                current_user,
                allowed_roles=settings.ALL_ROLES,
                resource_name="police_registry:view_station_detail",
            )
        except UnauthorizedAccessError:
            AuditService.log_unauthorized_access(current_user, f"police_registry:station:{station_id}", db=db)
            raise

        target_db = db if db is not None else get_db()
        col = get_police_registry_col(target_db)
        try:
            return col.find_one({"station_id": station_id}, {"_id": 0})
        except PyMongoError as err:
            logger.error("Failed to get station %s: %s", station_id, err)
            return None

    @staticmethod
    def add_station(current_user: Dict[str, Any], station_data: Dict[str, Any], db: Optional[Database] = None) -> bool:
        """Create new station in registry. Restricted strictly to ADMIN role."""
        try:
            enforce_role(
                current_user,
                allowed_roles=[settings.ROLE_ADMIN],
                resource_name="police_registry:create_station",
            )
        except UnauthorizedAccessError:
            AuditService.log_unauthorized_access(current_user, "police_registry:create_station", db=db)
            raise

        target_db = db if db is not None else get_db()
        col = get_police_registry_col(target_db)
        try:
            col.update_one(
                {"station_id": station_data["station_id"]},
                {"$set": station_data},
                upsert=True,
            )
            return True
        except PyMongoError as err:
            logger.error("Failed to add station: %s", err)
            return False
