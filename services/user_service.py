"""Officer and user administration service with RBAC enforcement."""
import logging
from typing import List, Dict, Any, Optional
from pymongo.database import Database
from pymongo.errors import PyMongoError

from config.settings import settings
from database.connection import get_db, get_users_col, get_officers_col, get_login_attempts_col
from security.rbac import enforce_role, UnauthorizedAccessError
from security.lockout import LockoutManager
from services.audit_service import AuditService

logger = logging.getLogger("pact.services.user")


class UserService:
    """Service for user and officer management with RBAC."""

    @staticmethod
    def get_users_list(current_user: Dict[str, Any], db: Optional[Database] = None) -> List[Dict[str, Any]]:
        """List user accounts with roles and lockout status. Allowed for ADMIN and SP."""
        try:
            enforce_role(
                current_user,
                allowed_roles=[settings.ROLE_ADMIN, settings.ROLE_SP],
                resource_name="users:list_all",
            )
        except UnauthorizedAccessError:
            AuditService.log_unauthorized_access(current_user, "users:list_all", db=db)
            raise

        target_db = db if db is not None else get_db()
        users_col = get_users_col(target_db)
        try:
            cursor = users_col.find(
                {},
                {"password_hash": 0}  # Never leak password hash
            ).sort("officer_id", 1)
            results = []
            for doc in cursor:
                doc["_id"] = str(doc["_id"])
                results.append(doc)
            return results
        except PyMongoError as err:
            logger.error("Failed to query users: %s", err)
            return []

    @staticmethod
    def get_officers_list(current_user: Dict[str, Any], db: Optional[Database] = None) -> List[Dict[str, Any]]:
        """List officer personnel directory. Allowed for ADMIN, SP, and SI."""
        try:
            enforce_role(
                current_user,
                allowed_roles=[settings.ROLE_ADMIN, settings.ROLE_SP, settings.ROLE_SI],
                resource_name="officers:list_directory",
            )
        except UnauthorizedAccessError:
            AuditService.log_unauthorized_access(current_user, "officers:list_directory", db=db)
            raise

        target_db = db if db is not None else get_db()
        officers_col = get_officers_col(target_db)
        try:
            cursor = officers_col.find({}, {"_id": 0}).sort("officer_id", 1)
            return list(cursor)
        except PyMongoError as err:
            logger.error("Failed to query officers directory: %s", err)
            return []

    @staticmethod
    def unlock_user_account(current_user: Dict[str, Any], target_officer_id: str, db: Optional[Database] = None) -> bool:
        """Unlock a locked account. STRICTLY restricted to ADMIN."""
        try:
            enforce_role(
                current_user,
                allowed_roles=[settings.ROLE_ADMIN],
                resource_name=f"users:unlock_account:{target_officer_id}",
            )
        except UnauthorizedAccessError:
            AuditService.log_unauthorized_access(current_user, f"users:unlock_account:{target_officer_id}", db=db)
            raise

        target_db = db if db is not None else get_db()
        users_col = get_users_col(target_db)
        target_user = users_col.find_one({"officer_id": target_officer_id.upper()})
        if not target_user:
            return False

        success = LockoutManager.unlock_account(target_user["_id"], db=target_db)
        if success:
            AuditService.log_event(
                event_type="ACCOUNT_UNLOCKED",
                user_id=str(current_user.get("user_id")),
                officer_id=current_user.get("officer_id"),
                role=current_user.get("role"),
                details={"unlocked_officer_id": target_officer_id},
                status="SUCCESS",
                db=target_db,
            )
        return success

    @staticmethod
    def get_security_telemetry(current_user: Dict[str, Any], db: Optional[Database] = None) -> Dict[str, Any]:
        """Aggregate security status metrics. Allowed for ADMIN and SP."""
        try:
            enforce_role(
                current_user,
                allowed_roles=[settings.ROLE_ADMIN, settings.ROLE_SP],
                resource_name="security:view_telemetry",
            )
        except UnauthorizedAccessError:
            AuditService.log_unauthorized_access(current_user, "security:view_telemetry", db=db)
            raise

        target_db = db if db is not None else get_db()
        users_col = get_users_col(target_db)
        attempts_col = get_login_attempts_col(target_db)

        try:
            total_users = users_col.count_documents({})
            locked_users = users_col.count_documents({"is_locked": True})
            recent_attempts = attempts_col.count_documents({})
            failed_attempts = attempts_col.count_documents({"success": False})

            return {
                "total_users": total_users,
                "locked_users": locked_users,
                "total_login_attempts": recent_attempts,
                "failed_login_attempts": failed_attempts,
            }
        except PyMongoError as err:
            logger.error("Failed to aggregate security telemetry: %s", err)
            return {
                "total_users": 0,
                "locked_users": 0,
                "total_login_attempts": 0,
                "failed_login_attempts": 0,
            }
