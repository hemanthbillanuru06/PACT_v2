"""Role-Based Access Control (RBAC) enforcement and permissions for PACT."""
import functools
import logging
from typing import Dict, List, Optional, Set, Callable, Any, Union, Tuple
from config.settings import settings

logger = logging.getLogger("pact.security.rbac")


class UnauthorizedAccessError(PermissionError):
    """Raised when a user attempts an action forbidden by their assigned role."""
    def __init__(self, message: str, user_id: Optional[str] = None, role: Optional[str] = None, resource: Optional[str] = None):
        super().__init__(message)
        self.user_id = user_id
        self.role = role
        self.resource = resource


# Role Permissions Matrix
ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    settings.ROLE_ADMIN: {
        "admin:manage_users",
        "admin:system_settings",
        "admin:view_telemetry",
        "audit:view_all",
        "registry:manage_stations",
        "registry:view_stations",
        "officers:manage_personnel",
        "officers:view_personnel",
        "cases:view_all",
        "cases:manage_all",
        "cases:create_fir",
        "firs:create",
        "firs:view",
        "sensitive_intel:access",
    },
    settings.ROLE_SP: {
        "audit:view_all",
        "registry:view_stations",
        "officers:view_personnel",
        "cases:view_all",
        "cases:department_oversight",
        "cases:create_fir",
        "firs:create",
        "firs:view",
        "sensitive_intel:access",
        "reports:executive_summary",
    },
    settings.ROLE_SI: {
        "registry:view_stations",
        "officers:view_station_personnel",
        "cases:station_view",
        "cases:assign_investigator",
        "cases:review_case",
        "cases:create_fir",
        "firs:create",
        "firs:view",
        "reports:station_summary",
    },
    settings.ROLE_INVESTIGATING_OFFICER: {
        "registry:view_stations",
        "cases:assigned_view",
        "cases:case_diary_write",
        "cases:evidence_catalog",
        "cases:create_fir",
        "firs:create",
        "firs:view",
        "reports:investigation_log",
    },
    settings.ROLE_CONSTABLE: {
        "registry:view_stations",
        "patrol:beat_report_write",
        "cases:view_basic",
        "cases:create_fir",
        "firs:create",
        "firs:view",
    },
}


def get_role_permissions(role: str) -> Set[str]:
    """Retrieve the set of allowed permissions for a given role."""
    return ROLE_PERMISSIONS.get(role, set())


def has_permission(user_role: str, permission: str) -> bool:
    """Check if a given role possesses a specific permission string."""
    permissions = get_role_permissions(user_role)
    return permission in permissions


def enforce_role(user: Optional[Any], allowed_roles: Union[List[str], Tuple[str, ...], Set[str]], resource_name: str = "resource") -> None:
    """Central backend enforcement function.

    Validates that user has one of the allowed_roles.
    Raises UnauthorizedAccessError if check fails.
    """
    if not user:
        logger.warning("Unauthenticated access attempt on %s", resource_name)
        raise UnauthorizedAccessError(
            f"Authentication required to access {resource_name}.",
            resource=resource_name
        )

    user_role = user.get("role") if hasattr(user, "get") else getattr(user, "role", None)
    user_id = str(user.get("_id", user.get("user_id", "unknown"))) if hasattr(user, "get") else str(getattr(user, "user_id", getattr(user, "_id", "unknown")))
    officer_id = user.get("officer_id", "unknown") if hasattr(user, "get") else getattr(user, "officer_id", "unknown")

    if user_role not in allowed_roles:
        logger.warning(
            "Access DENIED for user %s (role: %s, officer: %s) to %s. Allowed: %s",
            user_id, user_role, officer_id, resource_name, allowed_roles
        )
        raise UnauthorizedAccessError(
            f"Unauthorized: Role '{user_role}' does not have access to {resource_name}. Required roles: {list(allowed_roles)}.",
            user_id=user_id,
            role=user_role,
            resource=resource_name
        )


def require_role(allowed_roles: Union[List[str], Tuple[str, ...], Set[str]], resource_name: Optional[str] = None):
    """Centralized decorator to enforce RBAC on service functions."""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Extract user from kwargs or args
            user = kwargs.get("current_user") or kwargs.get("user") or kwargs.get("session")
            if user is None and args:
                for arg in args:
                    if isinstance(arg, dict) and "role" in arg:
                        user = arg
                        break
                    elif hasattr(arg, "role"):
                        user = arg
                        break

            target_resource = resource_name or func.__name__
            enforce_role(user, allowed_roles, resource_name=target_resource)
            return func(*args, **kwargs)
        return wrapper
    return decorator
