"""Security package exposing password management, lockout, and RBAC."""
from security.passwords import (
    hash_password,
    verify_password,
    validate_password_policy,
    enforce_password_policy,
    PasswordPolicyError,
)
from security.lockout import LockoutManager, AccountLockedError
from security.rbac import (
    enforce_role,
    require_role,
    UnauthorizedAccessError,
    has_permission,
    get_role_permissions,
    ROLE_PERMISSIONS,
)

__all__ = [
    "hash_password",
    "verify_password",
    "validate_password_policy",
    "enforce_password_policy",
    "PasswordPolicyError",
    "LockoutManager",
    "AccountLockedError",
    "enforce_role",
    "require_role",
    "UnauthorizedAccessError",
    "has_permission",
    "get_role_permissions",
    "ROLE_PERMISSIONS",
]
