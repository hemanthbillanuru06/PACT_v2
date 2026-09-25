"""Security package exposing password management, lockout, RBAC, and file security."""
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
from security.file_security import (
    validate_evidence_path,
    save_evidence_file,
    read_evidence_file,
    sanitize_filename,
    compute_sha256,
    PathTraversalError,
    SecurityViolationError,
    ensure_storage_directories,
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
    "validate_evidence_path",
    "save_evidence_file",
    "read_evidence_file",
    "sanitize_filename",
    "compute_sha256",
    "PathTraversalError",
    "SecurityViolationError",
    "ensure_storage_directories",
]
