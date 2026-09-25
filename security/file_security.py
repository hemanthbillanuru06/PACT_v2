"""File security and strict path traversal protection for evidence management."""
import hashlib
import mimetypes
import os
import re
import uuid
from typing import Tuple, Optional

from config.settings import settings


class SecurityViolationError(PermissionError):
    """Raised when an unauthorized or malicious path operation is attempted."""
    pass


class PathTraversalError(SecurityViolationError):
    """Raised when path traversal sequences or unauthorized directory escapes are detected."""
    pass


def ensure_storage_directories() -> None:
    """Ensure evidence and reports directories exist."""
    os.makedirs(settings.EVIDENCE_STORAGE_DIR, exist_ok=True)
    os.makedirs(settings.REPORTS_STORAGE_DIR, exist_ok=True)


def sanitize_filename(filename: str) -> str:
    """Sanitize original filename to strip directory traversal sequences and invalid characters."""
    if not filename:
        return "unnamed_evidence"

    # Check for null byte injection
    if "\x00" in filename:
        raise PathTraversalError("Null byte injection detected in filename.")

    # Explicit check for traversal indicators in raw filename
    if ".." in filename or filename.startswith("/") or filename.startswith("\\"):
        raise PathTraversalError(f"Directory traversal sequence detected in filename: '{filename}'")

    # Strip any directory path components (both forward and back slashes)
    cleaned = os.path.basename(filename.replace("\\", "/"))

    # Explicit check for traversal indicators
    if ".." in cleaned or not cleaned:
        raise PathTraversalError(f"Directory traversal sequence '..' detected in filename: '{filename}'")

    # Keep only alphanumeric, dots, underscores, dashes
    sanitized = re.sub(r"[^a-zA-Z0-9._-]", "_", cleaned)
    if not sanitized or sanitized in [".", ".."]:
        return f"file_{uuid.uuid4().hex[:8]}"

    return sanitized


def validate_evidence_path(target_path: str, base_dir: Optional[str] = None) -> str:
    """Strictly validate that a target filepath resides strictly within the designated storage directory.

    Rejects directory traversal, relative paths escaping root, and symlink escapes.
    Returns canonical absolute path.
    """
    if not target_path:
        raise PathTraversalError("Target path cannot be empty.")

    if "\x00" in target_path:
        raise PathTraversalError("Null byte detected in path.")

    storage_root = os.path.realpath(base_dir or settings.EVIDENCE_STORAGE_DIR)

    # If target_path is relative, anchor it to storage_root
    if not os.path.isabs(target_path):
        resolved_path = os.path.realpath(os.path.join(storage_root, target_path))
    else:
        resolved_path = os.path.realpath(target_path)

    # Check commonpath to ensure resolved_path is strictly within storage_root
    try:
        common = os.path.commonpath([storage_root, resolved_path])
    except ValueError as err:
        raise PathTraversalError(f"Path traversal detected across drives: {err}") from err

    if common != storage_root or resolved_path == storage_root:
        raise PathTraversalError(
            f"Path traversal detected: Target '{target_path}' resolves outside allowed directory '{storage_root}'."
        )

    return resolved_path


def compute_sha256(data: bytes) -> str:
    """Calculate SHA-256 hash of byte content."""
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest()


def detect_mime_type(filename: str, sample_bytes: Optional[bytes] = None) -> str:
    """Determine MIME type based on filename extension and content inspection."""
    mime, _ = mimetypes.guess_type(filename)
    if mime:
        return mime
    if sample_bytes and sample_bytes.startswith(b"%PDF"):
        return "application/pdf"
    if sample_bytes and sample_bytes.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if sample_bytes and sample_bytes.startswith(b"\x89PNG"):
        return "image/png"
    return "application/octet-stream"


def save_evidence_file(
    content: Optional[bytes] = None,
    original_filename: str = "",
    case_id: str = "",
    base_dir: Optional[str] = None,
    file_bytes: Optional[bytes] = None,
) -> Tuple[str, str, str, str, int]:
    """Securely save evidence file content with path traversal verification.

    Returns:
        (stored_relative_filename, stored_absolute_path, sha256_hash, mime_type, file_size_bytes)
    """
    actual_content = content if content is not None else (file_bytes or b"")
    target_base = base_dir or settings.EVIDENCE_STORAGE_DIR
    os.makedirs(target_base, exist_ok=True)

    # Sanitize and validate filename (raises PathTraversalError on traversal attempts)
    clean_name = sanitize_filename(original_filename)
    file_id = uuid.uuid4().hex[:12]
    safe_case = sanitize_filename(case_id).replace(".", "_")
    stored_filename = f"{safe_case}_{file_id}_{clean_name}"

    # Validate destination path
    dest_path = validate_evidence_path(stored_filename, base_dir=target_base)

    # Write file
    with open(dest_path, "wb") as f:
        f.write(actual_content)

    file_size = len(actual_content)
    sha256_hash = compute_sha256(actual_content)
    mime_type = detect_mime_type(original_filename, actual_content)

    return stored_filename, dest_path, sha256_hash, mime_type, file_size


def read_evidence_file(stored_filename_or_path: str, base_dir: Optional[str] = None) -> bytes:
    """Read evidence file with mandatory path traversal validation."""
    validated_path = validate_evidence_path(stored_filename_or_path, base_dir=base_dir)
    if not os.path.exists(validated_path):
        raise FileNotFoundError(f"Evidence file not found: {stored_filename_or_path}")

    with open(validated_path, "rb") as f:
        return f.read()
