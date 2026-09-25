"""Password security, policy validation, and bcrypt hashing for PACT."""
import re
from typing import Tuple, List
import bcrypt

from config.settings import settings


class PasswordPolicyError(ValueError):
    """Raised when a password fails the complexity or length policy."""
    pass


def validate_password_policy(password: str) -> Tuple[bool, List[str]]:
    """Validate password against strict police intelligence security policy:
    - Minimum length of 12 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    errors: List[str] = []

    if not password or len(password) < settings.PASSWORD_MIN_LENGTH:
        errors.append(f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters long.")

    if not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least one uppercase letter (A-Z).")

    if not re.search(r"[a-z]", password):
        errors.append("Password must contain at least one lowercase letter (a-z).")

    if not re.search(r"[0-9]", password):
        errors.append("Password must contain at least one digit (0-9).")

    # Special characters: punctuation and symbols
    if not re.search(r'[!@#$%^&*(),.?":{}|<>\-_+=\[\]\\/~`\';]', password):
        errors.append("Password must contain at least one special character (e.g. !@#$%^&*).")

    is_valid = len(errors) == 0
    return is_valid, errors


def enforce_password_policy(password: str) -> None:
    """Validate password, raising PasswordPolicyError if requirements are not met."""
    is_valid, errors = validate_password_policy(password)
    if not is_valid:
        raise PasswordPolicyError(" ".join(errors))


def hash_password(password: str) -> str:
    """Enforce policy and return bcrypt hash string."""
    enforce_password_policy(password)
    salt = bcrypt.gensalt(rounds=12)
    hashed_bytes = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed_bytes.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Safely verify a plaintext password against a stored bcrypt hash."""
    if not plain_password or not hashed_password:
        return False
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8")
        )
    except (ValueError, TypeError):
        return False
