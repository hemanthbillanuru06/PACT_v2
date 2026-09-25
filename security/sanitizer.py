"""Secret and sensitive credential sanitization for AI payloads and logging."""
import re
from typing import Any, Dict, List, Union


# Regex patterns for sensitive credentials, connection strings, and secrets
MONGO_URI_PATTERN = re.compile(r"mongodb(\+srv)?:\/\/[^\s\"'<>]+", re.IGNORECASE)
BEARER_TOKEN_PATTERN = re.compile(r"Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*", re.IGNORECASE)
GEMINI_KEY_PATTERN = re.compile(r"AIza[0-9A-Za-z\-_]{35}")
GENERIC_API_KEY_PATTERN = re.compile(r"(?:api[_-]?key|access[_-]?token|secret[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?", re.IGNORECASE)
PASSWORD_ASSIGN_PATTERN = re.compile(r"(password|passwd|pwd|command_password)\s*[:=]\s*['\"]?[^\s\"',]+['\"]?", re.IGNORECASE)
BCRYPT_HASH_PATTERN = re.compile(r"\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}")
AUTH_HEADER_PATTERN = re.compile(r"(authorization|x-api-key)\s*[:=]\s*['\"][^\s\"']+['\"]", re.IGNORECASE)

SENSITIVE_KEY_NAMES = {
    "password",
    "password_hash",
    "secret",
    "api_key",
    "token",
    "access_token",
    "refresh_token",
    "jwt",
    "auth_token",
    "private_key",
    "command_password",
}


def sanitize_text(text: str) -> str:
    """Sanitize secrets, passwords, connection strings, and API keys from a text string."""
    if not isinstance(text, str):
        return text

    sanitized = MONO_URI = MONGO_URI_PATTERN.sub("[REDACTED_DB_CONNECTION]", text)
    sanitized = BEARER_TOKEN_PATTERN.sub("Bearer [REDACTED_TOKEN]", sanitized)
    sanitized = GEMINI_KEY_PATTERN.sub("[REDACTED_API_KEY]", sanitized)
    sanitized = BCRYPT_HASH_PATTERN.sub("[REDACTED_BCRYPT_HASH]", sanitized)
    sanitized = PASSWORD_ASSIGN_PATTERN.sub(r"\1: [REDACTED_PASSWORD]", sanitized)
    sanitized = GENERIC_API_KEY_PATTERN.sub("api_key: [REDACTED_KEY]", sanitized)
    sanitized = AUTH_HEADER_PATTERN.sub(r"\1: [REDACTED_HEADER]", sanitized)
    return sanitized


def sanitize_payload(data: Any) -> Any:
    """Recursively sanitize data structures before sending to AI models or audit logs.

    Removes or redacts any dictionary keys matching sensitive credential names
    and runs regex scrubbing on all nested string values.
    """
    if isinstance(data, dict):
        cleaned: Dict[str, Any] = {}
        for k, v in data.items():
            key_lower = str(k).lower().strip()
            if key_lower in SENSITIVE_KEY_NAMES:
                cleaned[k] = "[REDACTED_SECRET]"
            else:
                cleaned[k] = sanitize_payload(v)
        return cleaned
    elif isinstance(data, (list, tuple, set)):
        cleaned_list = [sanitize_payload(item) for item in data]
        return type(data)(cleaned_list) if not isinstance(data, (set, tuple)) else type(data)(cleaned_list)
    elif isinstance(data, str):
        return sanitize_text(data)
    else:
        return data
