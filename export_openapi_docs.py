import json
import re
from pathlib import Path

SOURCE = Path("company-openapi.json")
OUTPUT = Path("company-openapi-sanitized.json")

SENSITIVE_KEYS = {
    "authorization",
    "api_key",
    "apikey",
    "api-key",
    "client_secret",
    "clientsecret",
    "password",
    "token",
    "access_token",
    "refresh_token",
    "private_key",
}

SECRET_PATTERNS = [
    re.compile(r"bearer\s+[a-z0-9._\-]+", re.IGNORECASE),
    re.compile(r"basic\s+[a-z0-9+/=]+", re.IGNORECASE),
]


def sanitize(value):
    if isinstance(value, dict):
        cleaned = {}

        for key, item in value.items():
            normalized_key = key.lower().replace("-", "_")

            if normalized_key in SENSITIVE_KEYS:
                cleaned[key] = "[REDACTED]"
            else:
                cleaned[key] = sanitize(item)

        return cleaned

    if isinstance(value, list):
        return [sanitize(item) for item in value]

    if isinstance(value, str):
        cleaned = value

        for pattern in SECRET_PATTERNS:
            cleaned = pattern.sub("[REDACTED]", cleaned)

        return cleaned

    return value


spec = json.loads(SOURCE.read_text(encoding="utf-8"))
sanitized = sanitize(spec)

OUTPUT.write_text(
    json.dumps(sanitized, indent=2),
    encoding="utf-8",
)

print(f"Saved sanitized schema to {OUTPUT}")
