from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

# Reused scanner discipline (SPEC §4.4): no plan, prompt, bundle, fact, or notification may
# surface a secret value. Patterns are deliberately conservative — a false positive only
# costs a redacted field and a recorded hash, which is recoverable by correlation.

_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "aws_access_key",
        re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b"),
    ),
    (
        "private_key",
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?"
            r"-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.MULTILINE,
        ),
    ),
    (
        "bearer_token",
        re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{12,}"),
    ),
    (
        "assigned_secret",
        re.compile(
            r"(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)\b\s*"
            r"[=:]\s*\S+"
        ),
    ),
)

PLACEHOLDER = "[REDACTED:{kind}]"


@dataclass(frozen=True)
class Redaction:
    kind: str
    sha256: str  # of the removed text, so it can be correlated without disclosure


def redact_text(text: str) -> tuple[str, list[Redaction]]:
    """Replace secret-shaped substrings with a placeholder and return what changed."""
    redactions: list[Redaction] = []
    for kind, pattern in _PATTERNS:

        def replace(match: re.Match[str], kind: str = kind) -> str:
            redactions.append(Redaction(kind, hashlib.sha256(match.group(0).encode()).hexdigest()))
            return PLACEHOLDER.format(kind=kind)

        text = pattern.sub(replace, text)
    return text, redactions


def redact(value: object) -> tuple[object, list[Redaction]]:
    """Recursively redact strings in a JSON-shaped value."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        redactions: list[Redaction] = []
        result = {}
        for key, item in value.items():
            clean, changes = redact(item)
            result[key] = clean
            redactions.extend(changes)
        return result, redactions
    if isinstance(value, list):
        redactions = []
        result = []
        for item in value:
            clean, changes = redact(item)
            result.append(clean)
            redactions.extend(changes)
        return result, redactions
    if isinstance(value, tuple):
        clean, changes = redact(list(value))
        return tuple(clean), changes
    return value, []
