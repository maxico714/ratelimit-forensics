from __future__ import annotations

import re

REDACTED = "[REDACTED]"


class RedactionError(RuntimeError):
    """A secret pattern survived redaction; refuse to emit the document."""


_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"(?i)(authorization\s*:\s*)(bearer|basic|token|apikey)\s+[^\s]+"),
        r"\1\2 " + REDACTED,
    ),
    (
        re.compile(r"(?i)(x-api-key\s*:\s*)[^\s]+"),
        r"\1" + REDACTED,
    ),
    (
        re.compile(r"\bsk-[A-Za-z0-9_\-]{8,}\b"),
        REDACTED,
    ),
    (
        re.compile(r"\b(?:ghp|gho|ghu|ghs|github_pat)_[A-Za-z0-9_]{10,}\b"),
        REDACTED,
    ),
    (
        re.compile(
            r"(?i)(\b(?:api[_-]?key|access[_-]?token|secret|password)[\"']?\s*[:=]\s*[\"'])([^\"']+)([\"'])"
        ),
        r"\1" + REDACTED + r"\3",
    ),
    (
        re.compile(
            r"(?i)(\b(?:api[_-]?key|access[_-]?token|secret|password)\s*[:=]\s*)[^\s&,;\"']+"
        ),
        r"\1" + REDACTED,
    ),
)

_LEAK_CHECKS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bsk-[A-Za-z0-9_\-]{8,}\b"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|github_pat)_[A-Za-z0-9_]{10,}\b"),
    re.compile(r"(?i)authorization\s*:\s*(?:bearer|basic|token|apikey)\s+(?!\[REDACTED\])[^\s]+"),
    re.compile(r"(?i)x-api-key\s*:\s*(?!\[REDACTED\])[^\s]+"),
)


def redact(text: str) -> tuple[str, int]:
    """Replace credential-shaped values; return (clean_text, replacement_count)."""
    count = 0
    for pattern, replacement in _PATTERNS:
        text, hits = pattern.subn(replacement, text)
        count += hits
    return text, count


def assert_clean(text: str) -> None:
    """Raise RedactionError if a high-confidence credential pattern survived."""
    for pattern in _LEAK_CHECKS:
        match = pattern.search(text)
        if match:
            raise RedactionError(
                f"credential-shaped value survived redaction at offset {match.start()}"
            )
