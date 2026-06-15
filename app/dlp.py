"""
DLP (Data Loss Prevention) scanner.
Scans text-extractable file content for sensitive data patterns.
Returns a list of findings: [{"type": "private_key", "count": 1}, ...]
Never raises. Returns [] for binary or non-text file types.
"""

import re
import logging
from pathlib import Path

log = logging.getLogger(__name__)

# Only scan formats where regex on raw text is meaningful
TEXT_EXTENSIONS = {
    "txt", "csv", "json", "jsonl", "yaml", "yml", "toml", "ini", "cfg",
    "conf", "env", "py", "js", "ts", "sh", "bash", "rb", "go", "java",
    "php", "log", "md", "xml", "html", "htm", "sql", "r",
    "pem", "crt", "key", "pub",
}

# Scan at most this many bytes — large text files are truncated, not skipped
_MAX_SCAN_BYTES = 512 * 1024


# ── validators ────────────────────────────────────────────────────────────────

def _luhn(s: str) -> bool:
    digits = re.sub(r"[^0-9]", "", s)
    if not (13 <= len(digits) <= 19):
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        n = int(d)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


_TW_ID_WEIGHTS = [1, 9, 8, 7, 6, 5, 4, 3, 2, 1, 1]
_TW_ID_MAP = {
    "A": 10, "B": 11, "C": 12, "D": 13, "E": 14, "F": 15, "G": 16,
    "H": 17, "I": 34, "J": 18, "K": 19, "L": 20, "M": 21, "N": 22,
    "O": 35, "P": 23, "Q": 24, "R": 25, "S": 26, "T": 27, "U": 28,
    "V": 29, "W": 32, "X": 30, "Y": 31, "Z": 33,
}


def _taiwan_id(s: str) -> bool:
    if not re.fullmatch(r"[A-Z][12]\d{8}", s):
        return False
    val = _TW_ID_MAP.get(s[0])
    if val is None:
        return False
    digits = [val // 10, val % 10] + [int(c) for c in s[1:]]
    return sum(d * w for d, w in zip(digits, _TW_ID_WEIGHTS)) % 10 == 0


# Common non-secret values assigned to password-like keys — discard these to
# cut false positives from code/config/docs.
_PASSWORD_PLACEHOLDERS = {
    "none", "null", "nil", "true", "false", "required", "optional",
    "changeme", "password", "passwd", "secret", "your_password",
    "yourpassword", "xxxxxx", "example", "redacted", "todo", "test",
    "${password}", "{{password}}", "<password>", "***",
}


def _password_val(s: str) -> bool:
    """Reject obvious placeholders / template vars assigned to password keys."""
    low = s.strip().lower()
    if low in _PASSWORD_PLACEHOLDERS:
        return False
    if low.startswith(("$", "{", "<", "%")) or low.endswith(("}", ">")):
        return False  # ${VAR}, {{var}}, <placeholder>, %ENV%
    return True


# ── pattern registry ──────────────────────────────────────────────────────────
# Each entry: (finding_type, compiled_regex, optional_validator)
# Validator receives the full match string; return False to discard.

_PATTERNS: list[tuple[str, re.Pattern, object]] = [
    # PEM private keys — near-zero false positives
    (
        "private_key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        None,
    ),
    # AWS access key ID
    (
        "aws_key",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        None,
    ),
    # GitHub PAT (classic + fine-grained)
    (
        "github_token",
        re.compile(r"\bghp_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{82}\b"),
        None,
    ),
    # Generic Bearer / API key assignment in config files
    (
        "api_credential",
        re.compile(
            r"(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token|bearer)\s*[=:]\s*[\"']?([A-Za-z0-9_\-]{24,})[\"']?"
        ),
        None,
    ),
    # Plain password assignment (password= / passwd= / pwd=)
    # \b around the key avoids matching password_field / my_pwd_hint;
    # value is a single token (no spaces) of 8+ chars; placeholders filtered.
    (
        "plaintext_password",
        re.compile(r"(?i)\b(?:password|passwd|pwd)\b\s*[=:]\s*[\"']?([^\s\"']{8,64})[\"']?"),
        _password_val,
    ),
    # JWT (three base64url segments)
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
        None,
    ),
    # Credit card number — Luhn validated to cut false positives
    (
        "credit_card",
        re.compile(r"\b(?:\d[ -]?){13,18}\d\b"),
        _luhn,
    ),
    # Taiwan National ID — checksum validated
    (
        "taiwan_id",
        re.compile(r"\b[A-Z][12]\d{8}\b"),
        _taiwan_id,
    ),
]


# ── public API ────────────────────────────────────────────────────────────────

def scan(data: bytes, filename: str) -> list[dict]:
    """
    Return a list of DLP findings for text-extractable file types.
    Each finding: {"type": str, "count": int}
    Returns [] when the file type is not scannable or content is binary.
    """
    ext = Path(filename).suffix.lower().lstrip(".")
    if ext not in TEXT_EXTENSIONS:
        return []

    try:
        text = data[:_MAX_SCAN_BYTES].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        try:
            text = data[:_MAX_SCAN_BYTES].decode("latin-1")
        except Exception:
            log.debug("dlp: cannot decode %s as text, skipping", filename)
            return []

    findings: dict[str, int] = {}
    for finding_type, regex, validator in _PATTERNS:
        matches = regex.findall(text)
        if validator:
            # findall returns strings or tuples depending on groups
            matches = [
                (m if isinstance(m, str) else m[0])
                for m in matches
                if validator(m if isinstance(m, str) else m[0])
            ]
        if matches:
            findings[finding_type] = len(matches)
            log.info("dlp: %s — found %d × %s", filename, len(matches), finding_type)

    return [{"type": t, "count": c} for t, c in findings.items()]
