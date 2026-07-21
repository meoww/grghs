"""HMAC fingerprints — store proof of detection without plaintext seeds."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from pathlib import Path


def default_secret_path() -> Path:
    base = Path(os.environ.get("SEEDLEAK_HOME", Path.home() / ".seedleak"))
    return base / "hmac_secret"


def load_or_create_secret(path: Path | None = None) -> bytes:
    """Load HMAC key from disk, or generate a new 32-byte secret."""
    p = path or default_secret_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.is_file():
        data = p.read_bytes()
        if len(data) < 16:
            raise ValueError(f"HMAC secret at {p} is too short")
        return data
    secret = secrets.token_bytes(32)
    # Restrictive permissions where supported.
    p.write_bytes(secret)
    try:
        p.chmod(0o600)
    except OSError:
        pass
    return secret


def fingerprint(normalized_mnemonic: str, secret: bytes) -> str:
    """Return hex HMAC-SHA256 of the normalized mnemonic."""
    return hmac.new(
        secret,
        normalized_mnemonic.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def content_hash(text: str) -> str:
    """Non-secret SHA256 of arbitrary text (for file content dedup)."""
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
