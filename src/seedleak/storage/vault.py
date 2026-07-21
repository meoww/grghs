"""Encrypted at-rest storage for high-value findings (funded, non-test mnemonics).

Only used when:
  - BIP39 checksum valid
  - NOT on denylist (not a known test vector)
  - on-chain balance > 0 on at least one derived address

Plaintext mnemonics are encrypted with a local Fernet key (SEEDLEAK_HOME/vault.key).
Never include decrypted secrets in GitHub issues or public logs.
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
from pathlib import Path


def default_vault_key_path() -> Path:
    base = Path(os.environ.get("SEEDLEAK_HOME", Path.home() / ".seedleak"))
    return base / "vault.key"


def load_or_create_vault_key(path: Path | None = None) -> bytes:
    """Load 32-byte vault key, or generate one (mode 600)."""
    p = path or default_vault_key_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.is_file():
        key = p.read_bytes()
        if len(key) < 32:
            raise ValueError(f"Vault key at {p} is too short")
        return key[:32]
    key = secrets.token_bytes(32)
    p.write_bytes(key)
    try:
        p.chmod(0o600)
    except OSError:
        pass
    return key


def _fernet(key: bytes | None = None):
    try:
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    except ImportError as e:
        raise RuntimeError(
            "Install cryptography: pip install cryptography"
        ) from e

    raw = key or load_or_create_vault_key()
    # Derive a url-safe Fernet key from the raw 32 bytes
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"seedleak-vault-v1",
        info=b"mnemonic-vault",
    ).derive(raw)
    fkey = base64.urlsafe_b64encode(derived)
    return Fernet(fkey)


def encrypt_mnemonic(mnemonic: str, key: bytes | None = None) -> str:
    """Return Fernet token (ascii str) for the normalized mnemonic."""
    token = _fernet(key).encrypt(mnemonic.strip().encode("utf-8"))
    return token.decode("ascii")


def decrypt_mnemonic(token: str, key: bytes | None = None) -> str:
    """Decrypt a Fernet token back to mnemonic text."""
    plain = _fernet(key).decrypt(token.encode("ascii"))
    return plain.decode("utf-8")


def should_store_secret(
    *,
    denylisted: bool,
    has_funds: bool,
    valid_checksum: bool = True,
) -> bool:
    """Policy: store only valid, non-test mnemonics with positive balance."""
    return bool(valid_checksum and (not denylisted) and has_funds)


def fingerprint_hint(mnemonic: str) -> str:
    """Short non-reversible hint for UI (not for security)."""
    return hashlib.sha256(mnemonic.encode()).hexdigest()[:12]
