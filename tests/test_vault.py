"""Vault encryption tests — synthetic funded path only."""

from __future__ import annotations

from pathlib import Path

from seedleak.detector.bip39 import Finding, mnemonic_from_entropy
from seedleak.pipeline import store_finding
from seedleak.storage.db import CaseStore
from seedleak.storage.vault import (
    decrypt_mnemonic,
    encrypt_mnemonic,
    should_store_secret,
)


def test_should_store_policy():
    assert should_store_secret(denylisted=False, has_funds=True) is True
    assert should_store_secret(denylisted=True, has_funds=True) is False
    assert should_store_secret(denylisted=False, has_funds=False) is False


def test_encrypt_roundtrip(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SEEDLEAK_HOME", str(tmp_path))
    m = mnemonic_from_entropy(bytes([8] * 16))
    token = encrypt_mnemonic(m)
    assert token != m
    assert decrypt_mnemonic(token) == m


def test_store_finding_vaults_only_when_funded(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SEEDLEAK_HOME", str(tmp_path))
    store = CaseStore(tmp_path / "cases.db")
    m = mnemonic_from_entropy(bytes([11] * 16))
    finding = Finding(
        words=tuple(m.split()),
        word_count=12,
        start_offset=0,
        end_offset=10,
        checksum_valid=True,
        is_denylisted=False,
        context_preview="…[REDACTED_MNEMONIC]…",
        language="english",
    )

    # Without balance check → no funds → no vault
    rec = store_finding(
        store,
        finding,
        source_type="file",
        source_path="/tmp/repo",
        file_path="wallet.txt",
        check_balance=False,
        store_secrets=True,
    )
    case = store.get(rec.case_id)
    assert case is not None
    assert case.secret_stored is False
    assert not case.mnemonic_enc

    # Force vault path by encrypting directly through upsert (unit-level)
    from seedleak.storage.vault import encrypt_mnemonic as enc

    token = enc(m)
    store.upsert_finding(
        fingerprint=rec.fingerprint,
        source_type="github",
        source_path="owner/repo",
        file_path="secret.env",
        word_count=12,
        context_preview="…[REDACTED_MNEMONIC]…",
        has_funds=True,
        mnemonic_enc=token,
        secret_stored=True,
        source_url="https://github.com/owner/repo/blob/main/secret.env",
        language="english",
        funded_summary="ETH=0.1",
        eth_address="0xabc",
    )
    vault = store.list_vault()
    assert any(v.secret_stored and v.source_url for v in vault)
    hit = next(v for v in vault if v.file_path == "secret.env")
    assert decrypt_mnemonic(hit.mnemonic_enc) == m
    assert hit.source_path == "owner/repo"
    assert "secret.env" in (hit.source_url or "")
