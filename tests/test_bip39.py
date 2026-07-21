"""Tests for BIP39 detection — uses synthetic entropy, not real wallets."""

from __future__ import annotations

from pathlib import Path

from seedleak.detector.bip39 import (
    LANGUAGES,
    load_wordlist,
    mnemonic_from_entropy,
    scan_text,
    validate_checksum,
)
from seedleak.detector.denylist import DEFAULT_DENYLIST, load_denylist


def test_wordlist_loads_english():
    words, index = load_wordlist("english")
    assert len(words) == 2048
    assert words[0] == "abandon"
    assert "about" in index


def test_all_bundled_wordlists_load():
    for lang in LANGUAGES:
        words, index = load_wordlist(lang)
        assert len(words) == 2048
        assert len(index) == 2048


def test_known_vector_checksum():
    _, index = load_wordlist("english")
    words = (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    ).split()
    assert validate_checksum(words, index)


def test_invalid_checksum_rejected():
    _, index = load_wordlist("english")
    words = (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon"
    ).split()
    assert not validate_checksum(words, index)


def test_mnemonic_from_entropy_roundtrip():
    _, index = load_wordlist("english")
    ent = bytes(range(16))
    m = mnemonic_from_entropy(ent)
    assert len(m.split()) == 12
    assert validate_checksum(m.split(), index)


def test_scan_finds_valid_in_noise():
    ent = bytes([7] * 16)
    m = mnemonic_from_entropy(ent)
    text = f"config:\n  wallet_seed: {m}\n  other: true\n"
    denylist = load_denylist()
    findings = scan_text(text, denylist=denylist)
    alerts = [f for f in findings if f.is_alert]
    assert len(alerts) == 1
    assert alerts[0].word_count == 12
    assert alerts[0].language == "english"
    assert "[REDACTED_MNEMONIC]" in alerts[0].context_preview
    assert m not in alerts[0].context_preview


def test_denylist_suppresses_alert():
    m = (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )
    assert m in DEFAULT_DENYLIST
    text = f"demo seed: {m}"
    findings = scan_text(text, denylist=load_denylist())
    assert findings
    assert all(f.is_denylisted for f in findings)
    assert not any(f.is_alert for f in findings)


def test_random_english_not_flagged():
    text = (
        "the quick brown fox jumps over the lazy dog again today "
        "while people watch carefully and write notes"
    )
    findings = scan_text(text, denylist=load_denylist())
    assert findings == []


def test_scan_file(tmp_path: Path):
    ent = bytes([9, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
    m = mnemonic_from_entropy(ent)
    p = tmp_path / "leak.env"
    p.write_text(f"MNEMONIC={m}\n", encoding="utf-8")
    from seedleak.detector.bip39 import scan_file

    findings = scan_file(p, denylist=load_denylist())
    assert any(f.is_alert for f in findings)


def test_spanish_mnemonic_roundtrip():
    m = mnemonic_from_entropy(bytes([3] * 16), language="spanish")
    _, index = load_wordlist("spanish")
    assert validate_checksum(m.split(), index)
    text = f"frase: {m}"
    findings = scan_text(text, languages=["spanish"], denylist=set())
    assert any(f.is_alert and f.language == "spanish" for f in findings)
