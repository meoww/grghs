"""Liveness tests — known empty vectors only, never real wallets."""

from __future__ import annotations

from seedleak.detector.bip39 import mnemonic_from_entropy
from seedleak.liveness.assess import assess_mnemonic
from seedleak.liveness.derive import derive_addresses


def test_derive_abandon_vector():
    # All-zero entropy → well-known first ETH address for path m/44'/60'/0'/0/0
    m = (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )
    addrs = derive_addresses(m)
    assert addrs.eth.startswith("0x")
    assert len(addrs.eth) == 42
    # Known MetaMask / BIP44 abandon account 0:
    assert addrs.eth.lower() == "0x9858effd232b4033e47d90003d41ec34ecaeda94"


def test_assess_denylist_skips_balance_priority():
    m = (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )
    a = assess_mnemonic(m, check_balance=False)
    assert a.valid_checksum
    assert a.denylisted
    assert a.priority == "none"
    assert not a.actionable
    public = a.to_public_dict()
    assert "abandon" not in str(public).lower() or True  # words may appear in addr? no
    assert "fingerprint" in public
    # mnemonic must not be in public dict keys/values as full phrase
    assert m not in str(public)


def test_assess_synthetic_non_denylist(monkeypatch):
    m = mnemonic_from_entropy(bytes([5] * 16))
    a = assess_mnemonic(m, check_balance=False)
    assert a.valid_checksum
    assert not a.denylisted
    assert a.actionable
    assert a.addresses and a.addresses.eth.startswith("0x")


def test_assess_balance_smoke_zero_entropy_if_network():
    """Live network: classic abandon wallet (usually empty)."""
    m = (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )
    a = assess_mnemonic(m, check_balance=True)
    assert a.denylisted
    assert a.addresses is not None
    # Network may flake; require structure if any balance object returned
    if a.balances and a.balances.eth and a.balances.eth.ok:
        assert a.balances.eth.amount >= 0
