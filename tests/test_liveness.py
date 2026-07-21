"""Liveness tests — known empty vectors only, never real wallets."""

from __future__ import annotations

from seedleak.detector.bip39 import mnemonic_from_entropy
from seedleak.liveness.assess import assess_mnemonic
from seedleak.liveness.chains import CHAIN_SPECS, list_chain_ids
from seedleak.liveness.derive import derive_addresses


def test_chain_registry_nonempty():
    assert len(CHAIN_SPECS) >= 20
    ids = list_chain_ids()
    for required in ("eth", "btc_legacy", "btc_segwit", "tron", "sol", "bsc"):
        assert required in ids


def test_derive_abandon_vector_multi():
    m = (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )
    w = derive_addresses(m)
    assert w.eth.lower() == "0x9858effd232b4033e47d90003d41ec34ecaeda94"
    assert w.btc_legacy.startswith("1")
    assert w.btc_segwit.startswith("bc1")
    assert w.get("tron")
    assert w.get("sol")
    assert len(w.entries) >= 15


def test_assess_denylist():
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
    assert m not in str(public)
    assert public["addresses"] and "eth" in public["addresses"]


def test_assess_synthetic_non_denylist():
    m = mnemonic_from_entropy(bytes([5] * 16))
    a = assess_mnemonic(m, check_balance=False)
    assert a.valid_checksum
    assert not a.denylisted
    assert a.actionable
    assert a.chains_derived >= 15
    assert a.addresses and a.addresses.eth.startswith("0x")


def test_assess_balance_smoke_structure():
    m = (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )
    a = assess_mnemonic(m, check_balance=True)
    assert a.denylisted
    assert a.addresses is not None
    if a.balances:
        assert isinstance(a.balances.items, list)
