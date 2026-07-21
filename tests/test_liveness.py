"""Liveness tests — known empty vectors only, never real wallets."""

from __future__ import annotations

from seedleak.detector.bip39 import mnemonic_from_entropy
from seedleak.liveness.assess import assess_mnemonic
from seedleak.liveness.chains import CHAIN_SPECS, list_chain_ids
from seedleak.liveness.derive import DEFAULT_INDEXES, derive_addresses, parse_indexes


def test_chain_registry_nonempty():
    assert len(CHAIN_SPECS) >= 20
    ids = list_chain_ids()
    for required in ("eth", "btc_legacy", "btc_segwit", "tron", "sol", "bsc"):
        assert required in ids


def test_parse_indexes():
    assert parse_indexes("0-5") == [0, 1, 2, 3, 4, 5]
    assert parse_indexes("0,2,4") == [0, 2, 4]
    assert parse_indexes(None) == list(DEFAULT_INDEXES)


def test_derive_abandon_vector_multi():
    m = (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )
    w = derive_addresses(m, indexes=[0, 1])
    assert w.eth.lower() == "0x9858effd232b4033e47d90003d41ec34ecaeda94"
    assert w.btc_legacy.startswith("1")
    assert w.btc_segwit.startswith("bc1")
    assert w.get("tron")
    assert w.get("sol")
    # Different indexes → different ETH addresses
    eth0 = w.get("eth", 0)
    eth1 = w.get("eth", 1)
    assert eth0 and eth1 and eth0 != eth1
    assert len(w.entries) >= 30  # 27 chains × 2 indexes roughly


def test_assess_denylist():
    m = (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )
    a = assess_mnemonic(m, check_balance=False, indexes=[0])
    assert a.valid_checksum
    assert a.denylisted
    assert a.priority == "none"
    assert not a.actionable
    public = a.to_public_dict()
    assert m not in str(public)
    assert public["addresses"] and "eth" in public["addresses"]


def test_assess_synthetic_multi_index():
    m = mnemonic_from_entropy(bytes([5] * 16))
    a = assess_mnemonic(m, check_balance=False, indexes=[0, 1, 2])
    assert a.valid_checksum
    assert not a.denylisted
    assert a.actionable
    assert a.indexes == [0, 1, 2]
    assert a.chains_derived >= 15
    assert a.addresses and len(a.addresses.entries) >= 40


def test_tron_and_sol_have_token_specs():
    specs = {s.id: s for s in CHAIN_SPECS}
    assert any(t[0] == "USDT" for t in specs["tron"].tokens)
    assert any(t[0] == "USDC" for t in specs["sol"].tokens)
    assert len(specs["tron"].tokens) >= 5
    assert len(specs["sol"].tokens) >= 5


def test_assess_balance_smoke_structure():
    m = (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )
    a = assess_mnemonic(m, check_balance=True, indexes=[0])
    assert a.denylisted
    assert a.addresses is not None
    if a.balances:
        assert isinstance(a.balances.items, list)
