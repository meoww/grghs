"""HD address derivation from BIP39 (in-memory only).

Read-only: produces public addresses. Never logs or returns private keys
to callers that persist data — private key material stays local to this module
and is discarded when the function returns.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DerivedAddresses:
    """Public addresses for common paths (account 0 / index 0)."""

    eth: str  # EIP-55 checksum
    btc_legacy: str  # BIP44 m/44'/0'/0'/0/0
    btc_segwit: str  # BIP84 m/84'/0'/0'/0/0 native
    path_eth: str = "m/44'/60'/0'/0/0"
    path_btc_legacy: str = "m/44'/0'/0'/0/0"
    path_btc_segwit: str = "m/84'/0'/0'/0/0"


def derive_addresses(mnemonic: str, passphrase: str = "") -> DerivedAddresses:
    """Derive standard first-account addresses from a BIP39 mnemonic."""
    try:
        from bip_utils import (
            Bip39SeedGenerator,
            Bip44,
            Bip44Changes,
            Bip44Coins,
            Bip84,
            Bip84Coins,
        )
    except ImportError as e:
        raise RuntimeError(
            "Install bip-utils: pip install 'seedleak[liveness]'"
        ) from e

    seed_bytes = Bip39SeedGenerator(mnemonic).Generate(passphrase)

    eth_ctx = (
        Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM)
        .Purpose()
        .Coin()
        .Account(0)
        .Change(Bip44Changes.CHAIN_EXT)
        .AddressIndex(0)
    )
    btc44 = (
        Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
        .Purpose()
        .Coin()
        .Account(0)
        .Change(Bip44Changes.CHAIN_EXT)
        .AddressIndex(0)
    )
    btc84 = (
        Bip84.FromSeed(seed_bytes, Bip84Coins.BITCOIN)
        .Purpose()
        .Coin()
        .Account(0)
        .Change(Bip44Changes.CHAIN_EXT)
        .AddressIndex(0)
    )

    return DerivedAddresses(
        eth=eth_ctx.PublicKey().ToAddress(),
        btc_legacy=btc44.PublicKey().ToAddress(),
        btc_segwit=btc84.PublicKey().ToAddress(),
    )
