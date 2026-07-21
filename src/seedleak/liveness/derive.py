"""Multi-chain HD address derivation from BIP39 (in-memory only)."""

from __future__ import annotations

from dataclasses import dataclass, field

from seedleak.liveness.chains import CHAIN_SPECS, ChainSpec, Family, resolve_bip_coin


@dataclass(frozen=True, slots=True)
class AddressEntry:
    chain_id: str
    label: str
    address: str
    path: str
    family: str


@dataclass
class DerivedWallet:
    """All derived public addresses for a mnemonic (index 0 defaults)."""

    entries: list[AddressEntry] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def by_id(self) -> dict[str, AddressEntry]:
        return {e.chain_id: e for e in self.entries}

    def get(self, chain_id: str) -> str | None:
        e = self.by_id().get(chain_id)
        return e.address if e else None

    # Back-compat helpers used by older code/tests
    @property
    def eth(self) -> str:
        return self.get("eth") or ""

    @property
    def btc_legacy(self) -> str:
        return self.get("btc_legacy") or ""

    @property
    def btc_segwit(self) -> str:
        return self.get("btc_segwit") or ""

    def to_dict(self) -> dict[str, str]:
        return {e.chain_id: e.address for e in self.entries}


# Alias for older imports
DerivedAddresses = DerivedWallet


def _derive_one(seed_bytes: bytes, spec: ChainSpec, index: int = 0) -> str:
    from bip_utils import Bip44, Bip44Changes, Bip84

    coin = resolve_bip_coin(spec.bip_coin, spec.family)

    if spec.family == Family.BIP84:
        ctx = (
            Bip84.FromSeed(seed_bytes, coin)
            .Purpose()
            .Coin()
            .Account(0)
            .Change(Bip44Changes.CHAIN_EXT)
            .AddressIndex(index)
        )
        return ctx.PublicKey().ToAddress()

    # BIP44 (and BIP44-style for most altcoins in bip_utils)
    bip = Bip44.FromSeed(seed_bytes, coin).Purpose().Coin().Account(0)

    # Some coins use different change/address layout; try standard first.
    try:
        ctx = bip.Change(Bip44Changes.CHAIN_EXT).AddressIndex(index)
        return ctx.PublicKey().ToAddress()
    except Exception:
        # Coins without change level (e.g. some ed25519)
        try:
            ctx = bip.AddressIndex(index)
            return ctx.PublicKey().ToAddress()
        except Exception:
            # Account-only
            return bip.PublicKey().ToAddress()


def derive_addresses(
    mnemonic: str,
    passphrase: str = "",
    *,
    chain_ids: list[str] | None = None,
    index: int = 0,
) -> DerivedWallet:
    """Derive public addresses for configured chains.

    Private key material never leaves bip-utils internals beyond this call.
    """
    try:
        from bip_utils import Bip39SeedGenerator
    except ImportError as e:
        raise RuntimeError(
            "Install bip-utils: pip install 'seedleak[liveness]'"
        ) from e

    seed_bytes = Bip39SeedGenerator(mnemonic).Generate(passphrase)
    wanted = set(chain_ids) if chain_ids else None
    wallet = DerivedWallet()

    # Deduplicate address derivation for same bip coin+path family where possible
    # (still iterate specs so labels/ids stay clear).
    for spec in CHAIN_SPECS:
        if wanted is not None and spec.id not in wanted:
            continue
        # Base uses OPTIMISM coin for key material but ETH-style path — same as eth addr.
        # Still derive separately so balance RPC can differ.
        try:
            addr = _derive_one(seed_bytes, spec, index=index)
            wallet.entries.append(
                AddressEntry(
                    chain_id=spec.id,
                    label=spec.label,
                    address=addr,
                    path=spec.path or "",
                    family=spec.family.value,
                )
            )
        except Exception as e:
            wallet.errors.append(f"{spec.id}: {e}")

    return wallet


def derive_addresses_multi_index(
    mnemonic: str,
    passphrase: str = "",
    *,
    indexes: list[int] | None = None,
    chain_ids: list[str] | None = None,
) -> dict[int, DerivedWallet]:
    """Derive for several address indexes (default 0 only)."""
    indexes = indexes if indexes is not None else [0]
    return {
        i: derive_addresses(mnemonic, passphrase, chain_ids=chain_ids, index=i)
        for i in indexes
    }
