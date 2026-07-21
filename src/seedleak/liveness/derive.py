"""Multi-chain HD address derivation from BIP39 (in-memory only)."""

from __future__ import annotations

from dataclasses import dataclass, field

from seedleak.liveness.chains import CHAIN_SPECS, ChainSpec, Family, resolve_bip_coin

# Default HD address indexes scanned for exposure severity.
DEFAULT_INDEXES: tuple[int, ...] = (0, 1, 2, 3, 4, 5)


@dataclass(frozen=True, slots=True)
class AddressEntry:
    chain_id: str
    label: str
    address: str
    path: str
    family: str
    index: int = 0

    @property
    def key(self) -> str:
        """Unique key: chain_id or chain_id#N for N>0."""
        return self.chain_id if self.index == 0 else f"{self.chain_id}#{self.index}"


@dataclass
class DerivedWallet:
    """All derived public addresses for a mnemonic across indexes."""

    entries: list[AddressEntry] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    indexes: list[int] = field(default_factory=lambda: [0])

    def by_key(self) -> dict[str, AddressEntry]:
        return {e.key: e for e in self.entries}

    def by_id(self) -> dict[str, AddressEntry]:
        """Index-0 entries only (back-compat)."""
        return {e.chain_id: e for e in self.entries if e.index == 0}

    def get(self, chain_id: str, index: int = 0) -> str | None:
        key = chain_id if index == 0 else f"{chain_id}#{index}"
        e = self.by_key().get(key)
        return e.address if e else None

    def entries_for_index(self, index: int) -> list[AddressEntry]:
        return [e for e in self.entries if e.index == index]

    # Back-compat helpers (index 0)
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
        """Map key → address (includes #N for non-zero indexes)."""
        return {e.key: e.address for e in self.entries}

    def to_nested_dict(self) -> dict[str, dict[str, str]]:
        """{index: {chain_id: address}}."""
        out: dict[str, dict[str, str]] = {}
        for e in self.entries:
            out.setdefault(str(e.index), {})[e.chain_id] = e.address
        return out


DerivedAddresses = DerivedWallet


def _path_with_index(path: str, index: int) -> str:
    if not path:
        return f"index={index}"
    if path.endswith("/0"):
        return path[: -len("/0")] + f"/{index}"
    if path.endswith("/0'"):
        return path[: -len("/0'")] + f"/{index}'"
    return f"{path}@{index}"


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

    bip = Bip44.FromSeed(seed_bytes, coin).Purpose().Coin().Account(0)

    try:
        ctx = bip.Change(Bip44Changes.CHAIN_EXT).AddressIndex(index)
        return ctx.PublicKey().ToAddress()
    except Exception:
        try:
            ctx = bip.AddressIndex(index)
            return ctx.PublicKey().ToAddress()
        except Exception:
            # Account-only coins ignore address index
            return bip.PublicKey().ToAddress()


def derive_addresses(
    mnemonic: str,
    passphrase: str = "",
    *,
    chain_ids: list[str] | None = None,
    index: int = 0,
    indexes: list[int] | None = None,
) -> DerivedWallet:
    """Derive public addresses for configured chains.

    Pass either a single ``index`` or ``indexes`` list (default: [0]).
    Private key material never leaves bip-utils internals beyond this call.
    """
    try:
        from bip_utils import Bip39SeedGenerator
    except ImportError as e:
        raise RuntimeError(
            "Install bip-utils: pip install 'seedleak[liveness]'"
        ) from e

    if indexes is None:
        indexes = [index]

    # Deduplicate and sort
    idx_list = sorted({int(i) for i in indexes if int(i) >= 0})
    if not idx_list:
        idx_list = [0]

    seed_bytes = Bip39SeedGenerator(mnemonic).Generate(passphrase)
    wanted = set(chain_ids) if chain_ids else None
    wallet = DerivedWallet(indexes=idx_list)

    for idx in idx_list:
        for spec in CHAIN_SPECS:
            if wanted is not None and spec.id not in wanted:
                continue
            try:
                addr = _derive_one(seed_bytes, spec, index=idx)
                wallet.entries.append(
                    AddressEntry(
                        chain_id=spec.id,
                        label=spec.label,
                        address=addr,
                        path=_path_with_index(spec.path, idx),
                        family=spec.family.value,
                        index=idx,
                    )
                )
            except Exception as e:
                wallet.errors.append(f"{spec.id}#{idx}: {e}")

    return wallet


def derive_addresses_multi_index(
    mnemonic: str,
    passphrase: str = "",
    *,
    indexes: list[int] | None = None,
    chain_ids: list[str] | None = None,
) -> DerivedWallet:
    """Derive for several address indexes (default DEFAULT_INDEXES 0–5)."""
    return derive_addresses(
        mnemonic,
        passphrase,
        chain_ids=chain_ids,
        indexes=list(indexes) if indexes is not None else list(DEFAULT_INDEXES),
    )


def parse_indexes(spec: str | None, default: list[int] | None = None) -> list[int]:
    """Parse '0-5' or '0,1,2' into index list."""
    if not spec or not spec.strip():
        return list(default) if default is not None else list(DEFAULT_INDEXES)
    s = spec.strip()
    out: set[int] = set()
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, _, b = part.partition("-")
            lo, hi = int(a), int(b)
            if lo > hi:
                lo, hi = hi, lo
            for i in range(lo, hi + 1):
                if 0 <= i <= 100:
                    out.add(i)
        else:
            i = int(part)
            if 0 <= i <= 100:
                out.add(i)
    return sorted(out) if out else list(DEFAULT_INDEXES)
