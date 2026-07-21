"""Assess a mnemonic in-memory: validity → multi-chain addresses → balances."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

from seedleak.detector.bip39 import LANGUAGES, load_wordlist, validate_checksum
from seedleak.detector.denylist import load_denylist
from seedleak.liveness.balances import BalanceReport, check_balances
from seedleak.liveness.chains import list_chain_ids
from seedleak.liveness.derive import (
    DEFAULT_INDEXES,
    DerivedWallet,
    derive_addresses,
    parse_indexes,
)
from seedleak.storage.fingerprint import fingerprint, load_or_create_secret


@dataclass
class Assessment:
    valid_checksum: bool
    denylisted: bool
    word_count: int
    language: str
    fingerprint: str
    addresses: DerivedWallet | None
    balances: BalanceReport | None
    error: str | None = None
    chains_derived: int = 0
    indexes: list[int] | None = None

    @property
    def actionable(self) -> bool:
        return self.valid_checksum and not self.denylisted

    @property
    def has_funds(self) -> bool:
        return bool(self.balances and self.balances.has_funds)

    @property
    def priority(self) -> str:
        if not self.actionable:
            return "none"
        if self.balances:
            return self.balances.priority
        return "unknown"

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "valid_checksum": self.valid_checksum,
            "denylisted": self.denylisted,
            "word_count": self.word_count,
            "language": self.language,
            "fingerprint": self.fingerprint,
            "actionable": self.actionable,
            "priority": self.priority,
            "has_funds": self.has_funds,
            "chains_derived": self.chains_derived,
            "indexes": self.indexes or [0],
            "chain_ids": list_chain_ids(),
            "addresses": self.addresses.to_dict() if self.addresses else None,
            "addresses_by_index": self.addresses.to_nested_dict()
            if self.addresses
            else None,
            "address_errors": self.addresses.errors if self.addresses else [],
            "balances": self.balances.to_dict() if self.balances else None,
            "error": self.error,
        }

    def to_public_json(self) -> str:
        return json.dumps(self.to_public_dict(), indent=2, ensure_ascii=False)


def detect_language(words: list[str]) -> str | None:
    for lang in LANGUAGES:
        try:
            _, index = load_wordlist(lang)
        except Exception:
            continue
        if all(w in index for w in words) and validate_checksum(words, index):
            return lang
    for lang in LANGUAGES:
        try:
            _, index = load_wordlist(lang)
        except Exception:
            continue
        if all(w in index for w in words):
            return lang
    return None


def assess_mnemonic(
    mnemonic: str,
    *,
    language: str | None = "english",
    check_balance: bool = True,
    check_usdt: bool = True,
    secret: bytes | None = None,
    chain_ids: list[str] | None = None,
    address_index: int | None = None,
    indexes: list[int] | str | None = None,
) -> Assessment:
    """Full multi-chain / multi-index pipeline. Do not persist the mnemonic."""
    words = mnemonic.strip().lower().split()
    word_count = len(words)
    normalized = " ".join(words)
    denylist = load_denylist()
    denylisted = normalized in denylist

    lang = language
    if not lang or lang == "auto":
        lang = detect_language(words) or "english"

    try:
        _, index = load_wordlist(lang)
        valid = validate_checksum(words, index)
    except Exception as e:
        return Assessment(
            valid_checksum=False,
            denylisted=denylisted,
            word_count=word_count,
            language=lang or "english",
            fingerprint="",
            addresses=None,
            balances=None,
            error=f"wordlist/checksum: {e}",
        )

    sec = secret or load_or_create_secret()
    fp = fingerprint(normalized, sec)

    if not valid:
        return Assessment(
            valid_checksum=False,
            denylisted=denylisted,
            word_count=word_count,
            language=lang,
            fingerprint=fp,
            addresses=None,
            balances=None,
        )

    # Resolve indexes: explicit list > single address_index > default 0-5
    if isinstance(indexes, str):
        idx_list = parse_indexes(indexes)
    elif indexes is not None:
        idx_list = sorted({int(i) for i in indexes})
    elif address_index is not None:
        idx_list = [int(address_index)]
    else:
        idx_list = list(DEFAULT_INDEXES)

    try:
        addrs = derive_addresses(
            normalized,
            chain_ids=chain_ids,
            indexes=idx_list,
        )
    except Exception as e:
        return Assessment(
            valid_checksum=True,
            denylisted=denylisted,
            word_count=word_count,
            language=lang,
            fingerprint=fp,
            addresses=None,
            balances=None,
            error=f"derive: {e}",
            indexes=idx_list,
        )

    balances = None
    if check_balance:
        try:
            workers = int(os.environ.get("SEEDLEAK_BALANCE_WORKERS", "16"))
            balances = check_balances(
                addrs,
                check_usdt=check_usdt,
                max_workers=workers,
            )
        except Exception as e:
            balances = BalanceReport(errors=[str(e)])

    return Assessment(
        valid_checksum=True,
        denylisted=denylisted,
        word_count=word_count,
        language=lang,
        fingerprint=fp,
        addresses=addrs,
        balances=balances,
        chains_derived=len({e.chain_id for e in addrs.entries}),
        indexes=idx_list,
    )
