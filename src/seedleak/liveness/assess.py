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
from seedleak.liveness.derive import DerivedWallet, derive_addresses
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
        """JSON-safe metadata — never includes mnemonic."""
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
            "chain_ids": list_chain_ids(),
            "addresses": self.addresses.to_dict() if self.addresses else None,
            "address_errors": self.addresses.errors if self.addresses else [],
            "balances": self.balances.to_dict() if self.balances else None,
            "error": self.error,
        }

    def to_public_json(self) -> str:
        return json.dumps(self.to_public_dict(), indent=2, ensure_ascii=False)


def detect_language(words: list[str]) -> str | None:
    """Return first language whose wordlist contains all words."""
    for lang in LANGUAGES:
        try:
            _, index = load_wordlist(lang)
        except Exception:
            continue
        if all(w in index for w in words):
            # Prefer exact checksum match
            if validate_checksum(words, index):
                return lang
    # Fallback: any full membership
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
    address_index: int = 0,
) -> Assessment:
    """Full multi-chain pipeline. Do not persist the mnemonic after return."""
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

    try:
        addrs = derive_addresses(
            normalized,
            chain_ids=chain_ids,
            index=address_index,
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
        )

    balances = None
    if check_balance:
        try:
            workers = int(os.environ.get("SEEDLEAK_BALANCE_WORKERS", "12"))
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
        chains_derived=len(addrs.entries),
    )
