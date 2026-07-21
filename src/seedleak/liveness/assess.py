"""Assess a mnemonic in-memory: validity → addresses → balances → drop seed."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from seedleak.detector.bip39 import load_wordlist, validate_checksum
from seedleak.detector.denylist import load_denylist
from seedleak.liveness.balances import BalanceReport, check_balances
from seedleak.liveness.derive import DerivedAddresses, derive_addresses
from seedleak.storage.fingerprint import fingerprint, load_or_create_secret


@dataclass
class Assessment:
    valid_checksum: bool
    denylisted: bool
    word_count: int
    language: str
    fingerprint: str
    addresses: DerivedAddresses | None
    balances: BalanceReport | None
    error: str | None = None

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
            # Funded denylist would still be "none" via actionable=False
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
            "addresses": {
                "eth": self.addresses.eth if self.addresses else None,
                "btc_legacy": self.addresses.btc_legacy if self.addresses else None,
                "btc_segwit": self.addresses.btc_segwit if self.addresses else None,
            }
            if self.addresses
            else None,
            "balances": self.balances.to_dict() if self.balances else None,
            "error": self.error,
        }

    def to_public_json(self) -> str:
        return json.dumps(self.to_public_dict(), indent=2, ensure_ascii=False)


def assess_mnemonic(
    mnemonic: str,
    *,
    language: str = "english",
    check_balance: bool = True,
    check_usdt: bool = True,
    secret: bytes | None = None,
) -> Assessment:
    """Full pipeline. Mnemonic must not be persisted by the caller after this."""
    words = mnemonic.strip().lower().split()
    word_count = len(words)
    normalized = " ".join(words)
    denylist = load_denylist()
    denylisted = normalized in denylist

    try:
        _, index = load_wordlist(language)
        valid = validate_checksum(words, index)
    except Exception as e:
        return Assessment(
            valid_checksum=False,
            denylisted=denylisted,
            word_count=word_count,
            language=language,
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
            language=language,
            fingerprint=fp,
            addresses=None,
            balances=None,
        )

    try:
        addrs = derive_addresses(normalized)
    except Exception as e:
        return Assessment(
            valid_checksum=True,
            denylisted=denylisted,
            word_count=word_count,
            language=language,
            fingerprint=fp,
            addresses=None,
            balances=None,
            error=f"derive: {e}",
        )

    balances = None
    if check_balance:
        try:
            balances = check_balances(
                eth=addrs.eth,
                btc_legacy=addrs.btc_legacy,
                btc_segwit=addrs.btc_segwit,
                check_usdt=check_usdt,
            )
        except Exception as e:
            balances = BalanceReport(errors=[str(e)])

    return Assessment(
        valid_checksum=True,
        denylisted=denylisted,
        word_count=word_count,
        language=language,
        fingerprint=fp,
        addresses=addrs,
        balances=balances,
    )
