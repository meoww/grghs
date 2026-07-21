"""Shared scan→assess→store helpers (never persist mnemonics)."""

from __future__ import annotations

import json
from dataclasses import dataclass

from seedleak.detector.bip39 import Finding
from seedleak.liveness.assess import Assessment, assess_mnemonic
from seedleak.storage.db import CaseStore
from seedleak.storage.fingerprint import fingerprint as fp_fn
from seedleak.storage.fingerprint import load_or_create_secret


@dataclass
class RecordedFinding:
    case_id: int
    created: bool
    fingerprint: str
    assessment: Assessment | None
    finding: Finding


def assess_finding(
    finding: Finding,
    *,
    check_balance: bool,
) -> Assessment:
    return assess_mnemonic(
        finding.normalized,
        language=finding.language if finding.language != "custom" else "english",
        check_balance=check_balance,
    )


def store_finding(
    store: CaseStore,
    finding: Finding,
    *,
    source_type: str,
    source_path: str,
    file_path: str | None,
    commit_sha: str | None = None,
    notes: str | None = None,
    check_balance: bool = False,
    secret: bytes | None = None,
) -> RecordedFinding:
    """Fingerprint, optional multi-chain balance check, store metadata, drop seed."""
    sec = secret or load_or_create_secret()
    assessment: Assessment | None = None
    bal_json: str | None = None
    priority = None
    has_funds = False
    eth = btc44 = btc84 = None
    addresses_json: str | None = None

    if check_balance:
        assessment = assess_finding(finding, check_balance=True)
        fp = assessment.fingerprint or fp_fn(finding.normalized, sec)
        if assessment.addresses:
            eth = assessment.addresses.eth or None
            btc44 = assessment.addresses.btc_legacy or None
            btc84 = assessment.addresses.btc_segwit or None
            addresses_json = json.dumps(
                assessment.addresses.to_dict(), ensure_ascii=False
            )
        if assessment.balances:
            bal_json = json.dumps(assessment.balances.to_dict(), ensure_ascii=False)
            priority = assessment.priority
            has_funds = assessment.has_funds
        elif assessment.priority:
            priority = assessment.priority
    else:
        # Still derive addresses without network I/O for inventory
        assessment = assess_finding(finding, check_balance=False)
        fp = assessment.fingerprint or fp_fn(finding.normalized, sec)
        if assessment.addresses:
            eth = assessment.addresses.eth or None
            btc44 = assessment.addresses.btc_legacy or None
            btc84 = assessment.addresses.btc_segwit or None
            addresses_json = json.dumps(
                assessment.addresses.to_dict(), ensure_ascii=False
            )

    note_parts = [notes] if notes else []
    if finding.language:
        note_parts.append(f"lang={finding.language}")
    if priority:
        note_parts.append(f"priority={priority}")
    if assessment and assessment.chains_derived:
        note_parts.append(f"chains={assessment.chains_derived}")
    merged_notes = ";".join(p for p in note_parts if p)

    cid, created = store.upsert_finding(
        fingerprint=fp,
        source_type=source_type,
        source_path=source_path,
        file_path=file_path,
        word_count=finding.word_count,
        context_preview=finding.context_preview,
        commit_sha=commit_sha,
        notes=merged_notes or None,
        priority=priority,
        has_funds=has_funds,
        eth_address=eth,
        btc_legacy=btc44,
        btc_segwit=btc84,
        balance_json=bal_json,
        addresses_json=addresses_json,
    )
    return RecordedFinding(
        case_id=cid,
        created=created,
        fingerprint=fp,
        assessment=assessment,
        finding=finding,
    )


def format_assessment_line(assessment: Assessment | None) -> str:
    if not assessment:
        return ""
    parts = [f"priority={assessment.priority}"]
    if assessment.chains_derived:
        parts.append(f"chains={assessment.chains_derived}")
    if assessment.addresses and assessment.addresses.eth:
        parts.append(f"eth={assessment.addresses.eth[:10]}…")
    if assessment.balances:
        parts.append(assessment.balances.summary_line())
        if assessment.has_funds:
            parts.append("HAS_FUNDS")
            parts.append("funded=" + ",".join(assessment.balances.funded_chains))
    return "  ".join(parts)
