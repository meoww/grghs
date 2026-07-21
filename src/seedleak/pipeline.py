"""Shared scan→assess→store helpers.

Policy for secret storage:
  - Encrypt and store mnemonic ONLY if not denylist AND has_funds.
  - Always store path/source/addresses/balances metadata.
  - Never print secrets in notify templates.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from seedleak.detector.bip39 import Finding
from seedleak.liveness.assess import Assessment, assess_mnemonic
from seedleak.storage.db import CaseStore
from seedleak.storage.fingerprint import fingerprint as fp_fn
from seedleak.storage.fingerprint import load_or_create_secret
from seedleak.storage.vault import encrypt_mnemonic, should_store_secret


@dataclass
class RecordedFinding:
    case_id: int
    created: bool
    fingerprint: str
    assessment: Assessment | None
    finding: Finding
    secret_stored: bool = False


def assess_finding(
    finding: Finding,
    *,
    check_balance: bool,
    indexes: list[int] | str | None = None,
    balance_mode: str = "full",
) -> Assessment:
    return assess_mnemonic(
        finding.normalized,
        language=finding.language if finding.language != "custom" else "english",
        check_balance=check_balance,
        indexes=indexes,
        balance_mode=balance_mode,
    )


def _build_source_url(
    *,
    source_type: str,
    source_path: str,
    file_path: str | None,
    commit_sha: str | None,
    explicit: str | None = None,
) -> str | None:
    if explicit:
        return explicit
    if source_type != "github":
        # Local absolute path
        if file_path and source_path:
            return f"{source_path.rstrip('/')}/{file_path.lstrip('/')}"
        return source_path
    # owner/repo
    if "/" not in source_path or source_path.startswith("/"):
        return None
    base = f"https://github.com/{source_path}"
    if not file_path:
        return base
    ref = commit_sha or "HEAD"
    return f"{base}/blob/{ref}/{file_path}"


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
    indexes: list[int] | str | None = None,
    source_url: str | None = None,
    store_secrets: bool = True,
    search_query: str | None = None,
    query_category: str | None = None,
    query_note: str | None = None,
    balance_mode: str = "full",
) -> RecordedFinding:
    """Fingerprint, optional multi-chain balance check, store metadata.

    When ``store_secrets`` and the finding is non-test with funds, the
    mnemonic is encrypted into ``mnemonic_enc`` (local vault key).
    """
    sec = secret or load_or_create_secret()
    bal_json: str | None = None
    priority = None
    has_funds = False
    eth = btc44 = btc84 = None
    addresses_json: str | None = None
    mnemonic_enc: str | None = None
    secret_ok = False
    funded_summary: str | None = None

    # Skip full re-check if this fingerprint already balance-scanned
    fp_early = fp_fn(finding.normalized, sec)
    existing = store.find_by_fingerprint(fp_early)
    if existing and existing.balance_json:
        return RecordedFinding(
            case_id=existing.id,
            created=False,
            fingerprint=fp_early,
            assessment=None,
            finding=finding,
            secret_stored=bool(existing.secret_stored),
        )

    do_balance = check_balance and not finding.is_denylisted
    assessment = assess_finding(
        finding,
        check_balance=do_balance,
        indexes=indexes,
        balance_mode=balance_mode,
    )
    fp = assessment.fingerprint or fp_fn(finding.normalized, sec)
    if assessment.addresses:
        eth = assessment.addresses.eth or None
        btc44 = assessment.addresses.btc_legacy or None
        btc84 = assessment.addresses.btc_segwit or None
        addresses_json = json.dumps(
            {
                "flat": assessment.addresses.to_dict(),
                "by_index": assessment.addresses.to_nested_dict(),
                "indexes": assessment.indexes or assessment.addresses.indexes,
            },
            ensure_ascii=False,
        )
    if assessment.balances:
        bal_json = json.dumps(assessment.balances.to_dict(), ensure_ascii=False)
        priority = assessment.priority
        has_funds = assessment.has_funds
        if has_funds:
            funded_summary = assessment.balances.summary_line(max_parts=20)
    elif assessment.priority:
        priority = assessment.priority

    denylisted = bool(assessment.denylisted or finding.is_denylisted)
    if store_secrets and should_store_secret(
        denylisted=denylisted,
        has_funds=has_funds,
        valid_checksum=assessment.valid_checksum and finding.checksum_valid,
    ):
        try:
            mnemonic_enc = encrypt_mnemonic(finding.normalized)
            secret_ok = True
        except Exception:
            mnemonic_enc = None
            secret_ok = False

    note_parts = [notes] if notes else []
    if finding.language:
        note_parts.append(f"lang={finding.language}")
    if priority:
        note_parts.append(f"priority={priority}")
    if assessment.chains_derived:
        note_parts.append(f"chains={assessment.chains_derived}")
    if assessment.indexes:
        note_parts.append(f"idx={','.join(map(str, assessment.indexes))}")
    if secret_ok:
        note_parts.append("vault=1")
    if query_category:
        note_parts.append(f"qcat={query_category}")
    merged_notes = ";".join(p for p in note_parts if p)

    url = _build_source_url(
        source_type=source_type,
        source_path=source_path,
        file_path=file_path,
        commit_sha=commit_sha,
        explicit=source_url,
    )

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
        mnemonic_enc=mnemonic_enc,
        secret_stored=secret_ok,
        source_url=url,
        language=finding.language or assessment.language,
        funded_summary=funded_summary,
        search_query=search_query,
        query_category=query_category,
        query_note=query_note,
    )
    return RecordedFinding(
        case_id=cid,
        created=created,
        fingerprint=fp,
        assessment=assessment,
        finding=finding,
        secret_stored=secret_ok,
    )


def format_assessment_line(assessment: Assessment | None) -> str:
    if not assessment:
        return ""
    parts = [f"priority={assessment.priority}"]
    if assessment.chains_derived:
        parts.append(f"chains={assessment.chains_derived}")
    if assessment.indexes:
        parts.append(f"idx={min(assessment.indexes)}-{max(assessment.indexes)}")
    if assessment.addresses and assessment.addresses.eth:
        parts.append(f"eth={assessment.addresses.eth[:10]}…")
    if assessment.balances:
        parts.append(assessment.balances.summary_line())
        if assessment.has_funds:
            parts.append("HAS_FUNDS")
            funded = assessment.balances.funded_chains
            parts.append("funded=" + ",".join(funded[:6]))
            if len(funded) > 6:
                parts.append(f"+{len(funded) - 6}")
    return "  ".join(parts)
