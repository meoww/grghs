"""Notification templates. NEVER include the mnemonic or its words."""

from __future__ import annotations

from seedleak.storage.db import Case


def issue_title(case: Case) -> str:
    return "[Security] Potential cryptocurrency seed phrase exposure"


def private_report_summary(case: Case) -> str:
    return "Exposed BIP39 cryptocurrency seed phrase in public repository"


def _location_block(case: Case) -> str:
    location = case.file_path or case.source_path
    source = case.source_path
    commit = f"\n- Commit: `{case.commit_sha}`" if case.commit_sha else ""
    lang = f"\n- Wordlist language: `{case.notes}`" if case.notes and case.notes.startswith("lang=") else ""
    preview = case.context_preview or "(context unavailable)"
    return f"""- Source: `{source}`
- Path: `{location}`{commit}{lang}
- Context (mnemonic redacted): `{preview}`
- Case fingerprint: `{case.fingerprint[:16]}…`
- Word count: {case.word_count}
"""


def _funds_block(case: Case) -> str:
    if not getattr(case, "has_funds", False) and not getattr(case, "priority", None):
        return ""
    lines = ["## On-chain priority (public balances only)", ""]
    if case.has_funds:
        lines.append(
            "**Non-zero balance observed** on at least one derived mainnet address "
            "(ETH / ERC-20 USDT / BTC). Treat as **urgent** — rotate immediately."
        )
    elif case.priority:
        lines.append(f"Priority heuristic: `{case.priority}` (may be zero-balance or partial check).")
    if case.eth_address:
        lines.append(f"- ETH address checked: `{case.eth_address}`")
    if case.btc_segwit:
        lines.append(f"- BTC (BIP84) checked: `{case.btc_segwit}`")
    if case.btc_legacy:
        lines.append(f"- BTC (BIP44) checked: `{case.btc_legacy}`")
    lines.append("")
    lines.append(
        "Balances were read via public APIs only. No private keys were used or stored."
    )
    lines.append("")
    return "\n".join(lines)


def issue_body(case: Case, *, tool_name: str = "seedleak") -> str:
    return f"""## Summary

A string matching a **valid BIP39 mnemonic** pattern ({case.word_count} words) was detected in a **public** location associated with this repository.

This pattern may allow full control of associated cryptocurrency wallets (Bitcoin, Ethereum, ERC-20/USDT, and other HD-derived accounts).

## Location (no secret included)

{_location_block(case)}
{_funds_block(case)}
**We do not store or publish the secret itself.** Detected by `{tool_name}`.

## Recommended actions

1. **Move funds immediately** to a new wallet generated offline (new seed).
2. **Remove the secret** from the working tree and from git history (`git filter-repo` / BFG).
3. **Rotate** any related credentials and API keys in the same files.
4. Enable **GitHub Secret Scanning** and **Push Protection**.
5. Review other branches and forks for the same material.

## What we will not do

- We will not publish the mnemonic or derived keys.
- We will not attempt to access any wallets.

If this is a known **test/demo** seed with no real funds, prefer well-known public test vectors only and mark clearly.

---
*Automated responsible disclosure. Please reply if you need remediation guidance.*
"""


def private_report_body(case: Case, *, tool_name: str = "seedleak") -> str:
    return f"""## Impact

A valid BIP39 mnemonic seed phrase appears to be exposed in this public repository.
Anyone who obtains it can derive private keys for Bitcoin, Ethereum, USDT (ERC-20/TRC-20 via related wallets), and other HD accounts — **critical** confidentiality impact for users who deposited funds to those addresses.

## Location (secret intentionally omitted)

{_location_block(case)}
{_funds_block(case)}

The reporting tool (`{tool_name}`) stores only an HMAC fingerprint of the finding, not the plaintext secret.

## Remediation

1. Transfer any funds to a newly generated offline wallet.
2. Purge the secret from git history and all forks/clones you control.
3. Enable secret scanning + push protection.
4. Audit other branches and related repos.

## Severity rationale

CWE-312 / CWE-540 style exposure of credentials that grant full wallet control. Severity set to **critical**.
"""


def dry_run_report(case: Case) -> str:
    return (
        f"[DRY-RUN notify] case=#{case.id} status={case.status}\n"
        f"  source={case.source_path}\n"
        f"  file={case.file_path}\n"
        f"  words={case.word_count} fp={case.fingerprint[:16]}…\n"
        f"  title={issue_title(case)!r}\n"
    )
