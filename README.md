# seedleak

Detect **exposed BIP39 seed phrases** in public / local source trees and **notify repository owners** (responsible disclosure).

> **Policy:** detect → validate checksum → store **HMAC fingerprint only** → notify.  
> Plaintext mnemonics are **never** written to disk. Not for wallet access or fund movement.

One BIP39 seed can control BTC, ETH, ERC-20 USDT, and other HD accounts.

## Install

```bash
cd seed-leak-alert
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,github]"
```

## Auth (GitHub)

```bash
export GITHUB_TOKEN=ghp_...   # or GH_TOKEN
seedleak auth-check
```

**Never** put tokens in the repo, commits, or chat. If a token was exposed, **revoke it immediately** at https://github.com/settings/tokens and create a new one.

Recommended: classic PAT with rights to open issues on public repos; private vulnerability reports need the target repo to enable that feature.

## Quick start

```bash
seedleak scan-file ./suspicious.env
seedleak scan-path ./some-repo
seedleak scan-history ./some-repo --mode both --max-commits 500
seedleak scan-repo owner/name                 # tree + history (patch+blobs)
seedleak scan-repo owner/name --depth 1 --no-history

seedleak cases
seedleak show 1 --draft
seedleak stats
seedleak export ./cases.json
seedleak set-status 1 reviewed
seedleak notify 1                             # dry-run drafts
seedleak notify 1 --live --channel auto       # private report if enabled, else issue
seedleak notify-batch --status reviewed       # dry-run batch

seedleak github-search --max-per-query 5
seedleak scan-text --lang spanish,english --stdin < dump.txt
seedleak scan-path ./repo --all-langs
```

Exit codes: `0` clean, `2` actionable findings, `1` error.

## Languages

Bundled BIP39 wordlists: `english` (default), `spanish`, `french`, `italian`, `portuguese`, `czech`, `chinese_simplified`, `chinese_traditional`, `japanese`, `korean`.

```bash
seedleak scan-file x.txt --lang english,spanish
seedleak scan-path . --all-langs
```

## What gets stored

`~/.seedleak/` (override with `SEEDLEAK_HOME`):

| File | Purpose |
|------|---------|
| `hmac_secret` | Local HMAC key (mode 600) |
| `cases.db` | Metadata: path, commit, status, fingerprint, redacted context |

**Never stored:** full mnemonic, private keys, derived addresses.

## Notify channels

| Channel | Behavior |
|---------|----------|
| `auto` (default) | Private vulnerability report if repo enables it, else public issue |
| `private` | `POST .../security-advisories/reports` only |
| `issue` | Public GitHub issue only |

All templates **omit** the secret. Always dry-run first.

## History modes

| Mode | What it scans |
|------|----------------|
| `patch` | Commit diffs (added lines) — fast |
| `blobs` | Historical file contents (high-signal paths by default) |
| `both` | Default for `scan-history` / `scan-repo` |

Use `--all-paths` with blob mode to scan more files (slower, noisier).

## Detector pipeline

1. Tokenize (language-aware; CJK character-level for Chinese)  
2. Sliding window 12 / 15 / 18 / 21 / 24  
3. All words ∈ BIP39 wordlist  
4. Checksum valid  
5. Denylist of public test vectors  

## Legal / ethics

- Only public data or trees you may audit.  
- Do not access wallets or harvest balances.  
- Do not mass-spam issues; human-review first.  
- Dual-use: keep the tool notify/remediate oriented.

## Tests

```bash
pytest -q
```

## Layout

```
src/seedleak/
  detector/       # BIP39 multi-lang + denylist
  storage/        # HMAC + SQLite
  notify/         # issue + private report templates
  collectors/     # local, git history, GitHub search
  github_client.py
  cli.py
```
