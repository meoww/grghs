"""seedleak CLI — scan public/local data, store metadata, notify owners."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

import json

from seedleak import __version__
from seedleak.collectors.git_history import scan_git_history
from seedleak.collectors.local import scan_path
from seedleak.detector.bip39 import LANGUAGES, default_languages, scan_file, scan_text
from seedleak.detector.denylist import load_denylist
from seedleak.env import load_dotenv
from seedleak.notify.github_issue import NotifyChannel, notify_case
from seedleak.notify.templates import (
    dry_run_report,
    issue_body,
    issue_title,
    private_report_body,
    private_report_summary,
)
from seedleak.pipeline import format_assessment_line, store_finding
from seedleak.storage.db import CaseStatus, CaseStore
from seedleak.storage.fingerprint import fingerprint, load_or_create_secret

console = Console(stderr=True)

# Load .env before any command that needs GITHUB_TOKEN
load_dotenv()


def _default_db() -> Path:
    home = Path(os.environ.get("SEEDLEAK_HOME", Path.home() / ".seedleak"))
    return home / "cases.db"


def _store(db: Path | None) -> CaseStore:
    return CaseStore(db or _default_db())


def _secret() -> bytes:
    return load_or_create_secret()


def _parse_langs(lang: str | None, all_langs: bool, *, default_all: bool = False) -> list[str]:
    if all_langs or (default_all and not lang):
        return default_languages(all_langs=True)
    if not lang:
        return default_languages(all_langs=False)
    parts = [p.strip().lower().replace("-", "_") for p in lang.split(",") if p.strip()]
    for p in parts:
        if p not in LANGUAGES:
            raise click.ClickException(
                f"Unknown language {p!r}. Choose from: {', '.join(sorted(LANGUAGES))}"
            )
    return parts


def _lang_option(f):
    f = click.option(
        "--lang",
        default=None,
        help="Comma-separated BIP39 languages (default: english, or all for hunt). "
        f"Known: {', '.join(sorted(LANGUAGES))}",
    )(f)
    f = click.option(
        "--all-langs/--english-only",
        default=False,
        show_default=True,
        help="Scan with all bundled BIP39 wordlists",
    )(f)
    return f


def _indexes_option(default: str = "0-5"):
    def deco(f):
        return click.option(
            "--indexes",
            default=default,
            show_default=True,
            help="HD address indexes to derive/check, e.g. 0-5 or 0,1,2",
        )(f)

    return deco


@click.group()
@click.version_option(__version__, prog_name="seedleak")
def main() -> None:
    """Detect exposed BIP39 seed phrases and notify repository owners.

    Policy: detect → verify checksum → store HMAC fingerprint only → notify.
    Plaintext mnemonics are never written to disk.

    Auth: set GITHUB_TOKEN or GH_TOKEN in the environment (never commit tokens).
    """


@main.command("scan-file")
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--show-denied", is_flag=True, help="Also show denylisted test vectors")
@click.option("--db", type=click.Path(path_type=Path), default=None, help="Case DB path")
@click.option("--no-store", is_flag=True, help="Do not write findings to the case DB")
@click.option(
    "--check-balance/--no-check-balance",
    default=False,
    show_default=True,
    help="Derive addresses + public balance check",
)
@click.option("--indexes", default="0-5", show_default=True)
@_lang_option
def scan_file_cmd(
    path: Path,
    show_denied: bool,
    db: Path | None,
    no_store: bool,
    check_balance: bool,
    indexes: str,
    lang: str | None,
    all_langs: bool,
) -> None:
    """Scan a single file for valid BIP39 mnemonics."""
    languages = _parse_langs(lang, all_langs)
    denylist = load_denylist()
    findings = scan_file(path, denylist=denylist, languages=languages)
    if not findings:
        console.print(f"[green]No BIP39 candidates in[/green] {path}")
        return

    secret = _secret()
    store = None if no_store else _store(db)
    alerts = 0
    for f in findings:
        if f.is_denylisted and not show_denied:
            console.print(f"[dim]denylist hit ({f.word_count}w / {f.language}) ignored[/dim]")
            continue
        if not f.checksum_valid:
            continue
        alerts += 1
        if store and f.is_alert:
            rec = store_finding(
                store,
                f,
                source_type="file",
                source_path=str(path.resolve()),
                file_path=path.name,
                check_balance=check_balance,
                secret=secret,
                indexes=indexes,
            )
            color = "bold red" if rec.assessment and rec.assessment.has_funds else "red"
            console.print(
                f"[{color}]ALERT[/{color}] {f.word_count}w lang={f.language}  "
                f"fp={rec.fingerprint[:16]}…  case=#{rec.case_id}"
            )
            if rec.assessment:
                console.print(f"  {format_assessment_line(rec.assessment)}")
        else:
            fp = fingerprint(f.normalized, secret)
            status = "DENYLIST" if f.is_denylisted else "ALERT"
            color = "yellow" if f.is_denylisted else "red"
            console.print(
                f"[{color}]{status}[/{color}] {f.word_count}w lang={f.language}  "
                f"fp={fp[:16]}…  {f.context_preview}"
            )

    if alerts == 0:
        console.print("[green]No actionable alerts[/green]")
    sys.exit(2 if any(f.is_alert for f in findings) else 0)


@main.command("scan-path")
@click.argument("root", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--db", type=click.Path(path_type=Path), default=None)
@click.option("--no-store", is_flag=True)
@click.option("--max-files", default=50_000, show_default=True)
@_lang_option
def scan_path_cmd(
    root: Path,
    db: Path | None,
    no_store: bool,
    max_files: int,
    lang: str | None,
    all_langs: bool,
) -> None:
    """Recursively scan a directory (skips node_modules, .git, etc.)."""
    languages = _parse_langs(lang, all_langs)
    console.print(f"Scanning [bold]{root}[/bold] (langs={','.join(languages)}) …")
    hits = scan_path(root, max_files=max_files, languages=languages)
    secret = _secret()
    store = None if no_store else _store(db)
    total = 0
    for hit in hits:
        for f in hit.findings:
            total += 1
            fp = fingerprint(f.normalized, secret)
            console.print(
                f"[red]ALERT[/red] {hit.relative}  {f.word_count}w/{f.language}  fp={fp[:16]}…"
            )
            if store:
                cid, created = store.upsert_finding(
                    fingerprint=fp,
                    source_type="repo",
                    source_path=str(root.resolve()),
                    file_path=hit.relative,
                    word_count=f.word_count,
                    context_preview=f.context_preview,
                    notes=f"lang={f.language}",
                )
                console.print(f"  → case #{cid} ({'new' if created else 'dup'})")

    console.print(f"Done. actionable findings: [bold]{total}[/bold] in {len(hits)} file(s)")
    sys.exit(2 if total else 0)


@main.command("scan-history")
@click.argument("root", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--max-commits", default=300, show_default=True)
@click.option(
    "--mode",
    type=click.Choice(["patch", "blobs", "both"], case_sensitive=False),
    default="both",
    show_default=True,
    help="patch=commit diffs; blobs=historical file contents; both",
)
@click.option(
    "--all-paths",
    is_flag=True,
    help="In blob mode, scan all text-like paths (not only high-signal names)",
)
@click.option("--max-blobs", default=5000, show_default=True)
@click.option("--db", type=click.Path(path_type=Path), default=None)
@click.option("--no-store", is_flag=True)
@click.option(
    "--source-label",
    default=None,
    help="Label stored as source_path (e.g. owner/repo)",
)
@_lang_option
def scan_history_cmd(
    root: Path,
    max_commits: int,
    mode: str,
    all_paths: bool,
    max_blobs: int,
    db: Path | None,
    no_store: bool,
    source_label: str | None,
    lang: str | None,
    all_langs: bool,
) -> None:
    """Scan git history (patches and/or historical blobs)."""
    languages = _parse_langs(lang, all_langs)
    console.print(
        f"History scan [bold]{root}[/bold] mode={mode} max_commits={max_commits} "
        f"langs={','.join(languages)} …"
    )
    try:
        hits = scan_git_history(
            root,
            max_commits=max_commits,
            languages=languages,
            mode=mode,
            high_signal_only=not all_paths,
            max_blobs=max_blobs,
        )
    except RuntimeError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)

    secret = _secret()
    store = None if no_store else _store(db)
    source = source_label or str(root.resolve())
    total = 0
    for hit in hits:
        for f in hit.findings:
            total += 1
            fp = fingerprint(f.normalized, secret)
            short = hit.commit[:10]
            console.print(
                f"[red]ALERT[/red] [{hit.mode}] {short}:{hit.path}  "
                f"{f.word_count}w/{f.language}  fp={fp[:16]}…"
            )
            if store:
                cid, created = store.upsert_finding(
                    fingerprint=fp,
                    source_type="github"
                    if "/" in source and not source.startswith("/")
                    else "repo",
                    source_path=source,
                    file_path=hit.path or f"history:{short}",
                    word_count=f.word_count,
                    context_preview=f.context_preview,
                    commit_sha=hit.commit if hit.mode == "patch" else None,
                    notes=f"lang={f.language};hist={hit.mode}",
                )
                console.print(f"  → case #{cid} ({'new' if created else 'dup'})")

    console.print(f"Done. actionable history findings: [bold]{total}[/bold]")
    sys.exit(2 if total else 0)


@main.command("scan-repo")
@click.argument("repo")
@click.option("--db", type=click.Path(path_type=Path), default=None)
@click.option("--keep-clone", is_flag=True, help="Do not delete temp clone")
@click.option("--depth", default=0, show_default=True, help="git clone --depth (0=full)")
@click.option("--history/--no-history", default=True, show_default=True)
@click.option("--max-commits", default=300, show_default=True)
@click.option(
    "--history-mode",
    type=click.Choice(["patch", "blobs", "both"], case_sensitive=False),
    default="both",
    show_default=True,
)
@_lang_option
def scan_repo_cmd(
    repo: str,
    db: Path | None,
    keep_clone: bool,
    depth: int,
    history: bool,
    max_commits: int,
    history_mode: str,
    lang: str | None,
    all_langs: bool,
) -> None:
    """Clone a public git repo, scan tree (+ optional full history)."""
    import subprocess
    import tempfile

    languages = _parse_langs(lang, all_langs)
    if shutil.which("git") is None:
        console.print("[red]git not found on PATH[/red]")
        sys.exit(1)

    url = repo
    if repo.count("/") == 1 and not repo.startswith("http") and not repo.endswith(".git"):
        url = f"https://github.com/{repo}.git"
        source_label = repo
    else:
        source_label = repo

    tmp = Path(tempfile.mkdtemp(prefix="seedleak-"))
    console.print(f"Cloning [bold]{url}[/bold] → {tmp}")
    try:
        cmd = ["git", "clone"]
        if depth and depth > 0:
            cmd.extend(["--depth", str(depth)])
        cmd.extend([url, str(tmp / "repo")])
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            console.print(f"[red]clone failed:[/red] {r.stderr.strip()}")
            sys.exit(1)
        root = tmp / "repo"
        secret = _secret()
        store = _store(db)
        total = 0

        hits = scan_path(root, languages=languages)
        for hit in hits:
            for f in hit.findings:
                total += 1
                fp = fingerprint(f.normalized, secret)
                console.print(
                    f"[red]ALERT[/red] tree:{source_label}:{hit.relative}  "
                    f"{f.word_count}w/{f.language}"
                )
                store.upsert_finding(
                    fingerprint=fp,
                    source_type="github",
                    source_path=source_label
                    if source_label.count("/") == 1
                    else url,
                    file_path=hit.relative,
                    word_count=f.word_count,
                    context_preview=f.context_preview,
                    notes=f"lang={f.language}",
                )

        if history:
            # If shallow clone with depth, history is limited — warn.
            if depth and depth > 0:
                console.print(
                    f"[yellow]Shallow clone (depth={depth}); history is incomplete. "
                    "Use --depth 0 for full history.[/yellow]"
                )
            h_hits = scan_git_history(
                root,
                max_commits=max_commits,
                languages=languages,
                mode=history_mode,
            )
            for hit in h_hits:
                for f in hit.findings:
                    total += 1
                    fp = fingerprint(f.normalized, secret)
                    console.print(
                        f"[red]ALERT[/red] hist[{hit.mode}]:{hit.commit[:10]}:{hit.path}  "
                        f"{f.word_count}w/{f.language}"
                    )
                    store.upsert_finding(
                        fingerprint=fp,
                        source_type="github",
                        source_path=source_label
                        if source_label.count("/") == 1
                        else url,
                        file_path=hit.path or f"history:{hit.commit[:10]}",
                        word_count=f.word_count,
                        context_preview=f.context_preview,
                        commit_sha=hit.commit if hit.mode == "patch" else None,
                        notes=f"lang={f.language};hist={hit.mode}",
                    )

        console.print(f"Done. actionable findings: [bold]{total}[/bold]")
        sys.exit(2 if total else 0)
    finally:
        if not keep_clone:
            shutil.rmtree(tmp, ignore_errors=True)


@main.command("scan-text")
@click.argument("text", required=False)
@click.option("--stdin", "use_stdin", is_flag=True, help="Read text from stdin")
@click.option(
    "--check-balance/--no-check-balance",
    default=False,
    show_default=True,
    help="Derive addresses and query public balances (read-only)",
)
@_lang_option
def scan_text_cmd(
    text: str | None,
    use_stdin: bool,
    check_balance: bool,
    lang: str | None,
    all_langs: bool,
) -> None:
    """Scan a string (or stdin). Does not store."""
    languages = _parse_langs(lang, all_langs)
    if use_stdin or text is None:
        text = sys.stdin.read()
    denylist = load_denylist()
    findings = scan_text(text, denylist=denylist, languages=languages)
    secret = _secret()
    funded = 0
    for f in findings:
        fp = fingerprint(f.normalized, secret)
        label = "DENYLIST" if f.is_denylisted else ("ALERT" if f.is_alert else "invalid")
        console.print(
            f"{label} {f.word_count}w/{f.language} fp={fp[:16]}… {f.context_preview}"
        )
        if check_balance and f.is_alert:
            from seedleak.liveness.assess import assess_mnemonic

            a = assess_mnemonic(
                f.normalized,
                language=f.language,
                check_balance=True,
                indexes="0-5",
            )
            console.print(f"  {format_assessment_line(a)}")
            if a.addresses:
                console.print(f"  ETH  {a.addresses.eth}")
                console.print(f"  BTC84 {a.addresses.btc_segwit}")
                if a.addresses.get("tron"):
                    console.print(f"  TRON {a.addresses.get('tron')}")
                if a.addresses.get("sol"):
                    console.print(f"  SOL  {a.addresses.get('sol')}")
            if a.has_funds:
                funded += 1
                console.print("  [bold red]HAS_FUNDS — prioritize disclosure[/bold red]")
    if not findings:
        console.print("[green]No candidates[/green]")
    if check_balance and funded:
        console.print(f"[red]Funded findings: {funded}[/red]")
    sys.exit(2 if any(f.is_alert for f in findings) else 0)


@main.command("assess")
@click.argument("mnemonic", required=False)
@click.option("--stdin", "use_stdin", is_flag=True, help="Read mnemonic from stdin")
@click.option(
    "--lang",
    default="auto",
    show_default=True,
    help="BIP39 language or 'auto' to detect",
)
@click.option("--json", "as_json", is_flag=True, help="Machine-readable public metadata")
@click.option("--no-balance", is_flag=True, help="Skip network balance queries")
@click.option(
    "--indexes",
    default="0-5",
    show_default=True,
    help="HD address indexes, e.g. 0-5 or 0,1,2",
)
@click.option(
    "--show-all-addresses",
    is_flag=True,
    help="Print every derived chain address (verbose)",
)
def assess_cmd(
    mnemonic: str | None,
    use_stdin: bool,
    lang: str,
    as_json: bool,
    no_balance: bool,
    indexes: str,
    show_all_addresses: bool,
) -> None:
    """Validate BIP39 + multi-chain/multi-index derive + public balances.

    Covers BTC/EVM/TRON/SOL/COSMOS/XRP/APT/SUI and more (see `seedleak chains`).
    Default indexes 0–5. Input never written to DB. --json never includes mnemonic.
    """
    from seedleak.liveness.assess import assess_mnemonic
    from seedleak.liveness.derive import parse_indexes

    if use_stdin or mnemonic is None:
        mnemonic = sys.stdin.read().strip()
    if not mnemonic:
        console.print("[red]Empty mnemonic[/red]")
        sys.exit(1)

    idx = parse_indexes(indexes)
    a = assess_mnemonic(
        mnemonic,
        language=None if lang == "auto" else lang,
        check_balance=not no_balance,
        indexes=idx,
    )
    del mnemonic

    if as_json:
        click.echo(a.to_public_json())
    else:
        console.print(f"checksum   : {'valid' if a.valid_checksum else 'INVALID'}")
        console.print(f"denylisted : {a.denylisted}")
        console.print(f"words      : {a.word_count}  lang={a.language}")
        console.print(f"fingerprint: {a.fingerprint[:24]}…")
        console.print(f"priority   : {a.priority}")
        console.print(
            f"chains     : {a.chains_derived} × indexes {idx[0]}-{idx[-1]} "
            f"({len(a.addresses.entries) if a.addresses else 0} addresses)"
        )
        if a.addresses:
            if show_all_addresses:
                table = Table(title="Derived addresses (public)")
                table.add_column("Idx", justify="right")
                table.add_column("Chain")
                table.add_column("Path")
                table.add_column("Address")
                for e in a.addresses.entries:
                    table.add_row(str(e.index), e.chain_id, e.path, e.address)
                console.print(table)
            else:
                for cid in (
                    "eth",
                    "btc_segwit",
                    "btc_legacy",
                    "tron",
                    "sol",
                    "bsc",
                    "polygon",
                    "atom",
                    "xrp",
                ):
                    addr = a.addresses.get(cid, 0)
                    if addr:
                        console.print(f"{cid:12}: {addr}")
                console.print(
                    f"[dim]index 0 highlights; full map: --show-all-addresses / --json[/dim]"
                )
            if a.addresses.errors:
                console.print(f"[yellow]derive errors: {len(a.addresses.errors)}[/yellow]")
        if a.balances:
            console.print(f"balances   : {a.balances.summary_line()}")
            funded = [b for b in a.balances.items if b.ok and b.raw > 0]
            if funded:
                ft = Table(title="Funded")
                ft.add_column("Idx", justify="right")
                ft.add_column("Chain")
                ft.add_column("Asset")
                ft.add_column("Amount")
                ft.add_column("Address")
                for b in funded:
                    ft.add_row(
                        str(b.index),
                        b.chain_id,
                        b.symbol,
                        f"{b.amount:g}",
                        b.address[:18] + "…",
                    )
                console.print(ft)
            if a.balances.errors:
                console.print(
                    f"[dim]probe errors: {len(a.balances.errors)} "
                    f"(RPC rate-limits are normal)[/dim]"
                )
        if a.error:
            console.print(f"[yellow]error: {a.error}[/yellow]")
        if a.has_funds:
            console.print("[bold red]HAS_FUNDS on one or more derived addresses[/bold red]")
        elif a.actionable:
            console.print(
                f"[green]No funds on checked mainnet addresses (indexes {idx[0]}-{idx[-1]})[/green]"
            )

    if not a.valid_checksum:
        sys.exit(1)
    if a.has_funds:
        sys.exit(3)
    sys.exit(0)


@main.command("chains")
def chains_cmd() -> None:
    """List supported wallet chains for derivation / balance probes."""
    from seedleak.liveness.chains import CHAIN_SPECS

    table = Table(title="Supported chains")
    table.add_column("ID")
    table.add_column("Label")
    table.add_column("Path")
    table.add_column("Balance probe")
    for s in CHAIN_SPECS:
        table.add_row(s.id, s.label, s.path, s.balance.value)
    console.print(table)
    console.print(
        f"[dim]{len(CHAIN_SPECS)} chains. "
        "Balance=none means address is still derived for inventory.[/dim]"
    )


@main.command("cases")
@click.option(
    "--status",
    default=None,
    help="Filter: new|reviewed|notified|fixed|ignored|false_positive",
)
@click.option("--funds-only", is_flag=True, help="Only cases with has_funds=1")
@click.option("--limit", default=50, show_default=True)
@click.option("--db", type=click.Path(path_type=Path), default=None)
def cases_cmd(
    status: str | None,
    funds_only: bool,
    limit: int,
    db: Path | None,
) -> None:
    """List stored cases (metadata only)."""
    store = _store(db)
    rows = store.list_cases(
        status=status,
        has_funds=True if funds_only else None,
        limit=limit,
    )
    table = Table(title="Cases")
    table.add_column("ID", justify="right")
    table.add_column("Status")
    table.add_column("Pri")
    table.add_column("$", justify="center")
    table.add_column("V", justify="center")
    table.add_column("Words", justify="right")
    table.add_column("Source")
    table.add_column("File")
    table.add_column("FP")
    for c in rows:
        table.add_row(
            str(c.id),
            c.status,
            c.priority or "-",
            "Y" if c.has_funds else "",
            "Y" if c.secret_stored else "",
            str(c.word_count),
            (c.source_path or "")[:32],
            (c.file_path or "")[:24],
            c.fingerprint[:10] + "…",
        )
    console.print(table)
    if not rows:
        console.print("[dim]No cases yet. Run scan-file / scan-path / scan-repo.[/dim]")


@main.command("show")
@click.argument("case_id", type=int)
@click.option("--db", type=click.Path(path_type=Path), default=None)
@click.option("--draft", is_flag=True, help="Also print notification drafts")
def show_cmd(case_id: int, db: Path | None, draft: bool) -> None:
    """Show one case (metadata only, never the secret)."""
    store = _store(db)
    case = store.get(case_id)
    if not case:
        console.print(f"[red]Case #{case_id} not found[/red]")
        sys.exit(1)
    console.print(f"[bold]Case #{case.id}[/bold]  status={case.status}")
    console.print(f"  source_type : {case.source_type}")
    console.print(f"  source_path : {case.source_path}")
    console.print(f"  file_path   : {case.file_path}")
    console.print(f"  commit      : {case.commit_sha}")
    console.print(f"  words       : {case.word_count}")
    console.print(f"  fingerprint : {case.fingerprint}")
    console.print(f"  priority    : {case.priority}  has_funds={case.has_funds}")
    console.print(f"  language    : {case.language}")
    console.print(f"  source_url  : {case.source_url}")
    console.print(f"  search_query: {case.search_query}")
    console.print(f"  query_cat  : {case.query_category}  ({case.query_note})")
    console.print(f"  vault       : secret_stored={case.secret_stored}")
    console.print(f"  funded_sum  : {case.funded_summary}")
    console.print(f"  ETH         : {case.eth_address}")
    console.print(f"  BTC44       : {case.btc_legacy}")
    console.print(f"  BTC84       : {case.btc_segwit}")
    if case.addresses_json:
        try:
            addrs = json.loads(case.addresses_json)
            console.print(f"  addresses   : {len(addrs)} chains stored")
            for k in ("tron", "sol", "bsc", "polygon", "atom", "xrp", "aptos", "sui"):
                if k in addrs:
                    console.print(f"    {k:10}: {addrs[k]}")
        except Exception:
            console.print(f"  addresses   : {case.addresses_json[:120]}…")
    if case.balance_json:
        try:
            bal = json.loads(case.balance_json)
            console.print(
                f"  balances    : funded={bal.get('funded_chains')} "
                f"priority={bal.get('priority')}"
            )
        except Exception:
            console.print(f"  balances    : {case.balance_json[:200]}…")
    console.print(f"  context     : {case.context_preview}")
    console.print(f"  notes       : {case.notes}")
    console.print(f"  found_at    : {case.found_at}")
    console.print(f"  notified    : attempts={case.notify_attempts} at={case.last_notified_at}")
    console.print(f"  notify_url  : {case.notify_url} ({case.notify_channel})")
    if case.source_type == "github" and case.source_path and "/" in case.source_path:
        base = f"https://github.com/{case.source_path}"
        if case.file_path:
            console.print(f"  link        : {base}/blob/HEAD/{case.file_path}")
        else:
            console.print(f"  link        : {base}")
    if draft:
        console.print("\n[bold]Issue draft[/bold]")
        console.print(issue_title(case))
        console.print(issue_body(case))


@main.command("stats")
@click.option("--db", type=click.Path(path_type=Path), default=None)
def stats_cmd(db: Path | None) -> None:
    """Case counts by status."""
    store = _store(db)
    s = store.stats()
    table = Table(title="Case stats")
    table.add_column("Status")
    table.add_column("Count", justify="right")
    for k in (
        "new",
        "reviewed",
        "notified",
        "fixed",
        "ignored",
        "false_positive",
        "total",
    ):
        if k in s:
            table.add_row(k, str(s[k]))
    for k, v in sorted(s.items()):
        if k not in {
            "new",
            "reviewed",
            "notified",
            "fixed",
            "ignored",
            "false_positive",
            "total",
        }:
            table.add_row(k, str(v))
    console.print(table)


@main.command("export")
@click.argument("path", type=click.Path(path_type=Path))
@click.option("--status", default=None)
@click.option("--limit", default=10_000, show_default=True)
@click.option("--db", type=click.Path(path_type=Path), default=None)
def export_cmd(path: Path, status: str | None, limit: int, db: Path | None) -> None:
    """Export case metadata to JSON (never includes decrypted mnemonics)."""
    store = _store(db)
    n = store.export_json(path, status=status, limit=limit)
    console.print(f"Wrote {n} case(s) → {path} (secrets stay encrypted/omitted)")


@main.command("set-status")
@click.argument("case_id", type=int)
@click.argument(
    "status",
    type=click.Choice([s.value for s in CaseStatus], case_sensitive=False),
)
@click.option("--notes", default=None)
@click.option("--db", type=click.Path(path_type=Path), default=None)
def set_status_cmd(case_id: int, status: str, notes: str | None, db: Path | None) -> None:
    """Update case status after human review."""
    store = _store(db)
    case = store.get(case_id)
    if not case:
        console.print(f"[red]Case #{case_id} not found[/red]")
        sys.exit(1)
    store.set_status(case_id, status, notes=notes)
    console.print(f"Case #{case_id}: {case.status} → {status}")


@main.command("notify")
@click.argument("case_id", type=int)
@click.option("--live", is_flag=True, help="Actually send (default: dry-run)")
@click.option(
    "--channel",
    type=click.Choice([c.value for c in NotifyChannel], case_sensitive=False),
    default="auto",
    show_default=True,
    help="auto=private report if enabled, else public issue",
)
@click.option("--db", type=click.Path(path_type=Path), default=None)
def notify_cmd(case_id: int, live: bool, channel: str, db: Path | None) -> None:
    """Responsible-disclosure notification for a case."""
    store = _store(db)
    case = store.get(case_id)
    if not case:
        console.print(f"[red]Case #{case_id} not found[/red]")
        sys.exit(1)
    if case.status in (CaseStatus.FALSE_POSITIVE.value, CaseStatus.IGNORED.value):
        console.print(f"[yellow]Case #{case_id} is {case.status}; refusing notify[/yellow]")
        sys.exit(1)

    dry_run = not live
    if dry_run:
        console.print(dry_run_report(case))
        console.print("[bold]Public issue draft:[/bold]")
        console.print(f"  title: {issue_title(case)}")
        console.print(issue_body(case))
        console.print("[bold]Private report draft:[/bold]")
        console.print(f"  summary: {private_report_summary(case)}")
        console.print(private_report_body(case))
        result = notify_case(case, channel=channel, dry_run=True)
        console.print(f"[cyan]{result.message}[/cyan]")
        console.print(
            "[dim]Re-run with --live to send (needs GITHUB_TOKEN). Prefer --channel private.[/dim]"
        )
        return

    result = notify_case(case, channel=channel, dry_run=False)
    if result.ok:
        store.mark_notified(case_id, url=result.url, channel=result.channel)
        console.print(f"[green]{result.message}[/green] {result.url or ''}")
    else:
        console.print(f"[red]{result.message}[/red]")
        sys.exit(1)


@main.command("notify-batch")
@click.option("--status", default="reviewed", show_default=True)
@click.option("--live", is_flag=True)
@click.option(
    "--channel",
    type=click.Choice([c.value for c in NotifyChannel], case_sensitive=False),
    default="auto",
)
@click.option("--limit", default=20, show_default=True)
@click.option("--db", type=click.Path(path_type=Path), default=None)
def notify_batch_cmd(
    status: str,
    live: bool,
    channel: str,
    limit: int,
    db: Path | None,
) -> None:
    """Notify multiple cases (default: status=reviewed). Dry-run unless --live."""
    store = _store(db)
    rows = store.list_cases(status=status, limit=limit)
    if not rows:
        console.print(f"[dim]No cases with status={status}[/dim]")
        return
    ok_n = 0
    for case in rows:
        if case.status in (CaseStatus.FALSE_POSITIVE.value, CaseStatus.IGNORED.value):
            continue
        result = notify_case(case, channel=channel, dry_run=not live)
        mark = "OK" if result.ok else "FAIL"
        console.print(f"[{'green' if result.ok else 'red'}]{mark}[/{'green' if result.ok else 'red'}] "
                      f"#{case.id} {result.channel}: {result.message}")
        if live and result.ok:
            store.mark_notified(case.id, url=result.url, channel=result.channel)
            ok_n += 1
    if live:
        console.print(f"Notified: {ok_n}/{len(rows)}")


@main.command("list-queries")
@click.option("--ngrams/--no-ngrams", default=True, show_default=True)
@click.option("--ngram-count", default=40, show_default=True)
def list_queries_cmd(ngrams: bool, ngram_count: int) -> None:
    """Show the default hunt query catalog (code constructs + BIP39 n-grams)."""
    from seedleak.collectors.queries import default_hunt_queries

    qs = default_hunt_queries(include_ngrams=ngrams, ngram_count=ngram_count)
    table = Table(title=f"Hunt queries ({len(qs)})")
    table.add_column("#", justify="right")
    table.add_column("Cat")
    table.add_column("Query")
    table.add_column("Note")
    for i, q in enumerate(qs, 1):
        table.add_row(str(i), q.category, q.query[:70], (q.note or "")[:28])
    console.print(table)


@main.command("github-search")
@click.option("--query", "queries", multiple=True, help="Override default search queries")
@click.option("--max-per-query", default=10, show_default=True)
@click.option(
    "--check-balance/--no-check-balance",
    default=True,
    show_default=True,
    help="Derive addresses + public balance check for each alert",
)
@click.option(
    "--indexes",
    default="0",
    show_default=True,
    help="HD address indexes (fast default: 0; deep: 0-5)",
)
@click.option(
    "--fast/--full",
    default=True,
    show_default=True,
    help="Fast: index 0 + core chains only; full: all chains/tokens",
)
@click.option(
    "--all-langs/--english-only",
    default=False,
    show_default=True,
    help="All BIP39 languages (slower; default english-only for speed)",
)
@click.option("--lang", default=None, help="Override languages")
@click.option(
    "--no-ngrams",
    is_flag=True,
    help="Disable BIP39 word n-gram queries in the default catalog",
)
@click.option("--ngram-count", default=20, show_default=True, help="How many 3-gram queries")
@click.option(
    "--max-per-file",
    default=3,
    show_default=True,
    help="Max findings with balance check per file (rest skip network)",
)
@click.option("--db", type=click.Path(path_type=Path), default=None)
def github_search_cmd(
    queries: tuple[str, ...],
    max_per_query: int,
    check_balance: bool,
    indexes: str,
    fast: bool,
    all_langs: bool,
    lang: str | None,
    no_ngrams: bool,
    ngram_count: int,
    max_per_file: int,
    db: Path | None,
) -> None:
    """Search public GitHub code (requires GITHUB_TOKEN). Rate-limit aware.

    Default is --fast (index 0, core chains). Use --full --indexes 0-5 for deep.
    """
    from seedleak.collectors.github_search import search_and_scan
    from seedleak.collectors.queries import default_hunt_queries
    from seedleak.liveness.derive import parse_indexes

    if lang:
        languages = _parse_langs(lang, False)
    else:
        languages = _parse_langs(None, all_langs)
    # Fast mode forces single index unless user passed multi via indexes explicitly
    # (indexes still honored as given; default CLI is "0")
    idx = parse_indexes(indexes)
    balance_mode = "fast" if fast else "full"

    if queries:
        qlist = list(queries)
    else:
        qlist = default_hunt_queries(
            include_ngrams=not no_ngrams and not fast,
            ngram_count=ngram_count if not fast else 0,
            include_keyword=True,
        )
    console.print(
        f"Hunt mode={'fast' if fast else 'full'} queries={len(qlist)} "
        f"langs={len(languages)} indexes={idx[0]}-{idx[-1]} "
        f"balance={check_balance} max_per_file={max_per_file}"
    )
    try:
        hits, stats = search_and_scan(
            qlist,
            max_per_query=max_per_query,
            languages=languages,
            continue_on_error=True,
        )
    except Exception as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)

    if stats.errors:
        console.print(f"[yellow]Search errors: {len(stats.errors)}[/yellow]")
        for err in stats.errors[:5]:
            console.print(f"  [dim]{err[:120]}[/dim]")

    store = _store(db)
    total = 0
    funded = 0
    vaulted = 0
    skipped_bal = 0
    for hit in hits:
        # Cap expensive balance checks per file (test vector dumps)
        bal_left = max_per_file if check_balance else 0
        for f in hit.findings:
            total += 1
            do_bal = check_balance and bal_left > 0 and not f.is_denylisted
            if check_balance and not do_bal:
                skipped_bal += 1
            if do_bal:
                bal_left -= 1
            rec = store_finding(
                store,
                f,
                source_type="github",
                source_path=hit.repo_full_name,
                file_path=hit.path,
                commit_sha=hit.sha,
                check_balance=do_bal,
                indexes=idx,
                source_url=hit.html_url or None,
                search_query=hit.search_query or None,
                query_category=hit.query_category or None,
                query_note=hit.query_note or None,
                balance_mode=balance_mode,
            )
            color = "bold red" if rec.assessment and rec.assessment.has_funds else "red"
            vault_tag = " [vault]" if rec.secret_stored else ""
            console.print(
                f"[{color}]ALERT[/{color}]{vault_tag} {hit.repo_full_name}:{hit.path}  "
                f"{f.word_count}w/{f.language}  case=#{rec.case_id}"
            )
            if hit.search_query:
                console.print(
                    f"  [cyan]query[/cyan] [{hit.query_category}] {hit.search_query[:100]}"
                )
            console.print(f"  {hit.html_url}")
            if rec.assessment:
                console.print(f"  {format_assessment_line(rec.assessment)}")
                if rec.assessment.addresses:
                    console.print(f"  ETH0 {rec.assessment.addresses.eth}")
                    console.print(f"  BTC84 {rec.assessment.addresses.btc_segwit}")
                    tron = rec.assessment.addresses.get("tron")
                    sol = rec.assessment.addresses.get("sol")
                    if tron:
                        console.print(f"  TRON {tron}")
                    if sol:
                        console.print(f"  SOL  {sol}")
                if rec.assessment.has_funds:
                    funded += 1
            if rec.secret_stored:
                vaulted += 1
                console.print(
                    "  [yellow]encrypted mnemonic stored in vault "
                    "(non-test + balance>0)[/yellow]"
                )
    console.print(
        f"Queries run: {stats.queries_run}  items: {stats.items_seen}  "
        f"files scanned: {stats.files_scanned}  bal_skipped={skipped_bal}"
    )
    console.print(
        f"Actionable findings: [bold]{total}[/bold]  "
        f"funded: [bold red]{funded}[/bold red]  "
        f"vaulted: [bold yellow]{vaulted}[/bold yellow]"
    )
    if total:
        console.print(
            "[dim]Next: seedleak cases --status new && seedleak show <id> --draft[/dim]"
        )
    sys.exit(2 if total else 0)


@main.command("vault")
@click.option("--limit", default=100, show_default=True)
@click.option("--db", type=click.Path(path_type=Path), default=None)
def vault_cmd(limit: int, db: Path | None) -> None:
    """List vault entries: non-test mnemonics with balance>0 (encrypted).

    Shows path/source metadata only. Use ``vault-show`` to decrypt one entry.
    """
    store = _store(db)
    rows = store.list_vault(limit=limit)
    table = Table(title="Vault (funded, non-test, encrypted)")
    table.add_column("ID", justify="right")
    table.add_column("Source")
    table.add_column("File")
    table.add_column("URL")
    table.add_column("Funds")
    table.add_column("ETH")
    for c in rows:
        table.add_row(
            str(c.id),
            (c.source_path or "")[:28],
            (c.file_path or "")[:22],
            (c.source_url or "")[:36],
            (c.funded_summary or "")[:28],
            (c.eth_address or "")[:12] + "…" if c.eth_address else "",
        )
    console.print(table)
    console.print(
        f"[dim]{len(rows)} vault entr(y/ies). "
        "Decrypt: seedleak vault-show <id>  |  export: seedleak vault-export out.json[/dim]"
    )
    if not rows:
        console.print(
            "[dim]Empty. Vault fills when a hunt finds non-denylist seed with balance>0.[/dim]"
        )


@main.command("vault-show")
@click.argument("case_id", type=int)
@click.option("--reveal", is_flag=True, help="Print decrypted mnemonic (sensitive!)")
@click.option("--db", type=click.Path(path_type=Path), default=None)
def vault_show_cmd(case_id: int, reveal: bool, db: Path | None) -> None:
    """Show vault case metadata; optionally decrypt mnemonic with --reveal."""
    from seedleak.storage.vault import decrypt_mnemonic

    store = _store(db)
    case = store.get(case_id)
    if not case:
        console.print(f"[red]Case #{case_id} not found[/red]")
        sys.exit(1)
    if not case.secret_stored or not case.mnemonic_enc:
        console.print(
            f"[yellow]Case #{case_id} has no vault secret "
            f"(secret_stored={case.secret_stored}, has_funds={case.has_funds})[/yellow]"
        )
        sys.exit(1)

    console.print(f"[bold]Vault case #{case.id}[/bold]")
    console.print(f"  source_path : {case.source_path}")
    console.print(f"  file_path   : {case.file_path}")
    console.print(f"  source_url  : {case.source_url}")
    console.print(f"  commit      : {case.commit_sha}")
    console.print(f"  language    : {case.language}  words={case.word_count}")
    console.print(f"  fingerprint : {case.fingerprint}")
    console.print(f"  found_at    : {case.found_at}")
    console.print(f"  search_query: {case.search_query}")
    console.print(f"  query_cat  : {case.query_category}  ({case.query_note})")
    console.print(f"  funded      : {case.funded_summary}")
    console.print(f"  ETH         : {case.eth_address}")
    console.print(f"  BTC84       : {case.btc_segwit}")
    console.print(f"  context     : {case.context_preview}")
    if case.balance_json:
        console.print(f"  balances    : {case.balance_json[:300]}…")
    if case.addresses_json:
        console.print(f"  addresses   : stored ({len(case.addresses_json)} bytes)")

    if reveal:
        try:
            mnemonic = decrypt_mnemonic(case.mnemonic_enc)
        except Exception as e:
            console.print(f"[red]Decrypt failed: {e}[/red]")
            sys.exit(1)
        console.print("[bold red]MNEMONIC (sensitive):[/bold red]")
        # Print to stdout only so it can be piped carefully
        click.echo(mnemonic)
        console.print(
            "[dim]Handle carefully. Do not paste into public issues/chats.[/dim]"
        )
    else:
        console.print(
            "[dim]Mnemonic encrypted. Re-run with --reveal to decrypt (sensitive).[/dim]"
        )


@main.command("vault-export")
@click.argument("path", type=click.Path(path_type=Path))
@click.option(
    "--reveal",
    is_flag=True,
    help="Include decrypted mnemonics in JSON (VERY sensitive)",
)
@click.option("--limit", default=10_000, show_default=True)
@click.option("--db", type=click.Path(path_type=Path), default=None)
def vault_export_cmd(
    path: Path,
    reveal: bool,
    limit: int,
    db: Path | None,
) -> None:
    """Export vault cases to JSON (path, balances, addresses; optional mnemonics)."""
    from seedleak.storage.vault import decrypt_mnemonic

    store = _store(db)
    rows = store.list_vault(limit=limit)
    out = []
    for c in rows:
        item = {
            "id": c.id,
            "fingerprint": c.fingerprint,
            "source_type": c.source_type,
            "source_path": c.source_path,
            "file_path": c.file_path,
            "source_url": c.source_url,
            "commit_sha": c.commit_sha,
            "language": c.language,
            "word_count": c.word_count,
            "found_at": c.found_at,
            "priority": c.priority,
            "has_funds": c.has_funds,
            "funded_summary": c.funded_summary,
            "search_query": c.search_query,
            "query_category": c.query_category,
            "query_note": c.query_note,
            "eth_address": c.eth_address,
            "btc_legacy": c.btc_legacy,
            "btc_segwit": c.btc_segwit,
            "context_preview": c.context_preview,
            "notes": c.notes,
            "balance_json": json.loads(c.balance_json) if c.balance_json else None,
            "addresses_json": json.loads(c.addresses_json) if c.addresses_json else None,
            "secret_stored": c.secret_stored,
        }
        if reveal and c.mnemonic_enc:
            try:
                item["mnemonic"] = decrypt_mnemonic(c.mnemonic_enc)
            except Exception as e:
                item["mnemonic_error"] = str(e)
        out.append(item)

    path.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    msg = f"Wrote {len(out)} vault case(s) → {path}"
    if reveal:
        msg += " [INCLUDES PLAINTEXT MNEMONICS — protect this file]"
    console.print(msg)


@main.command("auth-check")
def auth_check_cmd() -> None:
    """Verify GITHUB_TOKEN works (prints login only, never the token)."""
    from seedleak.github_client import GitHubClient, GitHubError

    try:
        with GitHubClient() as gh:
            me = gh.whoami()
    except GitHubError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)
    login = me.get("login", "?")
    scopes_note = "ok"
    console.print(f"[green]Authenticated as[/green] [bold]{login}[/bold] ({scopes_note})")
    console.print(
        "[dim]Recommended classic PAT scopes: public_repo (or repo), "
        "plus ability to open issues / security advisories reports.[/dim]"
    )


if __name__ == "__main__":
    main()
