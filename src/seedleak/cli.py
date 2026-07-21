"""seedleak CLI — scan public/local data, store metadata, notify owners."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from seedleak import __version__
from seedleak.collectors.git_history import scan_git_history
from seedleak.collectors.local import scan_path
from seedleak.detector.bip39 import LANGUAGES, default_languages, scan_file, scan_text
from seedleak.detector.denylist import load_denylist
from seedleak.notify.github_issue import NotifyChannel, notify_case
from seedleak.notify.templates import (
    dry_run_report,
    issue_body,
    issue_title,
    private_report_body,
    private_report_summary,
)
from seedleak.storage.db import CaseStatus, CaseStore
from seedleak.storage.fingerprint import fingerprint, load_or_create_secret

console = Console(stderr=True)


def _default_db() -> Path:
    home = Path(os.environ.get("SEEDLEAK_HOME", Path.home() / ".seedleak"))
    return home / "cases.db"


def _store(db: Path | None) -> CaseStore:
    return CaseStore(db or _default_db())


def _secret() -> bytes:
    return load_or_create_secret()


def _parse_langs(lang: str | None, all_langs: bool) -> list[str]:
    if all_langs:
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
        help="Comma-separated BIP39 languages (default: english). "
        f"Known: {', '.join(sorted(LANGUAGES))}",
    )(f)
    f = click.option(
        "--all-langs",
        is_flag=True,
        help="Scan with all bundled BIP39 wordlists (slower)",
    )(f)
    return f


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
@_lang_option
def scan_file_cmd(
    path: Path,
    show_denied: bool,
    db: Path | None,
    no_store: bool,
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
        fp = fingerprint(f.normalized, secret)
        status = "DENYLIST" if f.is_denylisted else "ALERT"
        color = "yellow" if f.is_denylisted else "red"
        console.print(
            f"[{color}]{status}[/{color}] {f.word_count}w lang={f.language}  "
            f"fp={fp[:16]}…  {f.context_preview}"
        )
        if store and f.is_alert:
            cid, created = store.upsert_finding(
                fingerprint=fp,
                source_type="file",
                source_path=str(path.resolve()),
                file_path=path.name,
                word_count=f.word_count,
                context_preview=f.context_preview,
                notes=f"lang={f.language}",
            )
            console.print(f"  → case #{cid} ({'new' if created else 'dup'})")

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
    db: Path | None,
    no_store: bool,
    source_label: str | None,
    lang: str | None,
    all_langs: bool,
) -> None:
    """Scan git commit history patches (catches deleted-but-still-in-history secrets)."""
    languages = _parse_langs(lang, all_langs)
    console.print(
        f"History scan [bold]{root}[/bold] max_commits={max_commits} "
        f"langs={','.join(languages)} …"
    )
    try:
        hits = scan_git_history(root, max_commits=max_commits, languages=languages)
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
                f"[red]ALERT[/red] {short}:{hit.path}  "
                f"{f.word_count}w/{f.language}  fp={fp[:16]}…"
            )
            if store:
                cid, created = store.upsert_finding(
                    fingerprint=fp,
                    source_type="github" if "/" in source and not source.startswith("/") else "repo",
                    source_path=source,
                    file_path=hit.path or f"history:{short}",
                    word_count=f.word_count,
                    context_preview=f.context_preview,
                    commit_sha=hit.commit,
                    notes=f"lang={f.language}",
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
@_lang_option
def scan_repo_cmd(
    repo: str,
    db: Path | None,
    keep_clone: bool,
    depth: int,
    history: bool,
    max_commits: int,
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
            h_hits = scan_git_history(root, max_commits=max_commits, languages=languages)
            for hit in h_hits:
                for f in hit.findings:
                    total += 1
                    fp = fingerprint(f.normalized, secret)
                    console.print(
                        f"[red]ALERT[/red] hist:{hit.commit[:10]}:{hit.path}  "
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
                        commit_sha=hit.commit,
                        notes=f"lang={f.language}",
                    )

        console.print(f"Done. actionable findings: [bold]{total}[/bold]")
        sys.exit(2 if total else 0)
    finally:
        if not keep_clone:
            shutil.rmtree(tmp, ignore_errors=True)


@main.command("scan-text")
@click.argument("text", required=False)
@click.option("--stdin", "use_stdin", is_flag=True, help="Read text from stdin")
@_lang_option
def scan_text_cmd(
    text: str | None,
    use_stdin: bool,
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
    for f in findings:
        fp = fingerprint(f.normalized, secret)
        label = "DENYLIST" if f.is_denylisted else ("ALERT" if f.is_alert else "invalid")
        console.print(
            f"{label} {f.word_count}w/{f.language} fp={fp[:16]}… {f.context_preview}"
        )
    if not findings:
        console.print("[green]No candidates[/green]")
    sys.exit(2 if any(f.is_alert for f in findings) else 0)


@main.command("cases")
@click.option(
    "--status",
    default=None,
    help="Filter: new|reviewed|notified|fixed|ignored|false_positive",
)
@click.option("--limit", default=50, show_default=True)
@click.option("--db", type=click.Path(path_type=Path), default=None)
def cases_cmd(status: str | None, limit: int, db: Path | None) -> None:
    """List stored cases (metadata only)."""
    store = _store(db)
    rows = store.list_cases(status=status, limit=limit)
    table = Table(title="Cases")
    table.add_column("ID", justify="right")
    table.add_column("Status")
    table.add_column("Words", justify="right")
    table.add_column("Source")
    table.add_column("File")
    table.add_column("Commit")
    table.add_column("FP")
    for c in rows:
        table.add_row(
            str(c.id),
            c.status,
            str(c.word_count),
            (c.source_path or "")[:36],
            (c.file_path or "")[:28],
            (c.commit_sha or "")[:8],
            c.fingerprint[:12] + "…",
        )
    console.print(table)
    if not rows:
        console.print("[dim]No cases yet. Run scan-file / scan-path / scan-repo.[/dim]")


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
        store.mark_notified(case_id)
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
            store.mark_notified(case.id)
            ok_n += 1
    if live:
        console.print(f"Notified: {ok_n}/{len(rows)}")


@main.command("github-search")
@click.option("--query", "queries", multiple=True, help="Override default search queries")
@click.option("--max-per-query", default=5, show_default=True)
@click.option("--db", type=click.Path(path_type=Path), default=None)
@_lang_option
def github_search_cmd(
    queries: tuple[str, ...],
    max_per_query: int,
    db: Path | None,
    lang: str | None,
    all_langs: bool,
) -> None:
    """Search public GitHub code (requires GITHUB_TOKEN). Rate-limit aware."""
    from seedleak.collectors.github_search import search_and_scan

    languages = _parse_langs(lang, all_langs)
    try:
        hits = search_and_scan(
            list(queries) if queries else None,
            max_per_query=max_per_query,
            languages=languages,
        )
    except Exception as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)

    secret = _secret()
    store = _store(db)
    total = 0
    for hit in hits:
        for f in hit.findings:
            total += 1
            fp = fingerprint(f.normalized, secret)
            console.print(
                f"[red]ALERT[/red] {hit.repo_full_name}:{hit.path}  "
                f"{f.word_count}w/{f.language}  {hit.html_url}"
            )
            store.upsert_finding(
                fingerprint=fp,
                source_type="github",
                source_path=hit.repo_full_name,
                file_path=hit.path,
                word_count=f.word_count,
                context_preview=f.context_preview,
                notes=f"lang={f.language}",
            )
    console.print(f"Actionable remote findings: [bold]{total}[/bold]")
    sys.exit(2 if total else 0)


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
