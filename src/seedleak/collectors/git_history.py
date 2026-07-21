"""Scan git object history for BIP39 mnemonics (deleted secrets often remain)."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from seedleak.detector.bip39 import Finding, scan_text
from seedleak.detector.denylist import load_denylist


@dataclass
class HistoryHit:
    commit: str
    path: str  # path if known from diff header, else ""
    findings: list[Finding]


def _run_git(repo: Path, *args: str, max_bytes: int = 50_000_000) -> str:
    r = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        timeout=300,
    )
    if r.returncode != 0:
        err = r.stderr.decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"git {' '.join(args)} failed: {err}")
    out = r.stdout
    if len(out) > max_bytes:
        out = out[:max_bytes]
    return out.decode("utf-8", errors="replace")


def list_commits(repo: Path, max_commits: int = 500) -> list[str]:
    out = _run_git(repo, "rev-list", "--all", f"--max-count={max_commits}")
    return [line.strip() for line in out.splitlines() if line.strip()]


def _parse_diff_for_paths(diff: str) -> list[tuple[str, str]]:
    """Split a multi-file patch into (path, patch_body) chunks."""
    chunks: list[tuple[str, str]] = []
    current_path = ""
    buf: list[str] = []
    for line in diff.splitlines(keepends=True):
        if line.startswith("diff --git "):
            if buf:
                chunks.append((current_path, "".join(buf)))
                buf = []
            # diff --git a/foo b/foo
            parts = line.strip().split()
            if len(parts) >= 4:
                current_path = parts[3].removeprefix("b/")
            else:
                current_path = ""
            buf.append(line)
        else:
            buf.append(line)
    if buf:
        chunks.append((current_path, "".join(buf)))
    return chunks or [("", diff)]


def scan_commit_patch(
    repo: Path,
    commit: str,
    *,
    denylist: set[str],
    languages: list[str] | None = None,
) -> list[HistoryHit]:
    """Scan the patch introduced by a single commit (added lines + context)."""
    # -U0 minimizes noise; still includes added lines with '+'
    try:
        diff = _run_git(
            repo,
            "show",
            "--pretty=format:",
            "--no-ext-diff",
            "-U0",
            commit,
            max_bytes=8_000_000,
        )
    except RuntimeError:
        return []

    hits: list[HistoryHit] = []
    for path, body in _parse_diff_for_paths(diff):
        # Prefer scanning added lines; also scan full body for moved secrets.
        added = "\n".join(
            line[1:]
            for line in body.splitlines()
            if line.startswith("+") and not line.startswith("+++")
        )
        text = added if added.strip() else body
        if not text.strip():
            continue
        findings = [f for f in scan_text(text, languages=languages, denylist=denylist) if f.is_alert]
        if findings:
            hits.append(HistoryHit(commit=commit, path=path, findings=findings))
    return hits


def scan_git_history(
    repo: Path | str,
    *,
    max_commits: int = 300,
    languages: list[str] | None = None,
    denylist_paths: list[str] | None = None,
) -> list[HistoryHit]:
    """Walk recent commits and scan patches for valid BIP39 mnemonics."""
    repo = Path(repo).resolve()
    if not (repo / ".git").exists() and not (repo / "HEAD").exists():
        # bare or worktree: still try
        try:
            _run_git(repo, "rev-parse", "--git-dir")
        except RuntimeError as e:
            raise RuntimeError(f"Not a git repository: {repo}") from e

    denylist = load_denylist(denylist_paths)
    commits = list_commits(repo, max_commits=max_commits)
    all_hits: list[HistoryHit] = []
    for sha in commits:
        all_hits.extend(
            scan_commit_patch(repo, sha, denylist=denylist, languages=languages)
        )
    return all_hits
