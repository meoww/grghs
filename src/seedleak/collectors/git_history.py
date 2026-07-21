"""Scan git object history for BIP39 mnemonics (deleted secrets often remain)."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from seedleak.detector.bip39 import Finding, scan_text
from seedleak.detector.denylist import load_denylist

# Prefer paths that often hold secrets when scanning full blobs.
_HIGH_SIGNAL_PATH = re.compile(
    r"(?i)("
    r"\.env|wallet|mnemonic|seed|backup|secret|private|keys?|"
    r"recovery|keystore|metamask|bip39|passphrase"
    r")"
)

_TEXT_SUFFIXES = frozenset(
    {
        "",
        ".txt",
        ".md",
        ".env",
        ".json",
        ".yml",
        ".yaml",
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
        ".py",
        ".js",
        ".ts",
        ".go",
        ".rs",
        ".java",
        ".rb",
        ".php",
        ".sh",
        ".sql",
        ".csv",
        ".log",
        ".xml",
        ".html",
        ".ipynb",
        ".example",
        ".sample",
        ".bak",
        ".old",
    }
)


@dataclass
class HistoryHit:
    commit: str
    path: str  # path if known from diff header, else ""
    findings: list[Finding]
    mode: str = "patch"  # patch | blob


def _run_git(repo: Path, *args: str, max_bytes: int = 50_000_000) -> bytes:
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
    return out


def _run_git_text(repo: Path, *args: str, max_bytes: int = 50_000_000) -> str:
    return _run_git(repo, *args, max_bytes=max_bytes).decode("utf-8", errors="replace")


def list_commits(repo: Path, max_commits: int = 500) -> list[str]:
    out = _run_git_text(repo, "rev-list", "--all", f"--max-count={max_commits}")
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
    try:
        diff = _run_git_text(
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
        added = "\n".join(
            line[1:]
            for line in body.splitlines()
            if line.startswith("+") and not line.startswith("+++")
        )
        text = added if added.strip() else body
        if not text.strip():
            continue
        findings = [
            f
            for f in scan_text(text, languages=languages, denylist=denylist)
            if f.is_alert
        ]
        if findings:
            hits.append(
                HistoryHit(commit=commit, path=path, findings=findings, mode="patch")
            )
    return hits


def _is_candidate_blob_path(path: str, high_signal_only: bool) -> bool:
    name = path.rsplit("/", 1)[-1]
    suffix = ""
    if "." in name and not name.startswith("."):
        suffix = "." + name.rsplit(".", 1)[-1].lower()
    elif name.startswith(".env"):
        suffix = ".env"
    if suffix not in _TEXT_SUFFIXES and not name.startswith(".env"):
        # still allow extensionless high-signal names
        if not _HIGH_SIGNAL_PATH.search(path):
            return False
    if high_signal_only and not _HIGH_SIGNAL_PATH.search(path):
        return False
    return True


def list_blob_paths(
    repo: Path,
    *,
    high_signal_only: bool = True,
    max_blobs: int = 5_000,
) -> list[tuple[str, str]]:
    """Return (blob_sha, path) from all reachable trees."""
    out = _run_git_text(repo, "rev-list", "--objects", "--all", max_bytes=80_000_000)
    pairs: list[tuple[str, str]] = []
    for line in out.splitlines():
        parts = line.strip().split(maxsplit=1)
        if len(parts) != 2:
            continue
        sha, path = parts[0], parts[1]
        if len(sha) < 40:
            continue
        if not _is_candidate_blob_path(path, high_signal_only):
            continue
        pairs.append((sha, path))
        if len(pairs) >= max_blobs:
            break
    return pairs


def scan_blob(
    repo: Path,
    blob_sha: str,
    path: str,
    *,
    denylist: set[str],
    languages: list[str] | None = None,
    max_bytes: int = 1_000_000,
) -> HistoryHit | None:
    try:
        raw = _run_git(repo, "cat-file", "blob", blob_sha, max_bytes=max_bytes)
    except RuntimeError:
        return None
    if b"\x00" in raw[:8192]:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1", errors="replace")
    findings = [
        f for f in scan_text(text, languages=languages, denylist=denylist) if f.is_alert
    ]
    if not findings:
        return None
    return HistoryHit(commit=blob_sha, path=path, findings=findings, mode="blob")


def scan_git_blobs(
    repo: Path | str,
    *,
    languages: list[str] | None = None,
    denylist_paths: list[str] | None = None,
    high_signal_only: bool = True,
    max_blobs: int = 5_000,
) -> list[HistoryHit]:
    """Scan reachable blob contents (catches secrets in any historical tree)."""
    repo = Path(repo).resolve()
    denylist = load_denylist(denylist_paths)
    hits: list[HistoryHit] = []
    seen_fp: set[tuple[str, str]] = set()  # (path, normalized words via context)
    for sha, path in list_blob_paths(
        repo, high_signal_only=high_signal_only, max_blobs=max_blobs
    ):
        hit = scan_blob(repo, sha, path, denylist=denylist, languages=languages)
        if not hit:
            continue
        # Dedupe identical path+preview within run
        key = (path, hit.findings[0].context_preview)
        if key in seen_fp:
            continue
        seen_fp.add(key)
        hits.append(hit)
    return hits


def scan_git_history(
    repo: Path | str,
    *,
    max_commits: int = 300,
    languages: list[str] | None = None,
    denylist_paths: list[str] | None = None,
    mode: str = "patch",
    high_signal_only: bool = True,
    max_blobs: int = 5_000,
) -> list[HistoryHit]:
    """Walk git history.

    mode:
      - patch: scan commit diffs (fast)
      - blobs: scan high-signal historical file contents
      - both: patch then blobs
    """
    repo = Path(repo).resolve()
    try:
        _run_git_text(repo, "rev-parse", "--git-dir")
    except RuntimeError as e:
        raise RuntimeError(f"Not a git repository: {repo}") from e

    denylist = load_denylist(denylist_paths)
    all_hits: list[HistoryHit] = []

    if mode in ("patch", "both"):
        commits = list_commits(repo, max_commits=max_commits)
        for sha in commits:
            all_hits.extend(
                scan_commit_patch(repo, sha, denylist=denylist, languages=languages)
            )

    if mode in ("blobs", "both"):
        all_hits.extend(
            scan_git_blobs(
                repo,
                languages=languages,
                denylist_paths=denylist_paths,
                high_signal_only=high_signal_only,
                max_blobs=max_blobs,
            )
        )

    return all_hits
