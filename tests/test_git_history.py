"""Git history scanner tests using a temporary repo."""

from __future__ import annotations

import subprocess
from pathlib import Path

from seedleak.collectors.git_history import scan_git_history
from seedleak.detector.bip39 import mnemonic_from_entropy


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
    )


def test_history_finds_deleted_secret(tmp_path: Path):
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")

    m = mnemonic_from_entropy(bytes([11] * 16))
    secret_file = repo / "wallet.txt"
    secret_file.write_text(f"seed={m}\n", encoding="utf-8")
    _git(repo, "add", "wallet.txt")
    _git(repo, "commit", "-m", "add wallet")

    secret_file.unlink()
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "remove wallet")

    # Working tree clean — secret only in history
    assert not secret_file.exists()
    hits = scan_git_history(repo, max_commits=20, languages=["english"])
    assert hits, "expected history hit for deleted mnemonic"
    assert any(h.findings for h in hits)
