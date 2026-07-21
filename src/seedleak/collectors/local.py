"""Walk local paths / git clones and scan text files."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from seedleak.detector.bip39 import Finding, scan_file
from seedleak.detector.denylist import load_denylist

DEFAULT_SKIP_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        "vendor",
        ".venv",
        "venv",
        "__pycache__",
        ".tox",
        "dist",
        "build",
        ".mypy_cache",
        ".pytest_cache",
        "target",
        ".idea",
        ".vscode",
    }
)

TEXT_EXTENSIONS = frozenset(
    {
        ".txt",
        ".md",
        ".markdown",
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
        ".jsx",
        ".tsx",
        ".go",
        ".rs",
        ".java",
        ".rb",
        ".php",
        ".sh",
        ".bash",
        ".zsh",
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
        "",
    }
)


@dataclass
class FileHit:
    path: Path
    relative: str
    findings: list[Finding]


def iter_files(
    root: Path,
    *,
    skip_dirs: frozenset[str] = DEFAULT_SKIP_DIRS,
    max_files: int = 50_000,
) -> list[Path]:
    root = root.resolve()
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs and not d.startswith(".git")]
        for name in filenames:
            p = Path(dirpath) / name
            if p.suffix.lower() in TEXT_EXTENSIONS or p.suffix == "":
                if name.endswith(
                    (".png", ".jpg", ".jpeg", ".gif", ".webp", ".zip", ".gz", ".woff")
                ):
                    continue
                out.append(p)
                if len(out) >= max_files:
                    return out
    return out


def scan_path(
    root: Path | str,
    *,
    denylist_paths: list[str] | None = None,
    max_files: int = 50_000,
    languages: list[str] | None = None,
) -> list[FileHit]:
    root = Path(root).resolve()
    denylist = load_denylist(denylist_paths)
    hits: list[FileHit] = []
    for path in iter_files(root, max_files=max_files):
        findings = scan_file(path, denylist=denylist, languages=languages)
        alerts = [f for f in findings if f.is_alert]
        if alerts:
            try:
                rel = str(path.relative_to(root))
            except ValueError:
                rel = str(path)
            hits.append(FileHit(path=path, relative=rel, findings=alerts))
    return hits
