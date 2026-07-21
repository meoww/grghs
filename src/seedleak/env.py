"""Load environment variables from local .env files (never commit secrets)."""

from __future__ import annotations

import os
from pathlib import Path


def _parse_env_file(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return out
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip()
        if not key:
            continue
        # Strip matching quotes
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
            val = val[1:-1]
        out[key] = val
    return out


def load_dotenv(
    *,
    override: bool = False,
    extra_paths: list[Path] | None = None,
) -> list[Path]:
    """Load KEY=VALUE pairs into os.environ from known locations.

    Search order (later does not override earlier unless override=True for
    already-set keys; by default existing env wins):
      1. cwd/.env
      2. package project root /.env (editable install)
      3. $SEEDLEAK_HOME/.env
      4. extra_paths
    """
    candidates: list[Path] = [
        Path.cwd() / ".env",
        Path(__file__).resolve().parents[2] / ".env",  # .../seed-leak-alert/.env
        Path(os.environ.get("SEEDLEAK_HOME", Path.home() / ".seedleak")) / ".env",
    ]
    if extra_paths:
        candidates.extend(extra_paths)

    loaded: list[Path] = []
    seen: set[Path] = set()
    for path in candidates:
        try:
            path = path.resolve()
        except OSError:
            continue
        if path in seen or not path.is_file():
            continue
        seen.add(path)
        for key, val in _parse_env_file(path).items():
            if override or key not in os.environ or os.environ.get(key, "") == "":
                os.environ[key] = val
        loaded.append(path)
        # Tighten permissions if possible
        try:
            path.chmod(0o600)
        except OSError:
            pass
    return loaded
