"""GitHub code search collector with rate-limit aware client."""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from seedleak.detector.bip39 import Finding, scan_text
from seedleak.detector.denylist import load_denylist
from seedleak.github_client import GitHubClient, GitHubError

# High-signal queries. Keep short — search API is expensive / rate-limited.
DEFAULT_QUERIES = [
    '"seed phrase" mnemonic -test -example -demo',
    '"recovery phrase" wallet -test -hardhat',
    "bip39 mnemonic wallet -test",
    '"mnemonic" filename:.env',
    "MNEMONIC= filename:.env",
    '"12 words" "private" wallet seed',
    "wallet_seed OR recovery_seed filename:.txt",
]


@dataclass
class RemoteHit:
    repo_full_name: str
    html_url: str
    path: str
    findings: list[Finding]
    sha: str | None = None


def _api_path_from_url(url: str) -> str | None:
    """Convert full API URL to path for GitHubClient base_url."""
    if not url:
        return None
    if url.startswith("https://api.github.com"):
        return url.removeprefix("https://api.github.com")
    if url.startswith("/"):
        return url
    parsed = urlparse(url)
    if parsed.netloc == "api.github.com":
        return parsed.path
    return None


def _fetch_file_text(gh: GitHubClient, item: dict) -> str:
    fragments = [
        tm.get("fragment")
        for tm in (item.get("text_matches") or [])
        if tm.get("fragment")
    ]
    text = "\n".join(fragments)

    # Always try full file content when possible (fragments alone miss boundaries)
    repo = item.get("repository", {}).get("full_name", "")
    path = item.get("path", "")
    if repo and path:
        try:
            owner, name = repo.split("/", 1)
            c = gh.get(f"/repos/{owner}/{name}/contents/{path}")
            if isinstance(c, dict) and c.get("content"):
                return base64.b64decode(c["content"]).decode("utf-8", errors="replace")
            if isinstance(c, list):
                # directory — ignore
                pass
        except GitHubError:
            pass

    if text:
        return text

    raw_url = item.get("url")
    api_path = _api_path_from_url(raw_url or "")
    if not api_path:
        return text
    try:
        c = gh.get(api_path)
    except GitHubError:
        return text
    content_b64 = (c or {}).get("content", "")
    try:
        return base64.b64decode(content_b64).decode("utf-8", errors="replace")
    except Exception:
        return text


def search_and_scan(
    queries: list[str] | None = None,
    *,
    token: str | None = None,
    max_per_query: int = 10,
    denylist_paths: list[str] | None = None,
    languages: list[str] | None = None,
) -> list[RemoteHit]:
    denylist = load_denylist(denylist_paths)
    hits: list[RemoteHit] = []
    seen: set[tuple[str, str]] = set()
    queries = queries or DEFAULT_QUERIES

    with GitHubClient(token) as gh:
        for q in queries:
            try:
                data = gh.get(
                    "/search/code",
                    params={"q": q, "per_page": max_per_query},
                    headers={"Accept": "application/vnd.github.text-match+json"},
                )
            except GitHubError as e:
                raise RuntimeError(str(e)) from e

            items = (data or {}).get("items", [])
            for item in items:
                repo = item.get("repository", {}).get("full_name", "")
                path = item.get("path", "")
                key = (repo, path)
                if key in seen:
                    continue
                seen.add(key)

                html_url = item.get("html_url", "")
                sha = item.get("sha")
                text = _fetch_file_text(gh, item)
                if not text.strip():
                    continue

                findings = [
                    f
                    for f in scan_text(text, languages=languages, denylist=denylist)
                    if f.is_alert
                ]
                if findings:
                    hits.append(
                        RemoteHit(
                            repo_full_name=repo,
                            html_url=html_url,
                            path=path,
                            findings=findings,
                            sha=sha,
                        )
                    )
    return hits


def parse_github_repo_arg(value: str) -> str:
    value = value.strip().rstrip("/")
    m = re.match(r"https?://github\.com/([^/]+)/([^/]+)", value)
    if m:
        return f"{m.group(1)}/{m.group(2).removesuffix('.git')}"
    if value.count("/") == 1:
        return value
    raise ValueError(f"Expected owner/repo or GitHub URL, got {value!r}")
