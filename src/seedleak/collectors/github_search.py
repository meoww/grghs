"""GitHub code search collector with rate-limit aware client."""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass

from seedleak.detector.bip39 import Finding, scan_text
from seedleak.detector.denylist import load_denylist
from seedleak.github_client import GitHubClient, GitHubError

DEFAULT_QUERIES = [
    '"seed phrase" mnemonic',
    '"recovery phrase" wallet',
    "bip39 mnemonic",
    '"12 words" wallet seed',
    "MNEMONIC filename:.env",
]


@dataclass
class RemoteHit:
    repo_full_name: str
    html_url: str
    path: str
    findings: list[Finding]


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
                html_url = item.get("html_url", "")
                fragments = [
                    tm.get("fragment")
                    for tm in (item.get("text_matches") or [])
                    if tm.get("fragment")
                ]
                text = "\n".join(fragments)
                if not text:
                    raw_url = item.get("url")
                    if not raw_url:
                        continue
                    # Contents API path is absolute in item["url"]
                    try:
                        # raw_url is full URL; client uses base — extract path
                        path_api = raw_url.split("api.github.com", 1)[-1]
                        c = gh.get(path_api)
                    except GitHubError:
                        continue
                    content_b64 = (c or {}).get("content", "")
                    try:
                        text = base64.b64decode(content_b64).decode(
                            "utf-8", errors="replace"
                        )
                    except Exception:
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
