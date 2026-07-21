"""GitHub code search collector with rate-limit aware client."""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from seedleak.collectors.queries import SearchQuery, default_hunt_queries
from seedleak.detector.bip39 import Finding, scan_text
from seedleak.detector.denylist import load_denylist
from seedleak.github_client import GitHubClient, GitHubError


@dataclass
class RemoteHit:
    repo_full_name: str
    html_url: str
    path: str
    findings: list[Finding]
    sha: str | None = None
    search_query: str = ""
    query_category: str = ""
    query_note: str = ""


@dataclass
class SearchRunStats:
    queries_run: int = 0
    items_seen: int = 0
    files_scanned: int = 0
    hits: int = 0
    errors: list[str] = field(default_factory=list)


def _api_path_from_url(url: str) -> str | None:
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

    repo = item.get("repository", {}).get("full_name", "")
    path = item.get("path", "")
    if repo and path:
        try:
            owner, name = repo.split("/", 1)
            c = gh.get(f"/repos/{owner}/{name}/contents/{path}")
            if isinstance(c, dict) and c.get("content"):
                return base64.b64decode(c["content"]).decode("utf-8", errors="replace")
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


def _normalize_queries(
    queries: list[str] | list[SearchQuery] | None,
) -> list[SearchQuery]:
    if not queries:
        return default_hunt_queries()
    out: list[SearchQuery] = []
    for q in queries:
        if isinstance(q, SearchQuery):
            out.append(q)
        else:
            out.append(SearchQuery(str(q), "custom", "user-provided"))
    return out


def search_and_scan(
    queries: list[str] | list[SearchQuery] | None = None,
    *,
    token: str | None = None,
    max_per_query: int = 10,
    denylist_paths: list[str] | None = None,
    languages: list[str] | None = None,
    continue_on_error: bool = True,
) -> tuple[list[RemoteHit], SearchRunStats]:
    """Search GitHub code and scan hits for valid BIP39 mnemonics.

    Each hit records the ``search_query`` that produced it.
    """
    denylist = load_denylist(denylist_paths)
    hits: list[RemoteHit] = []
    # Dedupe by repo+path but keep first query that found it
    seen: set[tuple[str, str]] = set()
    qlist = _normalize_queries(queries)
    stats = SearchRunStats()

    with GitHubClient(token) as gh:
        for sq in qlist:
            stats.queries_run += 1
            try:
                data = gh.get(
                    "/search/code",
                    params={"q": sq.query, "per_page": max_per_query},
                    headers={"Accept": "application/vnd.github.text-match+json"},
                )
            except GitHubError as e:
                msg = f"query={sq.query!r}: {e}"
                stats.errors.append(msg)
                if not continue_on_error:
                    raise RuntimeError(msg) from e
                continue

            items = (data or {}).get("items", [])
            stats.items_seen += len(items)
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
                stats.files_scanned += 1

                findings = [
                    f
                    for f in scan_text(text, languages=languages, denylist=denylist)
                    if f.is_alert
                ]
                if findings:
                    stats.hits += 1
                    hits.append(
                        RemoteHit(
                            repo_full_name=repo,
                            html_url=html_url,
                            path=path,
                            findings=findings,
                            sha=sha,
                            search_query=sq.query,
                            query_category=sq.category,
                            query_note=sq.note,
                        )
                    )
    return hits, stats


def parse_github_repo_arg(value: str) -> str:
    value = value.strip().rstrip("/")
    m = re.match(r"https?://github\.com/([^/]+)/([^/]+)", value)
    if m:
        return f"{m.group(1)}/{m.group(2).removesuffix('.git')}"
    if value.count("/") == 1:
        return value
    raise ValueError(f"Expected owner/repo or GitHub URL, got {value!r}")
