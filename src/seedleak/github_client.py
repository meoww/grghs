"""Minimal GitHub REST client with rate-limit / backoff handling.

Token is read only from GITHUB_TOKEN or GH_TOKEN environment variables.
Never hardcode or log tokens.
"""

from __future__ import annotations

import os
import time
from typing import Any

DEFAULT_API = "https://api.github.com"
USER_AGENT = "seedleak-responsible-disclosure/0.1"


class GitHubError(RuntimeError):
    def __init__(self, message: str, status: int | None = None, body: str = ""):
        super().__init__(message)
        self.status = status
        self.body = body


def get_token(explicit: str | None = None) -> str:
    token = explicit or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        raise GitHubError(
            "Missing GitHub token. Set GITHUB_TOKEN or GH_TOKEN in the environment "
            "(do not put tokens in the repo or chat)."
        )
    return token.strip()


class GitHubClient:
    def __init__(
        self,
        token: str | None = None,
        *,
        max_retries: int = 5,
        min_remaining: int = 3,
    ):
        try:
            import httpx
        except ImportError as e:
            raise GitHubError("Install httpx: pip install 'seedleak[github]'") from e

        self._httpx = httpx
        self.token = get_token(token)
        self.max_retries = max_retries
        self.min_remaining = min_remaining
        self._client = httpx.Client(
            base_url=DEFAULT_API,
            timeout=45.0,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": USER_AGENT,
            },
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> GitHubClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _sleep_for_rate_limit(self, resp: Any) -> None:
        remaining = resp.headers.get("X-RateLimit-Remaining")
        reset = resp.headers.get("X-RateLimit-Reset")
        retry_after = resp.headers.get("Retry-After")

        wait = 0.0
        if retry_after:
            try:
                wait = float(retry_after)
            except ValueError:
                wait = 10.0
        elif remaining is not None:
            try:
                rem = int(remaining)
            except ValueError:
                rem = 999
            if rem <= self.min_remaining and reset:
                try:
                    wait = max(0.0, int(reset) - time.time() + 1)
                except ValueError:
                    wait = 5.0
        if wait > 0:
            # Cap sleep to avoid multi-hour blocks in interactive CLI.
            time.sleep(min(wait, 120.0))

    def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        last_err: Exception | None = None
        for attempt in range(self.max_retries):
            resp = self._client.request(
                method, path, params=params, json=json, headers=headers
            )
            self._sleep_for_rate_limit(resp)

            if resp.status_code in (403, 429) and (
                "rate limit" in resp.text.lower()
                or resp.status_code == 429
                or resp.headers.get("X-RateLimit-Remaining") == "0"
            ):
                last_err = GitHubError(
                    f"Rate limited ({resp.status_code})",
                    status=resp.status_code,
                    body=resp.text[:300],
                )
                time.sleep(min(2 ** attempt * 2, 60))
                continue

            if resp.status_code >= 400:
                raise GitHubError(
                    f"GitHub API {method} {path} → {resp.status_code}: {resp.text[:400]}",
                    status=resp.status_code,
                    body=resp.text[:400],
                )
            if resp.status_code == 204 or not resp.content:
                return None
            return resp.json()

        raise last_err or GitHubError("GitHub request failed after retries")

    def get(self, path: str, **kwargs: Any) -> Any:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> Any:
        return self.request("POST", path, **kwargs)

    def whoami(self) -> dict[str, Any]:
        data = self.get("/user")
        return data if isinstance(data, dict) else {}
