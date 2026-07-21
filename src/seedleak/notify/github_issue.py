"""GitHub notifications: private vulnerability report preferred, issue fallback."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from seedleak.notify.templates import issue_body, issue_title, private_report_body, private_report_summary
from seedleak.storage.db import Case


class NotifyChannel(str, Enum):
    AUTO = "auto"
    PRIVATE = "private"
    ISSUE = "issue"
    DRAFT = "draft"


@dataclass
class NotifyResult:
    ok: bool
    dry_run: bool
    channel: str
    message: str
    url: str | None = None


def _parse_owner_repo(source_path: str) -> tuple[str, str] | None:
    s = source_path.strip().rstrip("/")
    if s.startswith("https://github.com/"):
        parts = s.removeprefix("https://github.com/").split("/")
        if len(parts) >= 2:
            return parts[0], parts[1].removesuffix(".git")
    if s.startswith("git@github.com:"):
        parts = s.removeprefix("git@github.com:").split("/")
        if len(parts) >= 2:
            return parts[0], parts[1].removesuffix(".git")
    if s.count("/") == 1 and " " not in s and not s.startswith("/"):
        owner, repo = s.split("/", 1)
        if owner and repo:
            return owner, repo.removesuffix(".git")
    return None


def private_reporting_enabled(owner: str, repo: str, token: str | None = None) -> bool:
    from seedleak.github_client import GitHubClient, GitHubError

    try:
        with GitHubClient(token) as gh:
            data = gh.get(f"/repos/{owner}/{repo}/private-vulnerability-reporting")
        return bool(data and data.get("enabled"))
    except GitHubError:
        return False


def notify_case(
    case: Case,
    *,
    channel: NotifyChannel | str = NotifyChannel.AUTO,
    token: str | None = None,
    dry_run: bool = True,
) -> NotifyResult:
    """Notify repository maintainers. Default dry_run=True (safe)."""
    if isinstance(channel, str):
        channel = NotifyChannel(channel)

    parsed = _parse_owner_repo(case.source_path)
    if not parsed:
        return NotifyResult(
            ok=False,
            dry_run=dry_run,
            channel=channel.value,
            message=f"Cannot parse GitHub owner/repo from {case.source_path!r}",
        )
    owner, repo = parsed

    if channel == NotifyChannel.DRAFT or dry_run:
        plan = _plan_channel(owner, repo, channel, token=token, probe=not dry_run)
        return NotifyResult(
            ok=True,
            dry_run=True,
            channel=plan,
            message=(
                f"Would notify {owner}/{repo} via {plan}: "
                f"{issue_title(case) if plan == 'issue' else private_report_summary(case)}"
            ),
        )

    # Live paths
    if channel == NotifyChannel.AUTO:
        if private_reporting_enabled(owner, repo, token=token):
            result = _send_private(owner, repo, case, token=token)
            if result.ok:
                return result
            # Fall through to public issue only if private failed as unavailable
        return _send_issue(owner, repo, case, token=token)

    if channel == NotifyChannel.PRIVATE:
        return _send_private(owner, repo, case, token=token)

    return _send_issue(owner, repo, case, token=token)


def _plan_channel(
    owner: str,
    repo: str,
    channel: NotifyChannel,
    *,
    token: str | None,
    probe: bool,
) -> str:
    if channel == NotifyChannel.ISSUE:
        return "issue"
    if channel == NotifyChannel.PRIVATE:
        return "private"
    if channel == NotifyChannel.DRAFT:
        return "draft"
    # auto
    if probe and token:
        if private_reporting_enabled(owner, repo, token=token):
            return "private"
        return "issue"
    return "auto(private→issue)"


def _send_private(
    owner: str,
    repo: str,
    case: Case,
    *,
    token: str | None,
) -> NotifyResult:
    from seedleak.github_client import GitHubClient, GitHubError

    body = {
        "summary": private_report_summary(case),
        "description": private_report_body(case),
        "severity": "critical",
        "vulnerabilities": [
            {
                "package": {"ecosystem": "other", "name": "cryptocurrency-wallet-seed"},
                "vulnerable_version_range": None,
                "patched_versions": None,
                "vulnerable_functions": None,
            }
        ],
        "cwe_ids": ["CWE-312", "CWE-540"],  # cleartext storage / inclusion of sensitive info
    }
    try:
        with GitHubClient(token) as gh:
            data = gh.post(f"/repos/{owner}/{repo}/security-advisories/reports", json=body)
    except GitHubError as e:
        return NotifyResult(
            ok=False,
            dry_run=False,
            channel="private",
            message=str(e),
        )
    url = (data or {}).get("html_url")
    return NotifyResult(
        ok=True,
        dry_run=False,
        channel="private",
        message=f"Private report submitted for {owner}/{repo}",
        url=url,
    )


def _send_issue(
    owner: str,
    repo: str,
    case: Case,
    *,
    token: str | None,
) -> NotifyResult:
    from seedleak.github_client import GitHubClient, GitHubError

    payload = {"title": issue_title(case), "body": issue_body(case)}
    try:
        with GitHubClient(token) as gh:
            data = gh.post(f"/repos/{owner}/{repo}/issues", json=payload)
    except GitHubError as e:
        return NotifyResult(
            ok=False,
            dry_run=False,
            channel="issue",
            message=str(e),
        )
    url = (data or {}).get("html_url")
    num = (data or {}).get("number")
    return NotifyResult(
        ok=True,
        dry_run=False,
        channel="issue",
        message=f"Opened issue #{num} on {owner}/{repo}",
        url=url,
    )


# Back-compat wrapper
def notify_github_issue(
    case: Case,
    *,
    token: str | None = None,
    dry_run: bool = True,
) -> NotifyResult:
    return notify_case(case, channel=NotifyChannel.ISSUE, token=token, dry_run=dry_run)
