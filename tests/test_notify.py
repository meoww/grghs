from seedleak.notify.github_issue import _parse_owner_repo, notify_case
from seedleak.notify.templates import issue_body, issue_title, private_report_body
from seedleak.storage.db import Case


def _case(**kwargs) -> Case:
    base = dict(
        id=1,
        fingerprint="deadbeef" * 8,
        source_type="github",
        source_path="octocat/Hello-World",
        file_path="wallet.txt",
        commit_sha="abc123",
        word_count=12,
        context_preview="…seed=[REDACTED_MNEMONIC]…",
        status="new",
        found_at="2026-01-01T00:00:00+00:00",
        updated_at="2026-01-01T00:00:00+00:00",
        notify_attempts=0,
        last_notified_at=None,
        notes="lang=english",
    )
    base.update(kwargs)
    return Case(**base)


def test_parse_owner_repo():
    assert _parse_owner_repo("octocat/Hello-World") == ("octocat", "Hello-World")
    assert _parse_owner_repo("https://github.com/octocat/Hello-World") == (
        "octocat",
        "Hello-World",
    )


def test_issue_body_never_contains_seed_words_block():
    c = _case()
    body = issue_body(c)
    title = issue_title(c)
    assert "Security" in title
    assert "BIP39" in body
    assert "abandon abandon" not in body
    priv = private_report_body(c)
    assert "REDACTED_MNEMONIC" in priv or "fingerprint" in priv.lower()


def test_notify_dry_run():
    r = notify_case(_case(), dry_run=True)
    assert r.ok and r.dry_run
