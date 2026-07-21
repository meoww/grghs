from pathlib import Path

from seedleak.storage.db import CaseStatus, CaseStore
from seedleak.storage.fingerprint import fingerprint, load_or_create_secret


def test_fingerprint_stable(tmp_path: Path, monkeypatch):
    secret_path = tmp_path / "hmac_secret"
    monkeypatch.setenv("SEEDLEAK_HOME", str(tmp_path))
    s1 = load_or_create_secret(secret_path)
    s2 = load_or_create_secret(secret_path)
    assert s1 == s2
    a = fingerprint("word " * 12, s1)
    b = fingerprint("word " * 12, s1)
    assert a == b
    assert a != fingerprint("other phrase here", s1)


def test_case_upsert(tmp_path: Path):
    db = tmp_path / "cases.db"
    store = CaseStore(db)
    cid, created = store.upsert_finding(
        fingerprint="abc" * 10,
        source_type="file",
        source_path="/tmp/x",
        file_path="a.env",
        word_count=12,
        context_preview="…[REDACTED_MNEMONIC]…",
    )
    assert created and cid >= 1
    cid2, created2 = store.upsert_finding(
        fingerprint="abc" * 10,
        source_type="file",
        source_path="/tmp/x",
        file_path="a.env",
        word_count=12,
        context_preview="…[REDACTED_MNEMONIC]…",
    )
    assert not created2 and cid2 == cid

    store.set_status(cid, CaseStatus.REVIEWED)
    case = store.get(cid)
    assert case is not None
    assert case.status == "reviewed"
    store.mark_notified(cid, url="https://github.com/o/r/issues/1", channel="issue")
    case = store.get(cid)
    assert case is not None
    assert case.status == "notified"
    assert case.notify_attempts == 1
    assert case.notify_url and case.notify_channel == "issue"
    assert store.stats()["notified"] == 1
    out = tmp_path / "export.json"
    n = store.export_json(out)
    assert n == 1 and out.is_file()
