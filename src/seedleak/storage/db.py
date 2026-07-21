"""SQLite case store — metadata only, never plaintext mnemonics."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterator


class CaseStatus(str, Enum):
    NEW = "new"
    REVIEWED = "reviewed"
    NOTIFIED = "notified"
    FIXED = "fixed"
    IGNORED = "ignored"
    FALSE_POSITIVE = "false_positive"


SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint     TEXT NOT NULL,
    source_type     TEXT NOT NULL,
    source_path     TEXT NOT NULL,
    file_path       TEXT,
    commit_sha      TEXT,
    word_count      INTEGER NOT NULL,
    context_preview TEXT,
    status          TEXT NOT NULL DEFAULT 'new',
    found_at        TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    notify_attempts INTEGER NOT NULL DEFAULT 0,
    last_notified_at TEXT,
    notes           TEXT,
    notify_url      TEXT,
    notify_channel  TEXT,
    priority        TEXT,
    has_funds       INTEGER NOT NULL DEFAULT 0,
    eth_address     TEXT,
    btc_legacy      TEXT,
    btc_segwit      TEXT,
    balance_json    TEXT,
    UNIQUE(fingerprint, source_path, file_path)
);

CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
CREATE INDEX IF NOT EXISTS idx_cases_fp ON cases(fingerprint);
CREATE INDEX IF NOT EXISTS idx_cases_priority ON cases(priority);
CREATE INDEX IF NOT EXISTS idx_cases_funds ON cases(has_funds);
"""

_MIGRATE_COLS = {
    "notify_url": "TEXT",
    "notify_channel": "TEXT",
    "priority": "TEXT",
    "has_funds": "INTEGER NOT NULL DEFAULT 0",
    "eth_address": "TEXT",
    "btc_legacy": "TEXT",
    "btc_segwit": "TEXT",
    "balance_json": "TEXT",
}


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Case:
    id: int
    fingerprint: str
    source_type: str
    source_path: str
    file_path: str | None
    commit_sha: str | None
    word_count: int
    context_preview: str | None
    status: str
    found_at: str
    updated_at: str
    notify_attempts: int
    last_notified_at: str | None
    notes: str | None
    notify_url: str | None = None
    notify_channel: str | None = None
    priority: str | None = None
    has_funds: bool = False
    eth_address: str | None = None
    btc_legacy: str | None = None
    btc_segwit: str | None = None
    balance_json: str | None = None


class CaseStore:
    def __init__(self, db_path: Path | str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA)
            cols = {r[1] for r in conn.execute("PRAGMA table_info(cases)").fetchall()}
            for name, decl in _MIGRATE_COLS.items():
                if name not in cols:
                    conn.execute(f"ALTER TABLE cases ADD COLUMN {name} {decl}")

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def upsert_finding(
        self,
        *,
        fingerprint: str,
        source_type: str,
        source_path: str,
        file_path: str | None,
        word_count: int,
        context_preview: str | None,
        commit_sha: str | None = None,
        notes: str | None = None,
        priority: str | None = None,
        has_funds: bool = False,
        eth_address: str | None = None,
        btc_legacy: str | None = None,
        btc_segwit: str | None = None,
        balance_json: str | None = None,
    ) -> tuple[int, bool]:
        """Insert or update balance metadata on duplicate. Returns (case_id, created)."""
        now = _utcnow()
        with self.connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO cases (
                    fingerprint, source_type, source_path, file_path,
                    commit_sha, word_count, context_preview, status,
                    found_at, updated_at, notes, priority, has_funds,
                    eth_address, btc_legacy, btc_segwit, balance_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(fingerprint, source_path, file_path) DO NOTHING
                """,
                (
                    fingerprint,
                    source_type,
                    source_path,
                    file_path,
                    commit_sha,
                    word_count,
                    context_preview,
                    CaseStatus.NEW.value,
                    now,
                    now,
                    notes,
                    priority,
                    1 if has_funds else 0,
                    eth_address,
                    btc_legacy,
                    btc_segwit,
                    balance_json,
                ),
            )
            if cur.rowcount == 1:
                return int(cur.lastrowid), True

            row = conn.execute(
                """
                SELECT id FROM cases
                WHERE fingerprint = ? AND source_path = ?
                  AND (file_path IS ? OR file_path = ?)
                """,
                (fingerprint, source_path, file_path, file_path),
            ).fetchone()
            cid = int(row["id"])
            # Refresh balance metadata if we just re-checked
            if balance_json is not None or priority is not None:
                conn.execute(
                    """
                    UPDATE cases SET
                        updated_at = ?,
                        priority = COALESCE(?, priority),
                        has_funds = COALESCE(?, has_funds),
                        eth_address = COALESCE(?, eth_address),
                        btc_legacy = COALESCE(?, btc_legacy),
                        btc_segwit = COALESCE(?, btc_segwit),
                        balance_json = COALESCE(?, balance_json)
                    WHERE id = ?
                    """,
                    (
                        now,
                        priority,
                        (1 if has_funds else 0) if balance_json is not None else None,
                        eth_address,
                        btc_legacy,
                        btc_segwit,
                        balance_json,
                        cid,
                    ),
                )
            return cid, False

    def list_cases(
        self,
        status: str | None = None,
        *,
        has_funds: bool | None = None,
        limit: int = 100,
    ) -> list[Case]:
        clauses: list[str] = []
        params: list[Any] = []
        if status:
            clauses.append("status = ?")
            params.append(status)
        if has_funds is not None:
            clauses.append("has_funds = ?")
            params.append(1 if has_funds else 0)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        with self.connection() as conn:
            rows = conn.execute(
                f"SELECT * FROM cases {where} "
                f"ORDER BY has_funds DESC, id DESC LIMIT ?",
                params,
            ).fetchall()
        return [self._row_to_case(r) for r in rows]

    def get(self, case_id: int) -> Case | None:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM cases WHERE id = ?", (case_id,)
            ).fetchone()
        return self._row_to_case(row) if row else None

    def set_status(
        self,
        case_id: int,
        status: CaseStatus | str,
        notes: str | None = None,
    ) -> None:
        st = status.value if isinstance(status, CaseStatus) else status
        now = _utcnow()
        with self.connection() as conn:
            if notes is not None:
                conn.execute(
                    "UPDATE cases SET status = ?, updated_at = ?, notes = ? WHERE id = ?",
                    (st, now, notes, case_id),
                )
            else:
                conn.execute(
                    "UPDATE cases SET status = ?, updated_at = ? WHERE id = ?",
                    (st, now, case_id),
                )

    def mark_notified(
        self,
        case_id: int,
        *,
        url: str | None = None,
        channel: str | None = None,
    ) -> None:
        now = _utcnow()
        with self.connection() as conn:
            conn.execute(
                """
                UPDATE cases
                SET status = ?, updated_at = ?, last_notified_at = ?,
                    notify_attempts = notify_attempts + 1,
                    notify_url = COALESCE(?, notify_url),
                    notify_channel = COALESCE(?, notify_channel)
                WHERE id = ?
                """,
                (CaseStatus.NOTIFIED.value, now, now, url, channel, case_id),
            )

    def stats(self) -> dict[str, int]:
        with self.connection() as conn:
            rows = conn.execute(
                "SELECT status, COUNT(*) AS n FROM cases GROUP BY status"
            ).fetchall()
            total = conn.execute("SELECT COUNT(*) AS n FROM cases").fetchone()["n"]
            funds = conn.execute(
                "SELECT COUNT(*) AS n FROM cases WHERE has_funds = 1"
            ).fetchone()["n"]
        out = {r["status"]: int(r["n"]) for r in rows}
        out["total"] = int(total)
        out["has_funds"] = int(funds)
        return out

    def export_cases(
        self,
        *,
        status: str | None = None,
        limit: int = 10_000,
    ) -> list[dict[str, Any]]:
        return [asdict(c) for c in self.list_cases(status=status, limit=limit)]

    def export_json(
        self,
        path: Path | str,
        *,
        status: str | None = None,
        limit: int = 10_000,
    ) -> int:
        data = self.export_cases(status=status, limit=limit)
        Path(path).write_text(
            json.dumps(data, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return len(data)

    @staticmethod
    def _row_to_case(row: sqlite3.Row) -> Case:
        keys = set(row.keys())

        def g(name: str, default=None):
            return row[name] if name in keys else default

        return Case(
            id=row["id"],
            fingerprint=row["fingerprint"],
            source_type=row["source_type"],
            source_path=row["source_path"],
            file_path=row["file_path"],
            commit_sha=row["commit_sha"],
            word_count=row["word_count"],
            context_preview=row["context_preview"],
            status=row["status"],
            found_at=row["found_at"],
            updated_at=row["updated_at"],
            notify_attempts=row["notify_attempts"],
            last_notified_at=row["last_notified_at"],
            notes=row["notes"],
            notify_url=g("notify_url"),
            notify_channel=g("notify_channel"),
            priority=g("priority"),
            has_funds=bool(g("has_funds") or 0),
            eth_address=g("eth_address"),
            btc_legacy=g("btc_legacy"),
            btc_segwit=g("btc_segwit"),
            balance_json=g("balance_json"),
        )
