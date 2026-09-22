from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from .models import RawAlchemyEvidence


class SQLiteEvidenceStore:
    """Bounded durable raw-evidence store for replay/debugging."""

    def __init__(self, path: str | Path = "artifacts/evidence.sqlite3", max_rows: int = 50_000):
        self.path = str(path)
        self.max_rows = max(100, max_rows)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._connect() as db:
            db.execute(
                """CREATE TABLE IF NOT EXISTS evidence (
                    evidence_id TEXT PRIMARY KEY,
                    method TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    block_number INTEGER,
                    block_hash TEXT,
                    error TEXT
                )"""
            )
            db.execute("CREATE INDEX IF NOT EXISTS idx_evidence_method_created ON evidence(method, created_at)")

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA busy_timeout=30000")
        return db

    def put(self, evidence: RawAlchemyEvidence) -> None:
        payload = json.dumps(evidence.to_dict(), sort_keys=True, default=str)
        with self._lock, self._connect() as db:
            db.execute(
                "INSERT OR REPLACE INTO evidence(evidence_id,method,provider,request_id,payload_json,created_at,block_number,block_hash,error) VALUES(?,?,?,?,?,?,?,?,?)",
                (evidence.evidence_id, evidence.method, evidence.provider, evidence.request_id, payload, evidence.fetched_at, evidence.block_number, evidence.block_hash, evidence.error),
            )
            overflow = db.execute("SELECT COUNT(*) FROM evidence").fetchone()[0] - self.max_rows
            if overflow > 0:
                db.execute(
                    "DELETE FROM evidence WHERE evidence_id IN (SELECT evidence_id FROM evidence ORDER BY created_at LIMIT ?)",
                    (overflow,),
                )

    def get(self, evidence_id: str) -> dict[str, Any]:
        with self._connect() as db:
            row = db.execute("SELECT payload_json FROM evidence WHERE evidence_id=?", (evidence_id,)).fetchone()
        if not row:
            raise KeyError(evidence_id)
        return json.loads(row[0])

    def recent(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT payload_json FROM evidence ORDER BY created_at DESC LIMIT ?",
                (max(1, limit),),
            ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def count(self) -> int:
        with self._connect() as db:
            return int(db.execute("SELECT COUNT(*) FROM evidence").fetchone()[0])
