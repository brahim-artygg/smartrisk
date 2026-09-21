from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class JobStore:
    def __init__(self, path: str | Path = "artifacts/jobs.sqlite3"):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS jobs (job_id TEXT PRIMARY KEY, status TEXT NOT NULL, request_json TEXT NOT NULL, result_json TEXT, error TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)")

    def _connect(self):
        return sqlite3.connect(self.path)

    def create(self, job_id: str, request: dict[str, Any], status: str = "pending") -> dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, self._connect() as db:
            db.execute("INSERT INTO jobs(job_id,status,request_json,created_at,updated_at) VALUES(?,?,?,?,?)", (job_id, status, json.dumps(request, sort_keys=True, default=str), now, now))
        return self.get(job_id)

    def update(self, job_id: str, status: str, result: dict[str, Any] | None = None, error: str | None = None) -> dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, self._connect() as db:
            db.execute("UPDATE jobs SET status=?, result_json=?, error=?, updated_at=? WHERE job_id=?", (status, json.dumps(result, sort_keys=True, default=str) if result is not None else None, error, now, job_id))
        return self.get(job_id)

    def get(self, job_id: str) -> dict[str, Any]:
        with self._connect() as db:
            row = db.execute("SELECT job_id,status,request_json,result_json,error,created_at,updated_at FROM jobs WHERE job_id=?", (job_id,)).fetchone()
        if not row:
            raise KeyError(job_id)
        return {"job_id": row[0], "status": row[1], "request": json.loads(row[2]), "result": json.loads(row[3]) if row[3] else None, "error": row[4], "created_at": row[5], "updated_at": row[6]}
