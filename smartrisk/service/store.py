from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class JobStore:
    """Durable job state with atomic claims and restart recovery metadata."""

    def __init__(self, path: str | Path = "artifacts/jobs.sqlite3"):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._connect() as db:
            db.execute(
                """CREATE TABLE IF NOT EXISTS jobs (
                    job_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    request_json TEXT NOT NULL,
                    result_json TEXT,
                    error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    started_at TEXT,
                    progress_stage TEXT NOT NULL DEFAULT 'queued',
                    progress_percent INTEGER NOT NULL DEFAULT 0
                )"""
            )
            columns = {row[1] for row in db.execute("PRAGMA table_info(jobs)").fetchall()}
            if "attempts" not in columns:
                db.execute("ALTER TABLE jobs ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0")
            if "started_at" not in columns:
                db.execute("ALTER TABLE jobs ADD COLUMN started_at TEXT")
            if "progress_stage" not in columns:
                db.execute("ALTER TABLE jobs ADD COLUMN progress_stage TEXT NOT NULL DEFAULT 'queued'")
            if "progress_percent" not in columns:
                db.execute("ALTER TABLE jobs ADD COLUMN progress_percent INTEGER NOT NULL DEFAULT 0")

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.execute("PRAGMA busy_timeout = 30000")
        return db

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def create(self, job_id: str, request: dict[str, Any], status: str = "pending") -> dict[str, Any]:
        now = self._now()
        with self._lock, self._connect() as db:
            db.execute(
                "INSERT INTO jobs(job_id,status,request_json,created_at,updated_at,attempts,started_at) VALUES(?,?,?,?,?,?,?)",
                (job_id, status, json.dumps(request, sort_keys=True, default=str), now, now, 0, None),
            )
        return self.get(job_id)

    def claim(self, job_id: str) -> bool:
        """Atomically transition pending -> running and increment attempts."""
        now = self._now()
        with self._lock, self._connect() as db:
            cur = db.execute(
                "UPDATE jobs SET status='running', attempts=attempts+1, started_at=?, updated_at=?, progress_stage='starting', progress_percent=0 WHERE job_id=? AND status='pending'",
                (now, now, job_id),
            )
            return cur.rowcount == 1

    def update_progress(self, job_id: str, stage: str, percent: int) -> dict[str, Any]:
        now = self._now()
        percent = max(0, min(100, int(percent)))
        with self._lock, self._connect() as db:
            db.execute(
                "UPDATE jobs SET progress_stage=?, progress_percent=?, updated_at=? WHERE job_id=?",
                (str(stage)[:120], percent, now, job_id),
            )
        return self.get(job_id)

    def update(self, job_id: str, status: str, result: dict[str, Any] | None = None, error: str | None = None) -> dict[str, Any]:
        now = self._now()
        with self._lock, self._connect() as db:
            db.execute(
                "UPDATE jobs SET status=?, result_json=?, error=?, updated_at=? WHERE job_id=?",
                (status, json.dumps(result, sort_keys=True, default=str) if result is not None else None, error, now, job_id),
            )
        return self.get(job_id)

    def recover_running(self, max_age_seconds: int = 900) -> list[str]:
        """Requeue jobs left running by a crashed process.

        Recovery is conservative: only jobs older than max_age_seconds are reset.
        """
        cutoff = datetime.now(timezone.utc).timestamp() - max(1, max_age_seconds)
        recovered: list[str] = []
        with self._lock, self._connect() as db:
            rows = db.execute("SELECT job_id, updated_at FROM jobs WHERE status='running'").fetchall()
            for job_id, updated_at in rows:
                try:
                    ts = datetime.fromisoformat(updated_at).timestamp()
                except ValueError:
                    ts = 0
                if ts <= cutoff:
                    db.execute(
                        "UPDATE jobs SET status='pending', error=?, updated_at=? WHERE job_id=? AND status='running'",
                        ("recovered after stale running state", self._now(), job_id),
                    )
                    recovered.append(job_id)
        return recovered

    def list_by_status(self, status: str, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT job_id,status,request_json,result_json,error,created_at,updated_at,attempts,started_at,progress_stage,progress_percent FROM jobs WHERE status=? ORDER BY created_at LIMIT ?",
                (status, max(1, limit)),
            ).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def get(self, job_id: str) -> dict[str, Any]:
        with self._connect() as db:
            row = db.execute(
                "SELECT job_id,status,request_json,result_json,error,created_at,updated_at,attempts,started_at,progress_stage,progress_percent FROM jobs WHERE job_id=?",
                (job_id,),
            ).fetchone()
        if not row:
            raise KeyError(job_id)
        return self._row_to_dict(row)

    @staticmethod
    def _row_to_dict(row) -> dict[str, Any]:
        return {
            "job_id": row[0],
            "status": row[1],
            "request": json.loads(row[2]),
            "result": json.loads(row[3]) if row[3] else None,
            "error": row[4],
            "created_at": row[5],
            "updated_at": row[6],
            "attempts": int(row[7] or 0),
            "started_at": row[8],
            "progress_stage": row[9] if len(row) > 9 else ("complete" if row[1] in {"complete", "partial", "unknown"} else row[1]),
            "progress_percent": int(row[10] if len(row) > 10 and row[10] is not None else (100 if row[1] in {"complete", "partial", "unknown", "failed"} else 0)),
        }
