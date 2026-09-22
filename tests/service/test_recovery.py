import sqlite3
from datetime import datetime, timedelta, timezone

from smartrisk.service.store import JobStore
from smartrisk.service.service import ScanService
from smartrisk.unified.models import UnifiedRequest


class FakeReport:
    status = "unknown"
    def to_dict(self):
        return {"status": self.status}


class FakeEngine:
    def analyze(self, request, run_id=None):
        return FakeReport()


def test_store_claim_is_atomic(tmp_path):
    store = JobStore(tmp_path / "jobs.sqlite3")
    store.create("job", {})
    assert store.claim("job") is True
    assert store.claim("job") is False
    assert store.get("job")["attempts"] == 1


def test_recover_stale_running_job(tmp_path):
    store = JobStore(tmp_path / "jobs.sqlite3")
    store.create("job", {}, status="running")
    stale = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    with sqlite3.connect(tmp_path / "jobs.sqlite3") as db:
        db.execute("UPDATE jobs SET updated_at=?, started_at=? WHERE job_id=?", (stale, stale, "job"))
    recovered = store.recover_running(60)
    assert recovered == ["job"]
    assert store.get("job")["status"] == "pending"


def test_service_metrics_and_sync_execution(tmp_path):
    service = ScanService(JobStore(tmp_path / "jobs.sqlite3"), FakeEngine(), max_workers=1, auto_recover=False)
    service.submit(UnifiedRequest(), run_id="job", asynchronous=False)
    metrics = service.metrics()
    assert metrics["completed"] == 1
    assert metrics["duration_ms"]["count"] == 1


def test_service_resumes_pending_jobs_from_store(tmp_path):
    store = JobStore(tmp_path / "jobs.sqlite3")
    store.create("pending-job", {})
    service = ScanService(store, FakeEngine(), max_workers=1, auto_recover=True)
    # The submitted recovery work is allowed to run synchronously through a fresh call.
    import time
    deadline = time.time() + 2
    while time.time() < deadline and store.get("pending-job")["status"] not in {"unknown", "failed", "complete", "partial"}:
        time.sleep(0.01)
    assert store.get("pending-job")["status"] == "unknown"
