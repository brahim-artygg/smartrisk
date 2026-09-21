from smartrisk.service.service import ScanService
from smartrisk.service.store import JobStore
from smartrisk.unified.models import UnifiedRequest


class FakeReport:
    status = "unknown"
    def to_dict(self):
        return {"status": self.status, "risk": {"band": "unknown"}}


class FakeEngine:
    def analyze(self, request, run_id=None):
        return FakeReport()


def test_scan_service_persists_and_reruns(tmp_path):
    service = ScanService(JobStore(tmp_path / "jobs.sqlite3"), FakeEngine(), max_workers=1)
    first = service.submit(UnifiedRequest(), run_id="job-1", asynchronous=False)
    assert first["status"] == "unknown"
    second = service.rerun("job-1", asynchronous=False)
    assert second["job_id"].startswith("job-1:rerun:")
    assert service.get("job-1")["result"]["risk"]["band"] == "unknown"
