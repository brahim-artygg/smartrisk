import time

from smartrisk.service.service import ScanService
from smartrisk.service.store import JobStore
from smartrisk.unified.models import UnifiedRequest


class _Report:
    status = "complete"

    def to_dict(self):
        return {"run_id": "r", "status": "complete", "verdict": {"code": "X"}, "risk": {}}


class _CountingEngine:
    def __init__(self):
        self.calls = 0

    def analyze(self, request, run_id=None):
        self.calls += 1
        return _Report()


def _service(tmp_path, ttl="600"):
    engine = _CountingEngine()
    service = ScanService(JobStore(tmp_path / "db.sqlite3"), engine, max_workers=1, auto_recover=False)
    service.cache_ttl_seconds = int(ttl)
    return service, engine


def _wait(service, job_id):
    end = time.time() + 3
    while time.time() < end:
        if service.get(job_id)["status"] in {"complete", "failed"}:
            return
        time.sleep(0.02)


def test_repeat_public_scan_reuses_existing_job(tmp_path):
    service, engine = _service(tmp_path)
    req = lambda: UnifiedRequest(chain_id="1", token_address="0x" + "A" * 40, scan_profile="free")
    first = service.submit(req())
    _wait(service, first["job_id"])
    second = service.submit(UnifiedRequest(chain_id="1", token_address="0x" + "a" * 40, scan_profile="free"))
    service.executor.shutdown(wait=True)
    assert second["job_id"] == first["job_id"]     # case-insensitive address, same job
    assert engine.calls == 1                        # Alchemy was hit once


def test_explicit_run_id_and_custom_projects_bypass_cache(tmp_path):
    service, engine = _service(tmp_path)
    a = service.submit(UnifiedRequest(chain_id="1", token_address="0x" + "b" * 40, scan_profile="free"))
    b = service.submit(UnifiedRequest(chain_id="1", token_address="0x" + "b" * 40, scan_profile="free"), run_id="embed_x")
    c = service.submit(UnifiedRequest(project="p.sol", chain_id="1", token_address="0x" + "b" * 40, scan_profile="free"))
    service.executor.shutdown(wait=True)
    assert len({a["job_id"], b["job_id"], c["job_id"]}) == 3
