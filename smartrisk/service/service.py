from __future__ import annotations

import os
import time
import threading
import uuid
import inspect
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from typing import Any

from ..state_fork.models import HoneypotSequence, SimulationScenario
from ..unified.engine import UnifiedRiskEngine
from ..unified.models import UnifiedRequest
from ..unified.profiles import get_scan_profile
from .store import JobStore


class ScanService:
    def __init__(
        self,
        store: JobStore | None = None,
        engine: UnifiedRiskEngine | None = None,
        max_workers: int = 2,
        recover_stale_seconds: int = 900,
        auto_recover: bool = True,
    ):
        self.store = store or JobStore()
        self.engine = engine or UnifiedRiskEngine()
        self.executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="smartrisk-scan")
        self._requests: dict[str, UnifiedRequest] = {}
        self._lock = threading.Lock()
        self._metrics = {"submitted": 0, "completed": 0, "failed": 0, "recovered": 0, "cache_hits": 0, "durations_ms": []}
        # Public scans of the same token within the TTL reuse the existing job (finished or still
        # running), so a popular token costs Alchemy one scan instead of one per visitor.
        self.cache_ttl_seconds = self._env_seconds("SMARTRISK_SCAN_CACHE_SECONDS", 600)
        self._scan_cache: dict[tuple, tuple[str, float]] = {}
        if auto_recover:
            recovered = self.store.recover_running(recover_stale_seconds)
            self._metrics["recovered"] = len(recovered)
            for record in self.store.list_by_status("pending", limit=1000):
                try:
                    self.executor.submit(self._run_from_record, record)
                except Exception:
                    break

    @staticmethod
    def _env_seconds(name: str, default: int) -> int:
        try:
            return max(0, int(os.getenv(name, default)))
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _cache_key(request: UnifiedRequest) -> tuple | None:
        """Only plain token scans are shareable; custom projects/scenarios/pinned blocks never are."""
        if request.project or request.scenarios or request.honeypot or request.block_number is not None:
            return None
        if not (request.chain_id and request.token_address):
            return None
        return (str(request.chain_id), str(request.token_address).lower(), request.scan_profile, request.block_tag, request.window_blocks, request.deployer_address)

    def _cached_job(self, key: tuple) -> dict[str, Any] | None:
        with self._lock:
            entry = self._scan_cache.get(key)
        if not entry:
            return None
        job_id, created = entry
        if time.monotonic() - created > self.cache_ttl_seconds:
            return None
        try:
            job = self.store.get(job_id)
        except Exception:
            return None
        return job if job.get("status") in {"pending", "running", "complete", "partial"} else None

    def submit(self, request: UnifiedRequest, run_id: str | None = None, asynchronous: bool = True) -> dict[str, Any]:
        # An explicit run_id (embed, rerun, admin) always means "run this exact job now".
        cache_key = self._cache_key(request) if (run_id is None and asynchronous and self.cache_ttl_seconds > 0) else None
        if cache_key is not None:
            cached = self._cached_job(cache_key)
            if cached is not None:
                with self._lock:
                    self._metrics["cache_hits"] += 1
                return cached
        job_id = run_id or str(uuid.uuid4())
        if cache_key is not None:
            with self._lock:
                self._scan_cache[cache_key] = (job_id, time.monotonic())
                if len(self._scan_cache) > 2000:
                    cutoff = time.monotonic() - self.cache_ttl_seconds
                    self._scan_cache = {k: v for k, v in self._scan_cache.items() if v[1] > cutoff}
        payload = self._serialize_request(request)
        self.store.create(job_id, payload)
        with self._lock:
            self._requests[job_id] = request
            self._metrics["submitted"] += 1
        if asynchronous:
            try:
                future = self.executor.submit(self._run, job_id, request)
                future.add_done_callback(lambda completed: self._record_worker_failure(job_id, completed))
            except Exception as exc:
                self.store.update(job_id, "failed", error=f"Scan worker could not be scheduled: {exc}")
                with self._lock:
                    self._metrics["failed"] += 1
                raise
        else:
            self._run(job_id, request)
        return self.store.get(job_id)

    def _record_worker_failure(self, job_id: str, future) -> None:
        try:
            error = future.exception()
        except Exception as exc:
            error = exc
        if error is None:
            return
        self.store.update(job_id, "failed", error=f"Scan worker failed: {error}")
        with self._lock:
            self._metrics["failed"] += 1

    def rerun(self, job_id: str, asynchronous: bool = True) -> dict[str, Any]:
        with self._lock:
            request = self._requests.get(job_id)
        if request is None:
            record = self.store.get(job_id)
            request = self.deserialize_request(record["request"])
        return self.submit(request, run_id=f"{job_id}:rerun:{uuid.uuid4().hex[:8]}", asynchronous=asynchronous)

    def get(self, job_id: str) -> dict[str, Any]:
        return self.store.get(job_id)

    def metrics(self) -> dict[str, Any]:
        with self._lock:
            durations = list(self._metrics["durations_ms"])
            payload = {key: value for key, value in self._metrics.items() if key != "durations_ms"}
        payload["in_flight"] = sum(1 for status in ("pending", "running") for _ in self.store.list_by_status(status, limit=1000))
        payload["duration_ms"] = {
            "count": len(durations),
            "avg": round(sum(durations) / len(durations), 2) if durations else None,
            "max": round(max(durations), 2) if durations else None,
        }
        return payload

    def _run_from_record(self, record: dict[str, Any]) -> None:
        job_id = record["job_id"]
        request = self.deserialize_request(record["request"])
        with self._lock:
            self._requests[job_id] = request
        self._run(job_id, request)

    def _run(self, job_id: str, request: UnifiedRequest) -> None:
        if not self.store.claim(job_id):
            return
        started = time.perf_counter()
        profile = get_scan_profile(request.scan_profile)
        deadline_at = time.monotonic() + profile.stage_timeout_seconds
        def on_progress(stage: str, percent: int) -> None:
            self.store.update_progress(job_id, stage, percent)
        try:
            kwargs = {"run_id": job_id}
            try:
                params = inspect.signature(self.engine.analyze).parameters
                if "progress_callback" in params or any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()):
                    kwargs["progress_callback"] = on_progress
                if "deadline_at" in params or any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()):
                    kwargs["deadline_at"] = deadline_at
            except (TypeError, ValueError):
                pass
            report = self.engine.analyze(request, **kwargs)
            self.store.update_progress(job_id, "complete", 100)
            self.store.update(job_id, report.status, report.to_dict())
            with self._lock:
                self._metrics["completed"] += 1
        except Exception as exc:
            self.store.update_progress(job_id, "failed", 100)
            self.store.update(job_id, "failed", error=str(exc))
            with self._lock:
                self._metrics["failed"] += 1
        finally:
            elapsed_ms = (time.perf_counter() - started) * 1000
            with self._lock:
                self._metrics["durations_ms"].append(elapsed_ms)
                self._metrics["durations_ms"] = self._metrics["durations_ms"][-1000:]

    @staticmethod
    def _serialize_request(request: UnifiedRequest) -> dict[str, Any]:
        payload = asdict(request)
        if request.honeypot:
            payload["honeypot"] = asdict(request.honeypot)
        return payload

    @staticmethod
    def deserialize_request(payload: dict[str, Any]) -> UnifiedRequest:
        def scenario(item):
            return SimulationScenario(
                item["scenario_id"], item["from_address"], item["to_address"], item.get("data", "0x"), int(item.get("value_wei", 0)),
                item.get("gas_limit"), item.get("description", ""), tuple(item.get("observed_tokens", [])),
                tuple(tuple(pair) for pair in item.get("observed_allowances", [])), tuple(item.get("observed_pairs", [])),
                item.get("category", "generic"), tuple(item.get("risk_tags", [])),
            )
        scenarios = [scenario(item) for item in payload.get("scenarios", []) if isinstance(item, dict)]
        hp_payload = payload.get("honeypot")
        honeypot = None
        if isinstance(hp_payload, dict):
            honeypot = HoneypotSequence(
                hp_payload["sequence_id"], scenario(hp_payload["buy"]), scenario(hp_payload["sell"]),
                scenario(hp_payload["approve"]) if hp_payload.get("approve") else None,
                hp_payload.get("token_address"), hp_payload.get("description", ""),
            )
        return UnifiedRequest(
            project=payload.get("project"), chain_id=payload.get("chain_id"), token_address=payload.get("token_address"),
            scenarios=scenarios, honeypot=honeypot, block_tag=payload.get("block_tag", "safe"), block_number=payload.get("block_number"),
            compiler_version=payload.get("compiler_version"), window_blocks=payload.get("window_blocks", 10000),
            deployer_address=payload.get("deployer_address"), scan_profile=payload.get("scan_profile", "paid"),
        )


# Backwards-compatible helper name retained for existing integrations.
ScanService._deserialize_request = staticmethod(ScanService.deserialize_request)
