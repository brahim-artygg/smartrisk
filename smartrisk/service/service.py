from __future__ import annotations

import json
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from pathlib import Path
from typing import Any

from ..state_fork.cli import _load_honeypot, _load_scenarios
from ..state_fork.models import HoneypotSequence, SimulationScenario
from ..unified.engine import UnifiedRiskEngine
from ..unified.models import UnifiedRequest
from .store import JobStore


class ScanService:
    def __init__(self, store: JobStore | None = None, engine: UnifiedRiskEngine | None = None, max_workers: int = 2):
        self.store = store or JobStore()
        self.engine = engine or UnifiedRiskEngine()
        self.executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="smartrisk-scan")
        self._requests: dict[str, UnifiedRequest] = {}
        self._lock = threading.Lock()

    def submit(self, request: UnifiedRequest, run_id: str | None = None, asynchronous: bool = True) -> dict[str, Any]:
        job_id = run_id or str(uuid.uuid4())
        payload = self._serialize_request(request)
        self.store.create(job_id, payload)
        with self._lock:
            self._requests[job_id] = request
        if asynchronous:
            self.executor.submit(self._run, job_id, request)
        else:
            self._run(job_id, request)
        return self.store.get(job_id)

    def rerun(self, job_id: str, asynchronous: bool = True) -> dict[str, Any]:
        with self._lock:
            request = self._requests.get(job_id)
        if request is None:
            record = self.store.get(job_id)
            request = self._deserialize_request(record["request"])
        return self.submit(request, run_id=f"{job_id}:rerun:{uuid.uuid4().hex[:8]}", asynchronous=asynchronous)

    def get(self, job_id: str) -> dict[str, Any]:
        return self.store.get(job_id)

    def _run(self, job_id: str, request: UnifiedRequest) -> None:
        self.store.update(job_id, "running")
        try:
            report = self.engine.analyze(request, run_id=job_id)
            self.store.update(job_id, report.status, report.to_dict())
        except Exception as exc:
            self.store.update(job_id, "failed", error=str(exc))

    @staticmethod
    def _serialize_request(request: UnifiedRequest) -> dict[str, Any]:
        payload = asdict(request)
        if request.honeypot:
            payload["honeypot"] = asdict(request.honeypot)
        return payload

    @staticmethod
    def _deserialize_request(payload: dict[str, Any]) -> UnifiedRequest:
        def scenario(item):
            return SimulationScenario(item["scenario_id"], item["from_address"], item["to_address"], item.get("data", "0x"), int(item.get("value_wei", 0)), item.get("gas_limit"), item.get("description", ""), tuple(item.get("observed_tokens", [])))
        scenarios = [scenario(item) for item in payload.get("scenarios", []) if isinstance(item, dict)]
        hp_payload = payload.get("honeypot")
        honeypot = None
        if isinstance(hp_payload, dict):
            honeypot = HoneypotSequence(hp_payload["sequence_id"], scenario(hp_payload["buy"]), scenario(hp_payload["sell"]), scenario(hp_payload["approve"]) if hp_payload.get("approve") else None, hp_payload.get("token_address"), hp_payload.get("description", ""))
        return UnifiedRequest(
            project=payload.get("project"), chain_id=payload.get("chain_id"), token_address=payload.get("token_address"),
            scenarios=scenarios, honeypot=honeypot, block_tag=payload.get("block_tag", "safe"), block_number=payload.get("block_number"),
            compiler_version=payload.get("compiler_version"), window_blocks=payload.get("window_blocks", 10000),
        )
