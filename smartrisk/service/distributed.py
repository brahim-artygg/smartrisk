from __future__ import annotations

import json
import os
import socket
import time
import uuid
from dataclasses import asdict, dataclass
from typing import Any, Callable


class DistributedQueueUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class RedisJobMessage:
    stream_id: str
    job_id: str
    delivery_count: int = 1


class RedisStreamJobStore:
    """Redis Streams-backed durable job store for multi-process / multi-node workers.

    Requires redis-py. Jobs use a Redis consumer group for at-least-once delivery;
    abandoned work is recovered with XAUTOCLAIM by another healthy worker.
    """

    def __init__(self, redis_client: Any, stream: str = "smartrisk:jobs", group: str = "smartrisk-workers"):
        self.redis = redis_client
        self.stream = stream
        self.group = group
        self._ensure_group()

    @classmethod
    def from_url(cls, url: str | None = None, **kwargs: Any) -> "RedisStreamJobStore":
        try:
            import redis  # type: ignore
        except ImportError as exc:
            raise DistributedQueueUnavailable("install smartrisk[distributed] to enable Redis Streams") from exc
        client = redis.Redis.from_url(url or os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0"), decode_responses=True)
        return cls(client, **kwargs)

    def _ensure_group(self) -> None:
        try:
            self.redis.xgroup_create(self.stream, self.group, id="0-0", mkstream=True)
        except Exception as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    def create(self, job_id: str, request: dict[str, Any], status: str = "pending") -> dict[str, Any]:
        now = time.time()
        payload = {
            "job_id": job_id,
            "status": status,
            "request": request,
            "result": None,
            "error": None,
            "created_at": now,
            "updated_at": now,
            "attempts": 0,
        }
        key = self._job_key(job_id)
        self.redis.set(key, json.dumps(payload, sort_keys=True, default=str))
        stream_id = self.redis.xadd(self.stream, {"job_id": job_id})
        payload["stream_id"] = stream_id
        self.redis.set(key, json.dumps(payload, sort_keys=True, default=str))
        return payload

    def get(self, job_id: str) -> dict[str, Any]:
        raw = self.redis.get(self._job_key(job_id))
        if not raw:
            raise KeyError(job_id)
        return json.loads(raw)

    def update(self, job_id: str, status: str, result: dict[str, Any] | None = None, error: str | None = None) -> dict[str, Any]:
        payload = self.get(job_id)
        payload.update({"status": status, "result": result, "error": error, "updated_at": time.time()})
        self.redis.set(self._job_key(job_id), json.dumps(payload, sort_keys=True, default=str))
        return payload

    def mark_running(self, job_id: str) -> dict[str, Any]:
        payload = self.get(job_id)
        payload["status"] = "running"
        payload["attempts"] = int(payload.get("attempts", 0)) + 1
        payload["updated_at"] = time.time()
        self.redis.set(self._job_key(job_id), json.dumps(payload, sort_keys=True, default=str))
        return payload

    def consume(self, consumer: str | None = None, block_ms: int = 1000, count: int = 1, claim_idle_ms: int = 900_000) -> list[RedisJobMessage]:
        consumer = consumer or f"worker-{socket.gethostname()}-{uuid.uuid4().hex[:8]}"
        messages: list[RedisJobMessage] = []
        try:
            claimed = self.redis.xautoclaim(self.stream, self.group, consumer, claim_idle_ms, "0-0", count=count)
            claimed_entries = claimed[1] if isinstance(claimed, (list, tuple)) and len(claimed) > 1 else []
            for stream_id, fields in claimed_entries or []:
                job_id = fields.get("job_id") if isinstance(fields, dict) else None
                if job_id:
                    messages.append(RedisJobMessage(stream_id, job_id, 2))
        except Exception as exc:
            if "unknown command" in str(exc).lower() or "unknown command 'xautoclaim'" in str(exc).lower():
                pass
            else:
                raise
        if messages:
            return messages

        response = self.redis.xreadgroup(self.group, consumer, {self.stream: ">"}, count=count, block=block_ms)
        for _, entries in response or []:
            for stream_id, fields in entries:
                job_id = fields.get("job_id") if isinstance(fields, dict) else None
                if job_id:
                    messages.append(RedisJobMessage(stream_id, job_id, 1))
        return messages

    def ack(self, stream_id: str) -> None:
        self.redis.xack(self.stream, self.group, stream_id)

    def metrics(self) -> dict[str, Any]:
        return {
            "stream": self.stream,
            "group": self.group,
            "stream_length": int(self.redis.xlen(self.stream)),
        }

    def _job_key(self, job_id: str) -> str:
        return f"smartrisk:job:{job_id}"


class DistributedScanWorker:
    def __init__(self, queue: RedisStreamJobStore, engine_factory: Callable[[], Any], request_decoder: Callable[[dict[str, Any]], Any], isolated_runner: Any | None = None, max_attempts: int = 3, claim_idle_ms: int = 900_000):
        self.queue = queue
        self.engine_factory = engine_factory
        self.request_decoder = request_decoder
        self.consumer = f"worker-{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:8]}"
        self.isolated_runner = isolated_runner
        self.max_attempts = max(1, max_attempts)
        self.claim_idle_ms = max(60_000, claim_idle_ms)
        self.processed = 0
        self.failed = 0
        self.recovered = 0

    def run_once(self, block_ms: int = 1000, count: int = 1) -> int:
        messages = self.queue.consume(self.consumer, block_ms=block_ms, count=count, claim_idle_ms=self.claim_idle_ms)
        for message in messages:
            self.process_message(message)
        return len(messages)

    def process_message(self, message: RedisJobMessage) -> None:
        record = self.queue.mark_running(message.job_id)
        try:
            if self.isolated_runner is not None:
                payload = self.isolated_runner.run(record["request"], message.job_id)
                if payload.get("status") != "complete":
                    raise RuntimeError(payload.get("error") or "isolated worker failed")
                report_payload = payload["report"]
                report_status = report_payload.get("status", "unknown")
            else:
                request = self.request_decoder(record["request"])
                engine = self.engine_factory()
                report = engine.analyze(request, run_id=message.job_id)
                report_payload = report.to_dict()
                report_status = report.status
            self.queue.update(message.job_id, report_status, report_payload)
            self.queue.ack(message.stream_id)
            self.processed += 1
        except Exception as exc:
            attempts = int(record.get("attempts", 1))
            if attempts >= self.max_attempts:
                self.queue.update(message.job_id, "failed", error=str(exc))
                self.queue.ack(message.stream_id)
                self.failed += 1
            else:
                self.queue.update(message.job_id, "pending_retry", error=str(exc))
                # Leave the PEL entry unacknowledged; XAUTOCLAIM can hand it to
                # another worker after the idle timeout.
                self.recovered += 1 if message.delivery_count > 1 else 0

    def run_forever(self, sleep_seconds: float = 0.2) -> None:
        while True:
            handled = self.run_once(block_ms=max(50, int(sleep_seconds * 1000)))
            if handled == 0:
                time.sleep(sleep_seconds)

class IsolatedScanRunner:
    """Run a complete UnifiedRiskEngine scan in a child process with OS limits.

    Network access remains available because chain/RPC reads are part of the scan;
    static tool subprocesses are separately network-isolated by CommandSandbox when
    bubblewrap is available.
    """

    def __init__(self, timeout_seconds: float = 300.0, cpu_seconds: int = 240, memory_bytes: int = 2_000_000_000):
        self.timeout_seconds = timeout_seconds
        self.cpu_seconds = cpu_seconds
        self.memory_bytes = memory_bytes

    def run(self, request_payload: dict[str, Any], run_id: str) -> dict[str, Any]:
        import multiprocessing as mp
        context = mp.get_context("spawn")
        parent, child = context.Pipe(False)
        process = context.Process(target=self._child, args=(child, request_payload, run_id, self.cpu_seconds, self.memory_bytes))
        process.start()
        child.close()
        try:
            if parent.poll(self.timeout_seconds):
                try:
                    payload = parent.recv()
                except EOFError:
                    payload = {"status": "failed", "error": "isolated child exited without a result"}
            else:
                process.terminate()
                process.join(3)
                if process.is_alive():
                    process.kill()
                    process.join(3)
                return {"status": "timeout", "error": "isolated scan exceeded wall timeout"}
        finally:
            parent.close()
        process.join(3)
        if payload.get("status") != "complete":
            return payload
        return payload

    @staticmethod
    def _child(connection: Any, request_payload: dict[str, Any], run_id: str, cpu_seconds: int, memory_bytes: int) -> None:
        try:
            if os.name == "posix":
                import resource
                resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
                resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
            from .service import ScanService
            from ..unified.engine import UnifiedRiskEngine
            request = ScanService.deserialize_request(request_payload)
            report = UnifiedRiskEngine().analyze(request, run_id=run_id)
            connection.send({"status": "complete", "report": report.to_dict()})
        except Exception as exc:
            try:
                connection.send({"status": "failed", "error": str(exc)})
            except Exception:
                pass
        finally:
            connection.close()
