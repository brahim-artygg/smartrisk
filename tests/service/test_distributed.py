from smartrisk.service.distributed import DistributedScanWorker, RedisJobMessage


class FakeQueue:
    def __init__(self):
        self.records = {"job": {"request": {"x": 1}, "attempts": 0}}
        self.acked = []
        self.last_claim_idle_ms = None
    def consume(self, consumer, block_ms=1000, count=1, claim_idle_ms=900_000):
        self.last_claim_idle_ms = claim_idle_ms
        return [RedisJobMessage("1-0", "job", 1)]
    def mark_running(self, job_id):
        record = self.records[job_id]
        record["attempts"] += 1
        return record
    def update(self, job_id, status, result=None, error=None):
        self.records[job_id].update(status=status, result=result, error=error)
        return self.records[job_id]
    def ack(self, stream_id):
        self.acked.append(stream_id)


class Report:
    status = "complete"
    def to_dict(self):
        return {"status": self.status}


class Engine:
    def analyze(self, request, run_id=None):
        assert run_id == "job"
        return Report()


def test_distributed_worker_processes_and_acks():
    queue = FakeQueue()
    worker = DistributedScanWorker(queue, lambda: Engine(), lambda payload: payload)
    assert worker.claim_idle_ms == 900_000
    assert worker.run_once() == 1
    assert queue.last_claim_idle_ms == 900_000
    assert queue.records["job"]["status"] == "complete"
    assert queue.acked == ["1-0"]
    assert worker.processed == 1


class FakeRedis:
    def __init__(self):
        self.store = {}
        self.stream = []
        self.groups = set()
        self.acked = []
    def xgroup_create(self, stream, group, id="$", mkstream=False):
        if group in self.groups:
            raise RuntimeError("BUSYGROUP Consumer Group name already exists")
        self.groups.add(group)
    def set(self, key, value): self.store[key] = value
    def get(self, key): return self.store.get(key)
    def xadd(self, stream, fields):
        entry = f"{len(self.stream)+1}-0"
        self.stream.append((entry, fields))
        return entry
    def xlen(self, stream): return len(self.stream)
    def xreadgroup(self, group, consumer, streams, count=1, block=1000):
        entries = self.stream[-count:]
        return [(self.stream_name(streams), entries)] if entries else []
    def xautoclaim(self, *args, **kwargs): return ["0-0", []]
    def xack(self, stream, group, stream_id): self.acked.append(stream_id)
    @staticmethod
    def stream_name(streams): return next(iter(streams.keys()))


def test_redis_stream_job_store_enqueue_and_consume():
    from smartrisk.service.distributed import RedisStreamJobStore
    fake = FakeRedis()
    store = RedisStreamJobStore(fake, stream="jobs", group="workers")
    record = store.create("j1", {"request": 1})
    assert record["job_id"] == "j1"
    messages = store.consume("w1", block_ms=1)
    assert messages[0].job_id == "j1"
    store.ack(messages[0].stream_id)
    assert fake.acked == [record["stream_id"]]


def test_isolated_scan_runner_returns_serialized_report():
    from smartrisk.service.distributed import IsolatedScanRunner
    result = IsolatedScanRunner(timeout_seconds=10).run({}, "isolated-test")
    assert result["status"] in {"complete", "failed"}
    if result["status"] == "complete":
        assert result["report"]["run_id"] == "isolated-test"
