from __future__ import annotations

import argparse

from .distributed import DistributedScanWorker, RedisStreamJobStore
from .service import ScanService
from ..unified.engine import UnifiedRiskEngine


def main() -> None:
    parser = argparse.ArgumentParser(description="SmartRisk distributed scan worker")
    parser.add_argument("--redis-url", default=None)
    parser.add_argument("--stream", default="smartrisk:jobs")
    parser.add_argument("--group", default="smartrisk-workers")
    parser.add_argument("--block-ms", type=int, default=1000)
    parser.add_argument("--claim-idle-ms", type=int, default=900_000, help="idle time before a stuck Redis job is reclaimed")
    parser.add_argument("--max-attempts", type=int, default=3)
    args = parser.parse_args()
    queue = RedisStreamJobStore.from_url(args.redis_url, stream=args.stream, group=args.group)
    worker = DistributedScanWorker(
        queue,
        engine_factory=UnifiedRiskEngine,
        request_decoder=ScanService.deserialize_request,
        max_attempts=args.max_attempts,
        claim_idle_ms=args.claim_idle_ms,
    )
    while True:
        worker.run_once(block_ms=args.block_ms)


if __name__ == "__main__":
    main()
