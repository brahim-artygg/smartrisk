from __future__ import annotations

import argparse
import asyncio

from .core.alchemy_gateway import AlchemyGateway
from .indexer.canonical import CanonicalChain
from .indexer.sync import PollingChainIndexer
from .indexer.websocket import ChainWebSocketSubscriber, ReorgAwareRealtimeIndexer, WebSocketUnavailable
from .state_fork.alchemy_rpc import AlchemyRpcClient
from .core.networks import supported_networks


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="smartrisk-realtime", description="SmartRisk WebSocket head watcher + canonical backfill")
    parser.add_argument("--chain", choices=[profile.rpc_chain for profile in supported_networks()], default="eth-mainnet")
    parser.add_argument("--token")
    parser.add_argument("--reorg-window", type=int, default=12)
    parser.add_argument("--once", action="store_true", help="perform one canonical sync and exit")
    args = parser.parse_args(argv)

    rpc = AlchemyRpcClient(chain=args.chain)
    chain_id = rpc.get_chain_id()
    canonical = CanonicalChain(chain_id)
    indexer = PollingChainIndexer(AlchemyGateway(rpc), canonical, args.token, reorg_window=args.reorg_window)
    if args.once:
        print(indexer.sync_once().to_dict())
        return 0

    urls = rpc.websocket_urls()
    if not urls:
        raise SystemExit("no WebSocket provider URL configured; add ALCHEMY_API_KEY/ALCHEMY_WS_URL or fallback *_WS_URL")
    subscriber = ChainWebSocketSubscriber(urls)
    orchestrator = ReorgAwareRealtimeIndexer(subscriber, indexer, reorg_window=args.reorg_window)
    try:
        asyncio.run(orchestrator.run())
    except WebSocketUnavailable as exc:
        raise SystemExit(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
