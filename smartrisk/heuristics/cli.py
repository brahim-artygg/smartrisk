from __future__ import annotations

import argparse
import json
from pathlib import Path

from .engine import HeuristicsEngine


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="smartrisk-score", description="SmartRisk Alchemy + Dexscreener heuristics scoring")
    parser.add_argument("chain_id", help="Alchemy/Dexscreener chain id, e.g. ethereum")
    parser.add_argument("token_address")
    parser.add_argument("--output", "-o", type=Path)
    parser.add_argument("--run-id")
    parser.add_argument("--block-tag", choices=["safe", "finalized", "latest"], default="safe")
    parser.add_argument("--block-number", type=int)
    parser.add_argument("--window-blocks", type=int, default=10_000)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = HeuristicsEngine().analyze(
        args.chain_id,
        args.token_address,
        run_id=args.run_id,
        block_tag=args.block_tag,
        block_number=args.block_number,
        window_blocks=args.window_blocks,
    )
    payload = result.to_json()
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)
    return 0 if result.status in {"complete", "partial", "unknown"} else 1
