from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from ..state_fork.cli import _load_honeypot, _load_scenarios
from .engine import UnifiedRiskEngine
from .models import UnifiedRequest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="smartrisk", description="SmartRisk Unified Risk Engine")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="run static, fork and heuristics engines")
    scan.add_argument("--config", type=Path, help="JSON scan configuration")
    scan.add_argument("--project", help="Solidity project or source file")
    scan.add_argument("--chain-id")
    scan.add_argument("--token-address")
    scan.add_argument("--scenarios", type=Path, help="scenario JSON file")
    scan.add_argument("--honeypot", type=Path, help="buy/approve/sell sequence JSON file")
    scan.add_argument("--output", "-o", type=Path)
    scan.add_argument("--run-id")
    scan.add_argument("--block-tag", choices=["safe", "finalized", "latest"], default="safe")
    scan.add_argument("--block-number", type=int)
    scan.add_argument("--compiler-version")
    scan.add_argument("--window-blocks", type=int, default=10_000)
    scan.add_argument("--deployer-address")
    serve = subparsers.add_parser("serve", help="run local scan API")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8787)
    return parser


def _config(path: Path | None) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8")) if path else {}


def _request(args: argparse.Namespace) -> UnifiedRequest:
    payload = _config(args.config)
    project = args.project or payload.get("project")
    chain_id = args.chain_id or payload.get("chain_id")
    token_address = args.token_address or payload.get("token_address")
    scenarios_path = args.scenarios or (Path(payload["scenarios"]) if payload.get("scenarios") else None)
    honeypot_path = args.honeypot or (Path(payload["honeypot"]) if payload.get("honeypot") else None)
    return UnifiedRequest(
        project=project,
        chain_id=chain_id,
        token_address=token_address,
        scenarios=_load_scenarios(scenarios_path) if scenarios_path else [],
        honeypot=_load_honeypot(honeypot_path) if honeypot_path else None,
        block_tag=args.block_tag if args.block_tag != "safe" or "block_tag" not in payload else payload["block_tag"],
        block_number=args.block_number if args.block_number is not None else payload.get("block_number"),
        compiler_version=args.compiler_version or payload.get("compiler_version"),
        window_blocks=args.window_blocks if args.window_blocks != 10_000 or "window_blocks" not in payload else payload["window_blocks"],
        deployer_address=args.deployer_address or payload.get("deployer_address"),
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "serve":
        from ..service.http import serve
        serve(args.host, args.port).serve_forever()
        return 0
    result = UnifiedRiskEngine().analyze(_request(args), run_id=args.run_id)
    payload = result.to_json()
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)
    return 0 if result.status in {"complete", "partial", "unknown"} else 1
