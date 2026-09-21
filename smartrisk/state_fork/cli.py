from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .engine import StateForkEngine
from .models import HoneypotSequence, SimulationScenario


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="smartrisk-fork", description="SmartRisk Alchemy-backed state-fork simulation")
    parser.add_argument("scenario_file", type=Path, help="JSON file containing scenarios or a honeypot sequence")
    parser.add_argument("--output", "-o", type=Path, help="Write normalized fork report to this file")
    parser.add_argument("--run-id")
    parser.add_argument("--block-tag", choices=["safe", "finalized", "latest"], default="safe")
    parser.add_argument("--block-number", type=int)
    parser.add_argument("--honeypot", action="store_true", help="Run buy -> optional approve -> sell in one fork state")
    return parser


def _scenario(item: dict[str, Any]) -> SimulationScenario:
    return SimulationScenario(
        scenario_id=item["scenario_id"],
        from_address=item["from"],
        to_address=item["to"],
        data=item.get("data", "0x"),
        value_wei=int(item.get("value_wei", 0)),
        gas_limit=item.get("gas_limit"),
        description=item.get("description", ""),
    )


def _load_scenarios(path: Path) -> list[SimulationScenario]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    items = payload if isinstance(payload, list) else payload.get("scenarios", [payload])
    return [_scenario(item) for item in items]


def _load_honeypot(path: Path) -> HoneypotSequence:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return HoneypotSequence(
        sequence_id=payload["sequence_id"],
        buy=_scenario(payload["buy"]),
        approve=_scenario(payload["approve"]) if payload.get("approve") else None,
        sell=_scenario(payload["sell"]),
        token_address=payload.get("token_address"),
        description=payload.get("description", ""),
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    engine = StateForkEngine()
    if args.honeypot:
        result = engine.analyze_honeypot(
            _load_honeypot(args.scenario_file),
            run_id=args.run_id,
            block_tag=args.block_tag,
            block_number=args.block_number,
        )
    else:
        result = engine.analyze(
            _load_scenarios(args.scenario_file),
            run_id=args.run_id,
            block_tag=args.block_tag,
            block_number=args.block_number,
        )
    payload = result.to_json()
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)
    return 0 if result.status in {"complete", "partial", "unknown"} else 1
