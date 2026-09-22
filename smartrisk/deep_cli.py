from __future__ import annotations

import argparse
import json
from pathlib import Path

from .state_fork.cli import _load_scenarios
from .state_fork.engine import StateForkEngine
from .core.foundry import FoundryDeepRunner


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="smartrisk-deep")
    sub = parser.add_subparsers(dest="command", required=True)
    symbolic = sub.add_parser("symbolic")
    symbolic.add_argument("--bytecode", required=True)
    symbolic.add_argument("--output", type=Path)
    fuzz = sub.add_parser("fuzz")
    fuzz.add_argument("scenario_file", type=Path)
    fuzz.add_argument("--iterations", type=int, default=32)
    fuzz.add_argument("--seed", type=int, default=20260921)
    fuzz.add_argument("--block-tag", choices=["safe", "finalized", "latest"], default="safe")
    fuzz.add_argument("--block-number", type=int)
    fuzz.add_argument("--output", type=Path)
    foundry = sub.add_parser("foundry")
    foundry.add_argument("project_dir", type=Path)
    foundry.add_argument("--mode", choices=["fuzz", "symbolic"], default="fuzz")
    foundry.add_argument("--match-test")
    foundry.add_argument("--fuzz-runs", type=int, default=256)
    foundry.add_argument("--network", action="store_true")
    foundry.add_argument("--output", type=Path)
    args = parser.parse_args(argv)

    engine = StateForkEngine()
    if args.command == "symbolic":
        payload = engine.analyze_symbolic(args.bytecode)
    elif args.command == "foundry":
        payload = FoundryDeepRunner().run(args.project_dir, mode=args.mode, match_test=args.match_test, fuzz_runs=args.fuzz_runs, network=args.network).to_dict()
    else:
        scenarios = _load_scenarios(args.scenario_file)
        if len(scenarios) != 1:
            raise SystemExit("fuzz requires a scenario file containing exactly one scenario")
        payload = engine.analyze_fuzz(scenarios[0], block_tag=args.block_tag, block_number=args.block_number, iterations=args.iterations, seed=args.seed)
    text = json.dumps(payload, indent=2, sort_keys=True, default=str)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0
