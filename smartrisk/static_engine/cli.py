from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engine import StaticEngine


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="smartrisk-static", description="SmartRisk static AST/IR analysis")
    parser.add_argument("project", help="Solidity project directory")
    parser.add_argument("--output", "-o", type=Path, help="Write normalized JSON report to this file")
    parser.add_argument("--run-id", help="Stable run identifier")
    parser.add_argument("--compiler-version", help="Require an installed exact solc version, e.g. 0.8.20")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = StaticEngine().analyze(
        args.project,
        run_id=args.run_id,
        compiler_version=args.compiler_version,
    )
    payload = result.to_json()
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)
    return 0 if result.status in {"complete", "unknown", "partial"} else 1
