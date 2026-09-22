from __future__ import annotations

import argparse
import json
from pathlib import Path

from .validation import StatisticalCalibrator


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="smartrisk-calibrate", description="Calibrate SmartRisk score thresholds from a labeled corpus")
    parser.add_argument("corpus", type=Path, help="JSON array of {sample_id, score, label}")
    parser.add_argument("--min-per-class", type=int, default=25)
    parser.add_argument("--holdout", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    records = StatisticalCalibrator.load_json(args.corpus)
    report = StatisticalCalibrator(args.min_per_class, args.holdout, args.seed).fit(records)
    text = json.dumps(report.to_dict(), indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0 if report.status in {"ready", "insufficient_data"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
