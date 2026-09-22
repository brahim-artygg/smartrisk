from __future__ import annotations

import argparse
import json
from pathlib import Path

from .custom_detectors import CustomDetectorRunner


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("project")
    args = parser.parse_args()
    findings, evidence, diagnostics = CustomDetectorRunner().run(Path(args.project))
    print(json.dumps({
        "findings": [item.__dict__ | {"source_location": item.source_location.__dict__ if item.source_location else None} for item in findings],
        "evidence": [item.__dict__ for item in evidence],
        "diagnostics": diagnostics,
    }, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
