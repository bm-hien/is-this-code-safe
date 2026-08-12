"""Command line interface for MalIR."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .benchmark import benchmark_scan
from .data import load_examples
from .model import OnlineLogisticModel
from .scanner import ScanLimits, Scanner

EXIT_THRESHOLDS = {
    "never": 101.0,
    "review": 25.0,
    "suspicious": 50.0,
    "high-risk": 75.0,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="itcs",
        description="Static, CPU-first Python malware behavior analysis",
    )
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="scan a Python file or tree")
    scan.add_argument("path")
    scan.add_argument("--json", action="store_true", dest="as_json")
    models = scan.add_mutually_exclusive_group()
    models.add_argument("--model", help="sparse model checkpoint")
    models.add_argument("--micro-model", help="µMal PyTorch checkpoint")
    scan.add_argument("--threads", type=int, default=2)
    scan.add_argument("--max-files", type=int, default=10_000)
    scan.add_argument("--max-file-bytes", type=int, default=1_000_000)
    scan.add_argument(
        "--fail-on",
        choices=EXIT_THRESHOLDS,
        default="never",
        help="return exit code 2 at or above this risk level",
    )

    extract = commands.add_parser("extract", help="print MalIR as JSON")
    extract.add_argument("path")
    extract.add_argument("--compact", action="store_true")

    sparse = commands.add_parser(
        "train-sparse",
        help="train the dependency-free online classifier",
    )
    sparse.add_argument("dataset", help="JSONL dataset")
    sparse.add_argument("-o", "--output", required=True)
    sparse.add_argument("--epochs", type=int, default=15)
    sparse.add_argument("--dimensions", type=int, default=1 << 16)
    sparse.add_argument("--learning-rate", type=float, default=0.15)

    micro = commands.add_parser(
        "train-micro",
        help="train µMal with classification and masked-token losses",
    )
    micro.add_argument("dataset", help="JSONL dataset")
    micro.add_argument("-o", "--output", required=True)
    micro.add_argument("--epochs", type=int, default=5)
    micro.add_argument("--batch-size", type=int, default=16)
    micro.add_argument("--d-model", type=int, default=96)
    micro.add_argument("--layers", type=int, default=2)
    micro.add_argument("--heads", type=int, default=4)
    micro.add_argument("--ffn-dim", type=int, default=192)
    micro.add_argument("--max-length", type=int, default=256)
    micro.add_argument("--vocab-size", type=int, default=4096)
    micro.add_argument("--learning-rate", type=float, default=1e-3)
    micro.add_argument("--mlm-weight", type=float, default=0.05)
    micro.add_argument("--threads", type=int, default=2)

    bench = commands.add_parser("benchmark", help="benchmark static scanning")
    bench.add_argument("path")
    bench.add_argument("--repeats", type=int, default=20)
    bench.add_argument("--json", action="store_true", dest="as_json")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            return _scan(args)
        if args.command == "extract":
            return _extract(args)
        if args.command == "train-sparse":
            return _train_sparse(args)
        if args.command == "train-micro":
            return _train_micro(args)
        if args.command == "benchmark":
            return _benchmark(args)
    except (OSError, ValueError, RuntimeError) as error:
        parser.error(str(error))
    return 1


def _scanner_from_args(args: argparse.Namespace) -> Scanner:
    model = None
    if args.model:
        model = OnlineLogisticModel.load(args.model)
    elif args.micro_model:
        try:
            from .microlm import MicroMalPredictor
        except ImportError as error:
            raise RuntimeError(
                "µMal needs the optional 'micro' dependencies"
            ) from error
        model = MicroMalPredictor.load(args.micro_model, args.threads)
    limits = ScanLimits(
        max_files=args.max_files,
        max_file_bytes=args.max_file_bytes,
    )
    return Scanner(model=model, limits=limits)


def _scan(args: argparse.Namespace) -> int:
    report = _scanner_from_args(args).scan(args.path)
    if args.as_json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        _print_report(report)
    threshold = EXIT_THRESHOLDS[args.fail_on]
    return 2 if report.risk_score >= threshold else 0


def _extract(args: argparse.Namespace) -> int:
    report = Scanner().scan(args.path)
    payload = {
        "schema": "malir.ir.v1",
        "target": report.target,
        "files": [item.to_dict() for item in report.files],
        "warnings": report.warnings,
    }
    indent = None if args.compact else 2
    print(json.dumps(payload, indent=indent, sort_keys=True))
    return 0


def _train_sparse(args: argparse.Namespace) -> int:
    examples = load_examples(args.dataset)
    model = OnlineLogisticModel(
        dimensions=args.dimensions,
        learning_rate=args.learning_rate,
    )
    losses = model.partial_fit(examples, epochs=args.epochs)
    predictions = [int(model.predict_proba(tokens) >= 0.5) for tokens, _ in examples]
    correct = sum(
        prediction == label
        for prediction, (_, label) in zip(predictions, examples, strict=True)
    )
    model.save(args.output)
    result = {
        "model": "sparse-logistic",
        "output": str(Path(args.output).resolve()),
        "examples": len(examples),
        "epochs": args.epochs,
        "active_weights": len(model.weights),
        "final_loss": round(losses[-1], 6),
        "training_accuracy": round(correct / len(examples), 6),
        "bytes": Path(args.output).stat().st_size,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _train_micro(args: argparse.Namespace) -> int:
    try:
        from .microlm import MicroConfig, train_micro
    except ImportError as error:
        raise RuntimeError("train-micro needs: pip install -e '.[micro]'") from error
    examples = load_examples(args.dataset)
    config = MicroConfig(
        vocab_size=args.vocab_size,
        max_length=args.max_length,
        d_model=args.d_model,
        n_heads=args.heads,
        n_layers=args.layers,
        ffn_dim=args.ffn_dim,
    )
    result = train_micro(
        examples,
        args.output,
        config=config,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.learning_rate,
        mlm_weight=args.mlm_weight,
        threads=args.threads,
    )
    result["model"] = "micro-transformer"
    result["output"] = str(Path(args.output).resolve())
    result["bytes"] = Path(args.output).stat().st_size
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _benchmark(args: argparse.Namespace) -> int:
    result = benchmark_scan(args.path, repeats=args.repeats)
    if args.as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(
            f"{result['files_per_run']} files | "
            f"median {result['median_ms']:.2f} ms | "
            f"p95 {result['p95_ms']:.2f} ms | "
            f"{result['files_per_second'] or 0:.1f} files/s | "
            f"peak {result['tracemalloc_peak_bytes'] / 1024:.1f} KiB"
        )
    return 0


def _print_report(report) -> None:
    print(
        f"{report.verdict} | risk {report.risk_score:.1f}/100 | "
        f"{report.files_scanned} Python files | {report.elapsed_ms:.1f} ms"
    )
    model_state = (
        f"{report.model_probability:.3f}"
        if report.model_probability is not None
        else "not needed"
    )
    print(f"rule score {report.rule_score:.1f} | model {model_state}")
    for item in report.evidence:
        motif = f" [{item.motif}]" if item.motif else ""
        print(
            f"- {item.path}:{item.line} {item.op}{motif} "
            f"+{item.score:.0f}: {item.reason}"
        )
    for warning in report.warnings:
        print(f"! {warning}", file=sys.stderr)
