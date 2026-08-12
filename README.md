# Is this code safe? (ITCS)

[![CI](https://github.com/bm-hien/is-this-code-safe/actions/workflows/ci.yml/badge.svg)](https://github.com/bm-hien/is-this-code-safe/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**ITCS** is a CPU-first research prototype for static malware-behavior analysis
of Python source code. It converts source into a compact Malware Intermediate
Representation (MalIR), preserves line-level evidence, and spends model compute
only on uncertain cases.

> This is not a VirusTotal replacement yet, and it is not an antivirus verdict.
> It is a local source-analysis layer for triage and research. Never install,
> import, or execute an untrusted package just to scan it.

## Why this architecture

Large code models are costly, raw source contains much irrelevant syntax, and a
single opaque score is difficult to audit. ITCS instead uses this cascade:

~~~mermaid
flowchart TD
    A["Python source"] --> B["Bounded AST parser"]
    B --> C["MalIR events"]
    C --> D["Behavior motifs"]
    C --> E["7 KB sparse model"]
    D --> F["Evidence score"]
    E --> G["Uncertainty gate"]
    F --> G
    G -->|uncertain only| H["µMal 0.57M"]
    G -->|clear case| I["Evidence report"]
    H --> I
~~~

Behavior sequences alone are not a new idea. The research hypothesis here is
the combination of an evidence-carrying IR, bounded extraction, conditional
compute, and a tiny domain language model trained from scratch.

## Current capabilities

- Parses Python with ast; inspected files are never imported or executed.
- Resolves common import aliases and emits source/transform/sink events.
- Detects local proximity motifs such as credential-to-network,
  download-to-execution, encoded execution, and install-time execution.
- Produces deterministic JSON with file hashes, line evidence, and warnings.
- Includes a dependency-free hashed online logistic classifier.
- Includes µMal: a 567,746-parameter Transformer with joint classification and
  masked-behavior-token objectives. It downloads no foundation-model weights.
- Skips symlinks and common dependency/build folders; bounds files, bytes, and
  emitted events.
- Provides training, evaluation, lint, tests, and reproducible CPU benchmarks.

## Quick start

Core scanning needs only Python 3.11 or newer:

~~~bash
cd /workspaces/codespaces-blank
make bootstrap
.venv/bin/itcs scan tests/fixtures/suspicious/static_exfil.py
.venv/bin/itcs extract tests/fixtures/benign
~~~

The current Codespace is already bootstrapped. Use make bootstrap-locked to
reproduce its Linux x86-64 / CPython 3.12 dependency snapshot. For a fresh
CPU-only setup with µMal:

~~~bash
make bootstrap-micro
.venv/bin/itcs train-micro examples/synthetic_train.jsonl \
  -o artifacts/micro.pt --epochs 20 --batch-size 8 --threads 2
.venv/bin/itcs scan path/to/source \
  --micro-model artifacts/micro.pt --threads 2
~~~

Train the much smaller online model:

~~~bash
.venv/bin/itcs train-sparse examples/synthetic_train.jsonl \
  -o artifacts/sparse.model.json --epochs 40
.venv/bin/itcs scan path/to/source \
  --model artifacts/sparse.model.json
~~~

The model is invoked only when the rule score is between 20 and 80 by default.
Clear low-signal and high-risk cases avoid that cost.

## CLI

~~~text
itcs scan PATH [--json] [--model FILE | --micro-model FILE]
itcs extract PATH [--compact]
itcs train-sparse DATASET -o MODEL
itcs train-micro DATASET -o CHECKPOINT
itcs benchmark PATH [--repeats N]
~~~

Use --fail-on review, suspicious, or high-risk to make scan return exit code 2
at a selected CI threshold. The default never changes the exit code based on a
heuristic result.

JSONL training rows accept one of these forms:

~~~json
{"label": 1, "tokens": ["P:runtime|C:source|O:ENV_READ|T:token"]}
{"label": "benign", "source": "from pathlib import Path\n"}
{"label": 0, "path": "relative/sample.py"}
~~~

The bundled 32-row dataset is deliberately synthetic and exists only for smoke
training. Do not report its training accuracy as real-world efficacy.

## Measured on the target Codespace

Environment: 2 vCPU, about 8 GB RAM, Python 3.12.1, Linux x86-64. Measurements
were taken on 2026-08-12.

| Component | Result |
|---|---:|
| Static AST + MalIR, 1,000 inert files | 889.23 files/s |
| Static scan latency, 1,000 files | median 1,111.24 ms; p95 1,190.57 ms |
| Python allocations during static benchmark | 2,725,883 bytes peak via tracemalloc |
| Sparse smoke checkpoint | 7,259 bytes; 258 active weights |
| Optional PyTorch training environment | 992 MB on disk; not needed by core/sparse |
| Default µMal | 567,746 parameters; 2,280,321-byte FP32 checkpoint |
| µMal single-example inference, 2 threads | median 6.49 ms; p95 12.50 ms |

The corpus benchmark uses repeated inert templates (95% ordinary and 5%
suspicious-shaped source). These numbers measure cost, not detection quality.
Use scripts/evaluate.py on a project-disjoint, time-split real dataset before
making efficacy claims.

~~~bash
.venv/bin/python scripts/benchmark_corpus.py --files 1000 --repeats 5
.venv/bin/python scripts/benchmark_micro.py artifacts/micro.pt --repeats 300
.venv/bin/python scripts/evaluate.py examples/synthetic_train.jsonl \
  --micro-model artifacts/micro.pt
~~~

## Verdict semantics

- low-signal: little evidence was found; this does not prove the code is safe.
- review: weak or ambiguous behavior deserves inspection.
- suspicious: multiple risky operations or a behavior motif was found.
- high-risk: strong or accumulated static evidence; still not a final malware
  attribution.

Each result retains the operations and source locations that created the score.
Motifs are bounded proximity evidence, not exact interprocedural data flow.

## Repository map

- docs/RESEARCH.vi.md: bản nghiên cứu và roadmap tiếng Việt.
- docs/EVALUATION_PROTOCOL.md: locked leakage/metrics/CPU study protocol.
- CONTRIBUTING.md: safe contribution and research-claim rules.
- src/malir/extractor.py: safe AST extraction and alias resolution.
- src/malir/motifs.py: bounded behavior-path construction.
- src/malir/detector.py: evidence weights and uncertainty gate.
- src/malir/model.py: dependency-free online sparse classifier.
- src/malir/microlm.py: tiny Transformer and training loop.
- docs/MALIR_SPEC.md: IR contract and versioning.
- docs/RESEARCH.md: literature gap, experiments, and claim gates.
- docs/THREAT_MODEL.md: security boundary and known evasions.
- tests/fixtures: inert code that is parsed only, never imported.

## Known limits

Version 0.1 does not yet perform full data-flow or interprocedural analysis,
unpack archives, inspect native extensions, deobfuscate arbitrary strings, or
observe runtime-only behavior. It supports Python source only. See the research
plan before extending the frontend to JavaScript, Go, or Rust.

## Safe contribution rule

Tests may contain suspicious-shaped source, but test runners must only read and
parse it. Never add a test that imports, installs, launches, or contacts a
network from an untrusted sample.

Licensed under the MIT License.