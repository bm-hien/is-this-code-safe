# Is this code safe? - ITCS

[![CI](https://github.com/bm-hien/is-this-code-safe/actions/workflows/ci.yml/badge.svg)](https://github.com/bm-hien/is-this-code-safe/actions/workflows/ci.yml)
[![GitHub Pages](https://github.com/bm-hien/is-this-code-safe/actions/workflows/pages.yml/badge.svg)](https://bm-hien.github.io/is-this-code-safe/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**ITCS** is a CPU-first research prototype for static malware-behavior analysis
of Python source code. It converts source into a compact Malware Intermediate
Representation (MalIR), preserves line-level evidence, and spends model compute
only on uncertain cases.

**[Try the browser-local GitHub Pages demo →](https://bm-hien.github.io/is-this-code-safe/)**

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
    C --> D["Candidate-gated local flow + motifs"]
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
- Tracks bounded, flow-sensitive local provenance through assignments,
  containers, transforms, comprehensions, and conservative branch joins.
- Distinguishes `dataflow:high`, `proximity:low`, and `structural:high`
  evidence; the labels are qualitative analysis tiers, not probabilities.
- Uses a cheap per-callable candidate gate, so the second AST pass runs only
  when the extracted events can form a supported source-to-sink path.
- Produces deterministic JSON with file hashes, line evidence, and warnings.
- Includes a dependency-free hashed online logistic classifier.
- Includes µMal: a 567,746-parameter Transformer with joint classification and
  masked-behavior-token objectives. It downloads no foundation-model weights.
- Ships a GitHub Pages demo with MalIR-Lite and µMal Nano, a 3,538-parameter
  behavior Transformer that runs entirely inside the browser.
- Skips symlinks and common dependency/build folders; bounds files, bytes, and
  emitted events.
- Audits metadata-only dataset manifests for artifact, group, family,
  campaign, time, and post-MalIR representation leakage.
- Evaluates locked predictions with validation-only thresholds, low-FPR power
  bounds, group bootstrap, calibration, and tie-aware risk-coverage/AURC.
- Provides training, lint, tests, and reproducible CPU benchmarks.

## Quick start

Core scanning needs only Python 3.11 or newer:

~~~bash
cd /workspaces/codespaces-blank
make bootstrap
.venv/bin/itcs tests/fixtures/suspicious/static_exfil.py
.venv/bin/itcs tests/fixtures/benign --json
~~~

A path as the first argument is shorthand for `itcs scan PATH`. Results begin
with `MALWARE-LIKE`, `NEEDS REVIEW`, or `NO MALWARE EVIDENCE` and retain the
supporting operations and line numbers. The last label means only that this
analyzer found little evidence; it is not proof of safety.

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

## Browser demo

The [GitHub Pages demo](https://bm-hien.github.io/is-this-code-safe/) accepts
pasted source or a local `.py` file. It performs all analysis in the tab and
has a Content Security Policy that disables network connections. It never
uploads, imports, or executes the inspected source.

GitHub Pages cannot run the Python AST backend, so the demo uses a documented
lexical subset named MalIR-Lite. Browser paths are explicitly labeled
`proximity:low` and receive weak motif weight; only the CLI can emit
`dataflow:high`. Uncertain cases are scored by µMal Nano: a
one-layer, two-head, 3,538-parameter behavior Transformer embedded as a 73 KB
ES module. Its bundled weights were trained from scratch on 32 synthetic smoke
rows. That makes the model architecture real and reproducible, but its output
is not a real-world efficacy claim. Use the Python CLI for AST-accurate results.
See [the browser architecture and security boundary](docs/WEB_DEMO.md).

Rebuild the embedded demo model with the optional CPU training environment:

~~~bash
.venv/bin/python scripts/train_web_model.py --epochs 500 --threads 2
node --test web/tests/*.test.mjs
~~~

## CLI

~~~text
itcs PATH [--json] [--no-dataflow] [--model FILE | --micro-model FILE]
itcs scan PATH [--json] [--no-dataflow] [--model FILE | --micro-model FILE]
itcs extract PATH [--compact] [--no-dataflow]
itcs train-sparse DATASET -o MODEL
itcs train-micro DATASET -o CHECKPOINT
itcs benchmark PATH [--repeats N] [--no-dataflow | --compare-dataflow]
itcs audit-manifest MANIFEST [--strict] [--json]
itcs evaluate-predictions PREDICTIONS [--target-fpr RATE] [--json]
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

## Leakage-aware research evaluation

The audit path reads metadata only; it never follows a sample path or opens an
archive. The bundled research manifest and predictions are synthetic examples:

~~~bash
.venv/bin/itcs audit-manifest examples/research_manifest.jsonl \
  --strict --json
.venv/bin/itcs evaluate-predictions examples/research_predictions.jsonl \
  --target-fpr 0.001 --bootstrap 2000 --seed 0 --json
~~~

The evaluator chooses a threshold on validation and applies it unchanged to
test. It reports calibration and confidence-ranking metrics separately. Even
with zero false positives, a one-sided 95% upper bound below 0.1% requires at
least 2,995 independent benign groups; the command labels smaller tests
underpowered.
See [the research data contract](docs/RESEARCH_DATA_FORMAT.md).

## Measured on the target Codespace

Environment: 2 vCPU, about 8 GB RAM, Python 3.12.1, Linux x86-64. Measurements
were taken on 2026-08-12.

| Component | Result |
|---|---:|
| Candidate-gated local flow, 1,000 inert files | 823.67 files/s |
| Local-flow scan latency, 1,000 files | median 1,193.69 ms; p95 1,331.91 ms |
| Data-flow-off ablation | median 1,159.24 ms; p95 1,272.15 ms |
| Local-flow overhead on the 95/5 synthetic mix | median +2.97%; p95 +4.70% |
| Python allocations with local flow | 2,782,985 bytes peak; +0.82% |
| Sparse smoke checkpoint | 7,259 bytes; 258 active weights |
| Optional PyTorch training environment | 992 MB on disk; not needed by core/sparse |
| Default µMal | 567,746 parameters; 2,280,321-byte FP32 checkpoint |
| Browser µMal Nano | 3,538 parameters; 72,620-byte ES module |
| µMal single-example inference, 2 threads | median 6.49 ms; p95 12.50 ms |

The corpus benchmark uses repeated inert templates (95% ordinary and 5%
suspicious-shaped source). These numbers measure cost, not detection quality.
Export predictions on a project-disjoint, time-split real dataset, audit the
manifest, and use `itcs evaluate-predictions` before making efficacy claims.

~~~bash
.venv/bin/python scripts/benchmark_corpus.py --files 1000 \
  --repeats 21 --compare-dataflow
.venv/bin/python scripts/benchmark_micro.py artifacts/micro.pt --repeats 300
# Checkpoint plumbing smoke test only; never use this line for efficacy claims.
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
`dataflow:high` means the bounded intraprocedural pass carried a value from a
supported source to the displayed sink. `proximity:low` is only a same-function
window fallback; `structural:high` needs no value flow. These categorical tiers
are not calibrated probabilities and none is whole-program proof.

## Repository map

- docs/RESEARCH.vi.md: bản nghiên cứu và roadmap tiếng Việt.
- docs/EVALUATION_PROTOCOL.md: locked leakage/metrics/CPU study protocol.
- docs/RESEARCH_DATA_FORMAT.md: manifest and prediction JSONL contracts.
- docs/WEB_DEMO.md: browser architecture, model details, and security boundary.
- CONTRIBUTING.md: safe contribution and research-claim rules.
- src/malir/extractor.py: safe AST extraction, alias resolution, and the
  per-callable data-flow candidate gate.
- src/malir/flow.py: bounded, name-independent local value provenance.
- src/malir/motifs.py: data-flow, proximity, and structural path policy.
- src/malir/detector.py: evidence weights and uncertainty gate.
- src/malir/model.py: dependency-free online sparse classifier.
- src/malir/microlm.py: tiny Transformer and training loop.
- src/malir/manifest.py: metadata audit and representation leakage checks.
- src/malir/evaluation.py: low-FPR, calibration, AURC, and group bootstrap.
- web/: dependency-free GitHub Pages analyzer and embedded µMal Nano weights.
- scripts/train_web_model.py: reproducible CPU trainer/exporter for µMal Nano.
- docs/MALIR_SPEC.md: IR contract and versioning.
- docs/RESEARCH.md: literature gap, experiments, and claim gates.
- docs/THREAT_MODEL.md: security boundary and known evasions.
- tests/fixtures: inert code that is parsed only, never imported.

## Known limits

Version 0.4 performs bounded intraprocedural value provenance, not full
interprocedural or whole-program data-flow analysis. It does not yet summarize
function calls, track object attributes or mutation precisely, unpack archives,
inspect native extensions, deobfuscate arbitrary strings, or observe
runtime-only behavior. It supports Python source only. See the research plan
before extending the frontend to JavaScript, Go, or Rust.

## Safe contribution rule

Tests may contain suspicious-shaped source, but test runners must only read and
parse it. Never add a test that imports, installs, launches, or contacts a
network from an untrusted sample.

Licensed under the MIT License.