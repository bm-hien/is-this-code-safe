# ITCS — Is This Code Safe?

[![CI](https://github.com/bm-hien/is-this-code-safe/actions/workflows/ci.yml/badge.svg)](https://github.com/bm-hien/is-this-code-safe/actions/workflows/ci.yml)
[![GitHub Pages](https://github.com/bm-hien/is-this-code-safe/actions/workflows/pages.yml/badge.svg)](https://bm-hien.github.io/is-this-code-safe/)
[![Vision: multi-language](https://img.shields.io/badge/vision-multi--language-7c3aed)](#language-roadmap)
[![Current frontend: Python 3.11+](https://img.shields.io/badge/current_frontend-Python_3.11%2B-3776AB)](#language-support)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**ITCS** is a CPU-first, language-extensible research platform for finding
malware-like behavior in source code. Language-specific frontends translate
code into a shared, evidence-carrying Malware Intermediate Representation
(**MalIR**). The detector then applies bounded flow analysis, behavior motifs,
cheap rules, and selective µMal inference without executing the inspected code.

> **Current status:** the production CLI frontend supports Python. A
> JavaScript/TypeScript frontend is the next planned language milestone, with
> Go or Rust considered only after the two-language MalIR contract is validated.
> Planned support is not the same as implemented support.

**[Open the browser-local analyzer →](https://bm-hien.github.io/is-this-code-safe/)**

ITCS is not an antivirus verdict or a VirusTotal replacement. It is a local
source-triage and security-research layer. Never install, import, or execute an
untrusted package merely to scan it.

## One behavior model, multiple source languages

Different languages express the same security-relevant intent through different
syntax and ecosystems. ITCS keeps those concerns separate:
~~~mermaid
flowchart TD
    A["Language frontend"] --> B["Language-neutral MalIR"]
    B --> C["Rules, flow, and motifs"]
    B --> D["Sparse model"]
    C --> E["Uncertainty gate"]
    D --> E
    E -->|uncertain only| F["Full µMal"]
    E -->|clear case| G["Evidence report"]
    F --> G
~~~

A frontend owns parsing, API mapping, lifecycle semantics, and source locations.
MalIR owns the shared behavior vocabulary. The detector and models consume MalIR
rather than raw syntax, allowing future frontends to reuse the same evidence
policy and model experiments.

The research hypothesis is not “a tiny LLM detects malware.” It is that a
compiler-like, evidence-preserving behavior IR plus conditional model compute
can make source triage cheaper, more auditable, and reusable across languages.

## Language support

| Language / frontend | Status | Scope |
|---|---|---|
| Python CLI | **Available** | Bounded AST parsing, alias resolution, local provenance plus direct-call summaries, motifs, and evidence reports |
| Python MalIR-Lite | **Available in browser** | Bounded lexical test frontend with conservative `proximity:low` evidence |
| JavaScript / TypeScript | **Next research milestone** | Package lifecycle hooks, environment, filesystem, process, dynamic evaluation, and network mappings |
| Go or Rust | **Later research milestone** | Considered after the Python + JavaScript/TypeScript IR contract survives cross-language evaluation |
| Additional languages | **Future / community** | Added through bounded frontends after the adapter contract is stable |

See [MalIR v1](docs/MALIR_SPEC.md) for the language-neutral contract,
[effect and purpose context](docs/EFFECT_PURPOSE_V1_2026-08-14.md) for the
capability/purpose split, and [the research plan](docs/RESEARCH.md) for claim
gates.

## Current capabilities

### Shared analysis and model layer

- Emits deterministic MalIR events in the categories `context`, `source`,
  `transform`, and `sink`.
- Preserves file, line, column, function, phase, operation, target, and
  human-readable evidence.
- Distinguishes `dataflow:high`, `summary:medium`, `proximity:low`, and
  `structural:high` evidence. These are qualitative tiers, not probabilities.
- Builds bounded behavior motifs such as source-to-network, download-to-execute,
  encoded execution, install-time execution, and persistence writes.
- Summarizes entrypoints, origins, destinations, transformations, flows, and
  conservative whole-file purpose candidates with supporting lines.
- Scores semantic evidence novelty rather than source-line frequency; repeated
  operations and motifs retain occurrence counts without repeatedly adding risk.
- Consults an optional model over normalized effect context. Inside the 20–80
  gate it may raise risk, but it cannot lower the deterministic capability
  score; outside the gate its probability remains advisory.
- Includes a dependency-free hashed online logistic classifier.
- Includes full µMal: a 567,746-parameter behavior Transformer trained from
  scratch with classification and masked-token objectives.
- Produces deterministic JSON reports with source evidence and explicit limits.

### Current Python frontend

- Parses source with Python `ast`; inspected files are never imported or run.
- Resolves common import and assignment aliases.
- Tracks bounded, flow-sensitive local provenance through assignments,
  containers, transforms, comprehensions, and conservative branch joins.
- Expands unique, unrebound top-level direct calls to depth 3 and 64
  expansions per file, with lexical-shadow guards, immediate-`await` semantics,
  generator safeguards, and explicit `summary:medium` evidence.
- Runs the second AST pass only when events can form a supported behavior path.
- Bounds files, bytes, events, recursion, directories, and traversal.
- Skips symlinks and common dependency or build folders.
- Provides an isolated, non-extracting wheel/ZIP/TAR.GZ research reader with
  member, byte, ratio, duplicate-path, traversal, and symlink limits.

### Research and evaluation tooling

- Audits dataset manifests for artifact, group, family, campaign, temporal, and
  post-MalIR representation leakage.
- Locks thresholds on validation and applies them unchanged to test data.
- Reports low-FPR power bounds, calibration, confidence ranking, risk coverage,
  AURC, and group bootstrap intervals.
- Compares aligned systems with independent thresholds, paired group bootstrap,
  transition counts, and a conservative claim gate.
- Includes reproducible CPU, memory, corpus, and checkpoint benchmarks.

## Quick start

The current scanner requires Python 3.11 or newer:

~~~bash
git clone https://github.com/bm-hien/is-this-code-safe.git
cd is-this-code-safe
make bootstrap

.venv/bin/itcs tests/fixtures/suspicious/static_exfil.py
.venv/bin/itcs tests/fixtures/benign --json
~~~

A path as the first argument is shorthand for `itcs scan PATH`. Reports use
the verdicts `MALWARE-LIKE`, `NEEDS REVIEW`, or `NO MALWARE EVIDENCE` and
retain the operations and line numbers that produced the score. The last label
means only that this analyzer found little evidence; it does not prove safety.

For the optional full µMal environment:

~~~bash
make bootstrap-micro
.venv/bin/itcs train-micro examples/synthetic_train.jsonl \
  -o artifacts/micro.pt --epochs 20 --batch-size 8 --threads 2
.venv/bin/itcs scan path/to/source \
  --micro-model artifacts/micro.pt --threads 2
~~~

For the much smaller dependency-free online model:
~~~bash
.venv/bin/itcs train-sparse examples/synthetic_train.jsonl \
  -o artifacts/sparse.model.json --epochs 40
.venv/bin/itcs scan path/to/source \
  --model artifacts/sparse.model.json
~~~

The bundled 44-row dataset is deliberately synthetic and exists only for
correctness and training-plumbing tests. Its training accuracy is not evidence
of real-world detection quality.

## Browser analyzer

The [GitHub Pages analyzer](https://bm-hien.github.io/is-this-code-safe/)
is a focused test interface for pasted source or a local `.py` file.

- Opening the page does **not** load model weights.
- The user explicitly selects **Download full model**.
- The 2,270,984-byte float32 binary is fetched from the same origin.
- Web Crypto verifies its SHA-256 digest before installation.
- Source stays in the browser and is never uploaded, imported, or executed.
- The editor is a locally bundled Monaco build with a same-origin worker and a
  textarea fallback; it makes no CDN request.
- The full 567,746-parameter µMal checkpoint runs locally in JavaScript.
- Equivalent URL/sink repetitions collapse into one score and one model token;
  raw events and occurrence counts remain available for review.
- The result separates deterministic capability from an effect/purpose profile;
  purpose candidates are explanations, not claims about author intent.
- µMal evaluates compacted input in bounded overlapping windows instead of
  silently ignoring behavior after its first 256-token context.
- Browser smoke vectors match the PyTorch checkpoint during tests.

The browser currently uses Python MalIR-Lite because GitHub Pages cannot run the
Python AST backend. MalIR-Lite masks strings and comments, resolves common
aliases, emits language-neutral operations, and gives same-function proximity
motifs only weak `proximity:low` weight. Use the CLI for AST-accurate Python
results.

See [the browser architecture and security boundary](docs/WEB_DEMO.md).

~~~bash
npm ci
make web-model
make test-web
make web
~~~
## CLI reference

~~~text
itcs PATH [--json] [--no-dataflow] [--no-call-summaries] [--model FILE | --micro-model FILE]
itcs scan PATH [--json] [--no-dataflow] [--no-call-summaries] [--model FILE | --micro-model FILE]
itcs extract PATH [--compact] [--no-dataflow] [--no-call-summaries]
itcs train-sparse DATASET -o MODEL
itcs train-micro DATASET -o CHECKPOINT
itcs benchmark PATH [--repeats N] [--no-dataflow | --no-call-summaries | --compare-dataflow | --compare-summaries]
itcs audit-manifest MANIFEST [--strict] [--json]
itcs evaluate-predictions PREDICTIONS [--target-fpr RATE] [--json]
itcs compare-predictions BASELINE CANDIDATE [--target-fpr RATE] [--json]
~~~

Use `--fail-on review`, `suspicious`, or `high-risk` to return exit code 2
at a selected CI threshold. The default never changes the exit code based only
on a heuristic verdict.

JSONL training rows accept extracted tokens, inline source, or a relative path:

~~~json
{"label": 1, "tokens": ["P:runtime|C:source|O:ENV_READ|T:token"]}
{"label": "benign", "source": "from pathlib import Path\n"}
{"label": 0, "path": "relative/sample.py"}
~~~

Source rows and paths are currently parsed by the Python frontend. Future
language adapters must add an explicit language identity rather than guessing
from untrusted content.

## Frontend contract

MalIR v1 is the stable integration boundary today. The internal frontend API is
not yet presented as a public plugin SDK. A new language frontend must:
1. parse source as data and never import, execute, build, or install it;
2. enforce explicit bounds on bytes, syntax depth, events, traversal, and time;
3. map ecosystem APIs into existing language-neutral operations where possible;
4. preserve source locations and short evidence explanations;
5. map equivalent lifecycle concepts to `import`, `install`, or `runtime`;
6. emit deterministic event ordering and normalized targets;
7. label evidence strength honestly and avoid claiming proximity as value flow;
8. include suspicious-shaped positive fixtures and benign counterexamples; and
9. update [MalIR v1](docs/MALIR_SPEC.md) when a new operation or schema field is
   truly required.

This contract is intentionally stricter than “add a parser.” Cross-language
reuse is accepted only if false-positive behavior, explanations, compute cost,
and model transfer are measured.

## Language roadmap

### Phase 1 — harden the shared core and Python reference frontend

- Semantic repeat saturation is implemented; package-level calibration against
  observed hard negatives and locked holdouts remains pending.
- Bounded direct-call summaries without whole-program graph construction:
  implemented; evaluation against locked corpora remains pending.
- Build a provenance-rich, statistically powered evaluation corpus.
- Freeze validation decisions before opening sealed holdouts.
- Continue repeated CPU, RSS, and latency profiling.

### Phase 2 — JavaScript / TypeScript frontend

- Map package install hooks and module-load behavior.
- Map environment reads, filesystem access, process execution, dynamic
  evaluation, decoding, deserialization, and network operations.
- Reuse the MalIR vocabulary before proposing language-specific operations.
- Compare zero-shot µMal transfer, few-shot adaptation, and joint fine-tuning.
- Evaluate Python and JavaScript/TypeScript with project-, family-, and
  time-disjoint groups.

### Phase 3 — additional compiled-language frontend

- Consider Go or Rust only after the two-language contract remains useful.
- Validate lifecycle, build-script, dependency, process, filesystem, and network
  semantics without forcing one ecosystem into another's assumptions.
- Stabilize a public adapter SDK only after multiple frontends expose the right
  abstraction boundary.

Roadmap items describe research order, not release promises.

## Leakage-aware evaluation

The audit path reads metadata only; it never follows a sample path or opens an
archive. The bundled research manifest and prediction files are synthetic
mechanics fixtures:

~~~bash
.venv/bin/itcs audit-manifest examples/research_manifest.jsonl \
  --strict --json
.venv/bin/itcs evaluate-predictions examples/research_predictions.jsonl \
  --target-fpr 0.001 --bootstrap 2000 --seed 0 --json
.venv/bin/itcs compare-predictions \
  examples/research_predictions.jsonl \
  examples/research_predictions_candidate.jsonl \
  --target-fpr 0.001 --bootstrap 2000 --seed 0 --json
~~~

The evaluator selects a threshold on validation and applies it unchanged to
test. The paired comparison requires aligned sample and group metadata,
independent validation thresholds, and shared test-group resampling. Even with
zero observed false positives, a one-sided 95% upper bound below 0.1% requires
at least 2,995 independent benign groups.

See [the evaluation protocol](docs/EVALUATION_PROTOCOL.md) and
[research data contract](docs/RESEARCH_DATA_FORMAT.md).

## Current research results

### Real-package pilot
The isolated OMCBench pilot covers 400 Python packages and 10,208 `.py`
files. Normalized-AST grouping produced 338 provisional analysis groups.
Candidate-gated local flow improved test average precision from 0.5837 to
0.5954, but both systems detected 0/100 malicious test packages at the locked
1% FPR operating point. The primary claim is unsupported and underpowered.
This is a useful negative result, not a detection-quality claim.

See the [full pilot report](docs/OMCBENCH_PILOT_2026-08-12.md) and
[payload-free metadata](research/results/omcbench-python-2026-08-12/).

### Hard-negative development update

The development-only `context-causal-v6` scorer plus staged-file provenance
passes the existing non-vacuity gate without opening the sealed PyPI holdout.
Its maximum development-benign score is 38, and the resulting threshold detects
15/53 OMCBench validation malicious groups. The staged-file extension changed
0/451 PyPI development artifact scores while recovering three malicious
normalized-AST groups.

This is development evidence only. It is not a confirmatory low-FPR result.
See the [V6 development report](docs/CONTEXT_CAUSAL_V6_DEVELOPMENT_2026-08-13.md).

## Measured on the target Codespace

Environment: 2 vCPU, about 8 GB RAM, Python 3.12.1, Linux x86-64. The
local-flow baseline was measured on 2026-08-12; the summary ablation was
measured on 2026-08-14.

| Component | Result |
|---|---:|
| Candidate-gated local flow, 1,000 inert files | 823.67 files/s |
| Local-flow scan latency, 1,000 files | median 1,193.69 ms; p95 1,331.91 ms |
| Data-flow-off ablation | median 1,159.24 ms; p95 1,272.15 ms |
| Local-flow overhead on the 95/5 synthetic mix | median +2.97%; p95 +4.70% |
| Python allocations with local flow | 2,782,985 bytes peak; +0.82% |
| Local-only flow on 95/5 direct-call mix | median 1,287.35 ms; p95 1,472.37 ms; 770.33 files/s |
| Summary-enabled flow on the same mix | median 1,298.90 ms; p95 1,468.30 ms; 750.89 files/s |
| Direct-call summary overhead | mean +2.59%; median +0.90%; p95 -0.28%; peak allocation +5.27% |
| Sparse smoke checkpoint | 7,259 bytes; 258 active weights |
| Optional PyTorch environment | 992 MB on disk; not needed by core/sparse |
| Default full µMal | 567,746 parameters; 2,280,513-byte FP32 checkpoint |
| Browser full µMal | 567,746 parameters; 2,270,984-byte on-demand binary |
| µMal single-example inference, 2 threads | median 6.49 ms; p95 12.50 ms |
| OMCBench pilot, 400 archives / 10,208 Python files | 158.78 s end to end |

These measurements describe cost, not detection quality. The direct-call
ablation used 1,000 generated inert files, 5% of which contain a source and sink
split across direct functions; both modes used 21 sequential repeats under
`tracemalloc`. An immediately preceding 21-repeat run measured +3.30%
median and +1.13% p95 overhead; the spread and negative latest p95 reflect host
noise, not a speedup claim. This is not an efficacy result, an interleaved
host-noise study, or a process-RSS measurement. Language comparisons must use
aligned, leakage-audited datasets and independently locked thresholds.

~~~bash
.venv/bin/python scripts/benchmark_corpus.py --files 1000 \
  --repeats 21 --compare-dataflow
.venv/bin/python scripts/benchmark_corpus.py --files 1000 \
  --repeats 21 --compare-summaries
.venv/bin/python scripts/benchmark_micro.py artifacts/micro.pt --repeats 300
~~~

## Verdict semantics

| Verdict | Meaning |
|---|---|
| `low-signal` | Little evidence was found; this does not prove safety |
| `review` | Weak or ambiguous behavior deserves inspection |
| `suspicious` | Multiple risky operations or a behavior motif was found |
| `high-risk` | Strong or accumulated static evidence; not final attribution |

Every result retains the operations and source locations that produced its
score. `capability_score` is deterministic reviewable capability, while the
effect summary explains a conservative whole-file role; neither is proof of
malicious intent. `dataflow:high` means bounded provenance reached the
displayed sink inside one callable. `summary:medium` crosses an eligible unique,
unrebound direct-call boundary. `proximity:low` is a same-scope fallback.
`structural:high` requires no value flow. None is whole-program proof or a
calibrated malware probability.

## Repository map

| Path | Purpose |
|---|---|
| `src/malir/extractor.py` | Current Python AST frontend and API mappings |
| `src/malir/effects.py` | Whole-file effect and conservative purpose summary |
| `src/malir/flow.py` | Bounded local provenance and direct-call summaries |
| `src/malir/motifs.py` | Data-flow, summary, proximity, and structural motif policy |
| `src/malir/detector.py` | Evidence weights and uncertainty gate |
| `src/malir/model.py` | Dependency-free sparse classifier |
| `src/malir/microlm.py` | Full µMal Transformer and training loop |
| `src/malir/model_tokens.py` | Model target normalization and effect-token schema |
| `src/malir/archive.py` | Bounded, non-extracting research archive reader |
| `src/malir/manifest.py` | Dataset metadata and leakage audit |
| `src/malir/evaluation.py` | Locked evaluation, calibration, and bootstrap |
| `src/malir/comparison.py` | Paired system comparison and claim gate |
| `web/` | Browser test interface and on-demand full µMal runtime |
| `scripts/train_web_model.py` | Full checkpoint trainer and browser exporter |
| `docs/MALIR_SPEC.md` | Language-neutral IR contract |
| `docs/EFFECT_PURPOSE_V1_2026-08-14.md` | Capability/effect/purpose decision record |
| `docs/BOUNDED_CALL_SUMMARIES.md` | Direct-call summary design and limits |
| `docs/WEB_DEMO.md` | Browser architecture and security boundary |
| `docs/EVALUATION_PROTOCOL.md` | Leakage and low-FPR evaluation protocol |
| `docs/RESEARCH.md` | Research questions, evidence, and language roadmap |
| `docs/RESEARCH.vi.md` | Vietnamese research overview and roadmap |
| `docs/THREAT_MODEL.md` | Trust boundary and known evasions |
| `CONTRIBUTING.md` | Safety, testing, and research-claim rules |

## Known limits

Version 0.6 has one production language frontend: Python. It performs bounded
intraprocedural provenance plus summaries for unique, unrebound top-level calls
in the same module, not general interprocedural or whole-program flow. Callable
aliases, duplicate/rebound definitions, generators, and unawaited async calls
are not guessed. It does not precisely model imported or nested calls, methods,
globals, attributes, mutation, native payloads, arbitrary obfuscation,
runtime-only behavior, or every package lifecycle.

The normal CLI does not yet scan archives directly; the research reader handles
bounded Python members in isolated workflows without extracting them. The
browser uses a smaller lexical frontend and cannot provide AST-level proof.

A language-neutral IR reduces duplication, but it does not guarantee that one
language's API, build lifecycle, or threat patterns transfer correctly to
another. Every new frontend needs its own benign counterexamples, false-positive
analysis, ecosystem-specific threat model, and cross-language evaluation.

## Safety and responsible use

- Treat every verdict as triage evidence, not final malware attribution.
- Do not run untrusted fixtures, packages, installers, or build scripts.
- Do not commit live malware, credentials, private source, or weaponized
  archives.
- Use `example.invalid` and inert suspicious-shaped text in tests.
- Handle real samples only in isolated workers with no reusable credentials or
  outbound network.
- Review [the threat model](docs/THREAT_MODEL.md) before research use.

## Contributing

Contributions are welcome for current Python analysis, hard-negative fixtures,
bounded extraction, evaluation, performance, explanations, and future language
frontends. Read [CONTRIBUTING.md](CONTRIBUTING.md) first.

A frontend contribution must map behavior into MalIR, remain bounded, include
both positive and benign fixtures, and never execute inspected source. New
operations or serialized fields require a MalIR specification update.

Run the relevant checks before opening a pull request:

~~~bash
make lint
make test
npm ci
make test-web
~~~

## License

Licensed under the [MIT License](LICENSE).
