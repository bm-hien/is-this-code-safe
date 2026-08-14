# Research plan: CPU-first malicious Python source analysis

Status: design and working prototype, 2026-08-12. This document separates
measured engineering facts from hypotheses that still require real data.

## 1. Problem statement

The goal is not to recreate all of VirusTotal on two CPUs. VirusTotal combines
many engines, reputation, dynamic analysis, and a large intelligence network.
A feasible low-cost research target is narrower:

> Given a Python source tree, identify security-relevant behavior paths, rank
> packages for review, and explain every alert locally under a strict CPU
> budget.

The system must work without uploading proprietary source, executing the
package, or querying a large model. A later service may combine its result with
signatures, reputation, sandboxing, or an analyst.

## 2. What prior work already establishes

| Work | Relevant idea | Lesson for this project | Remaining gap |
|---|---|---|---|
| [Cerebro (2023)](https://arxiv.org/abs/2309.02637) | Converts package behavior to sequences and classifies them with BERT/RoBERTa | Behavior abstraction can remove irrelevant source syntax | Transformer and extraction cost; evidence and CPU deployment |
| [SCORE (2024)](https://arxiv.org/abs/2411.08182) | Uses syntax highlighting/AST structure with lightweight sequential and graph models | Structural representation may matter more than model scale | A security-specific, cross-language behavior contract |
| [MalGuard (2025)](https://arxiv.org/abs/2506.14466) | Reports competitive RF/XGBoost results from 132 static features | Strong cheap baselines are mandatory | Temporal degradation and open-world generalization |
| [Donapi (2024)](https://www.usenix.org/conference/usenixsecurity24/presentation/huang-cheng) | Finds that individual suspicious behaviors and unordered API sets create many false positives | Test behavior combinations, ordering, and hard negatives | Its dynamic Node.js pipeline is not ITCS's static Python setting |
| [MOLOT (2026)](https://arxiv.org/abs/2606.07792) | Interprocedural behavior sequences, BERT, and SHAP explanations | Representation and explanation can dominate latency | Remove full call-graph/SHAP cost from the common path |
| [CodeQL Python data flow guide](https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-python/) | Local flow is cheaper and more precise than global flow; local taint also follows non-value-preserving transforms | Start with bounded intraprocedural provenance | This is design guidance, not an ITCS efficacy result |
| [MalTotal (2026)](https://arxiv.org/abs/2608.03232) | LLM-assisted sensitive-API discovery plus hybrid semantic slicing across five languages | Selective semantic reduction can sharply cut token cost | It still uses an LLM-assisted pipeline; results need independent replication |
| [PyGuard (2026)](https://arxiv.org/abs/2601.16463) | Mines behavior patterns from false positives/negatives and uses LLM semantic abstraction | Hard negatives and contextual boundaries directly attack alert fatigue | Behavior mining and LLM reasoning are already occupied novelty |
| [PYPILINE (2026)](https://arxiv.org/abs/2606.19063) | Builds AST/API graphs and suspicious-API knowledge for an agent workflow | Package-level API context is useful | Its LLM/RAG/agent path is not the two-CPU, offline target |
| [Leakage study (2024)](https://arxiv.org/abs/2410.19364) | Shows distinct malware samples can collapse to identical learned representations across temporal splits | Audit the representation seen by the model, not only artifact hashes | Published case studies are Android; ITCS must test the effect on MalIR |
| [Aurora (2025)](https://arxiv.org/abs/2505.22843) | Evaluates confidence ranking with risk-coverage/AURC and reject stability under drift | Calibration alone cannot validate an uncertainty gate | Transfer the protocol from Android streams to package source |
| [OMCBench](https://github.com/False-Positive-Community/open-malicious-code-benchmark) | Open malicious-code benchmark for Python and JavaScript | A reproducible public starting point exists | It is small for low-FPR claims and contains real malicious archives |

Reported numbers from papers are not direct measurements of this repository.
MOLOT reports that, on a two-core setting, its BERT inference is roughly
0.58 seconds per package while full call-graph extraction is around 16 seconds
and SHAP explanation is around 99 seconds. MalGuard reports feature extraction
on the order of milliseconds per package for its benchmark. MalTotal reports a
93.1% average F1 across five languages and a 94% token reduction. Those claims
use different datasets and protocols and must not be compared as one leaderboard.

The key conclusion is uncomfortable but useful: behavior sequences are not the
novelty. A larger Transformer is unlikely to be the breakthrough.

### 2.1 Evidence update: leakage, abstention, and statistical power

Three findings materially change the ITCS experiment design:

1. A forward time split is necessary but not sufficient. The leakage study
   found identical or nearly identical model representations across temporal
   train/test splits. Because MalIR is deliberately lossy, ITCS now requires a
   SHA-256 of the final model-visible representation and rejects any such hash
   crossing splits. Artifact SHA, package group, family, and campaign checks
   remain separate controls.
2. A probability near 0.5 is not evidence that uncertainty ranks errors well.
   Aurora shows calibration and selective ranking are distinct: tied scores can
   be calibrated yet useless for rejection. ITCS therefore reports ECE/Brier
   and tie-aware risk-coverage/AURC, plus future per-period gate usage.
3. A tiny benign set cannot support a tiny FPR claim. With zero observed false
   positives in n benign trials, the exact one-sided confidence bound is
   `1 - 0.05 ** (1 / n)` at 95% confidence. Showing an upper bound at or below
   0.1% therefore needs at least 2,995 independent benign packages even with
   zero errors. OMCBench's construction section specifies only 200 benign
   Python packages, so it is a pilot benchmark rather than low-FPR evidence.

The repository implements these controls in `itcs audit-manifest`,
`itcs evaluate-predictions`, and `itcs compare-predictions`. All operate on
bounded metadata/prediction JSONL; none opens or executes package content.

### 2.2 Evidence update: provenance without whole-program cost

Three observations motivate the version 0.4 flow design:

1. The CodeQL Python guide distinguishes local from global data flow and notes
   that local analysis is faster, more precise, and sufficient for many tasks.
   Its local taint model also covers non-value-preserving steps such as string
   composition, which matches malware-source transforms better than pure value
   equality.
2. MOLOT states that its intended data-flow augmentation made processing
   prohibitively slow, so its released pipeline retained call-graph behavior
   sequences instead. Its reported two-core call-graph and SHAP costs reinforce
   that neither belongs in ITCS's common path.
3. PyGuard's false-positive analysis reinforces that sensitive API occurrence
   alone is insufficient; the surrounding behavioral context determines whether
   an operation deserves an alert.

ITCS therefore performs a second, bounded AST traversal only when a cheap
event gate finds a supported source/sink candidate. It follows local names
through assignments, expressions, transforms, comprehensions, and conservative
control-flow joins. It does not build a whole-program call graph or compute
SHAP. Proven paths inside one callable receive `dataflow:high`; unproven
same-function windows remain visible as low-weight `proximity:low`. Those
labels are qualitative evidence tiers, not calibrated probabilities.

The 2026-08-14 follow-up adds summaries for bare calls to unique, unrebound
top-level definitions. Lexical shadows, duplicate/rebound definitions, callable
aliases, and star-import ambiguity are rejected rather than guessed. Arguments
are bound in an isolated callee frame and return provenance is merged under a
default depth of 3 and 64 expansions per file. Async callees require an
immediate `await`, while generator creation does not activate a generator body.
Eligible crossings receive `summary:medium`, preserve their real event indexes,
and reuse the existing motif token. The design is narrower than a global solver:
globals, attributes, mutation, dynamic dispatch, nested/imported functions, and
cross-module behavior remain outside its claim. The design rationale follows
the local/global distinction and summary-model pattern in
[CodeQL's data-flow documentation](https://codeql.github.com/docs/writing-codeql-queries/about-data-flow-analysis/)
and the valid-call/return motivation of
[IFDS](https://doi.org/10.1145/199448.199462), without claiming to implement
either complete system.

Counterexample tests cover reassignment, unrelated constant payloads, URL-only
provenance, branch joins, unknown transforms, constant-return and default-argument
semantics, lexical shadowing, duplicate/rebound definitions, async and
generator activation, recursion, and expansion limits. They validate
implementation semantics, not detection accuracy on real malware. The detailed
decision record is in
[BOUNDED_CALL_SUMMARIES.md](BOUNDED_CALL_SUMMARIES.md).

### 2.3 Evidence update: paired claims, not two independent scorecards

Donapi reports that single suspicious behaviors and unordered API sets create
false positives, while behavior combinations and order improve discrimination.
That supports the local-flow hypothesis, but it does not establish that ITCS's
particular provenance pass helps on Python. The relevant experiment is paired:
run proximity-only and local-flow variants on the identical locked artifacts.

Version 0.6 therefore rejects comparisons when sample IDs or immutable
label/split/group/period metadata differ. It chooses a separate validation
threshold for each variant at the same target FPR, freezes both thresholds, and
resamples identical test groups together. The report exposes detections gained
or lost and false alerts fixed or introduced at row and group level.

A point gain is not a claim. The conservative gate requires a positive lower
confidence bound for recall delta, a non-positive upper bound for FPR delta,
and enough independent benign groups for both systems' one-sided target-FPR
bounds. A 95% joint gate uses 97.5% per-system bounds via a two-system
Bonferroni correction. The bundled paired files are synthetic mechanics tests.

### 2.4 Evidence update: isolated OMCBench Python pilot

On 2026-08-12, version 0.6 ran a paired pilot on all 400 Python packages in a
pinned OMCBench checkout. The worker had no network, no reusable credentials, a
read-only root and corpus, dropped capabilities, non-root UID, and fixed CPU,
memory, PID, temporary-storage, member-count, byte-count, path, and compression
limits. The reader did not extract, install, import, compile, or execute package
code. Only payload-free metadata was retained in git.

Exact Python source-set hashing found 400 groups. Identifier- and
literal-normalized AST hashing found 338 groups, including 78 packages across
16 duplicate groups; the largest group contained 21 variants. Group closure
was applied before a deterministic 50/50 validation/test split, and 2,000
paired bootstrap replicates sampled normalized-AST groups.

At the locked target FPR of 1%, both variants selected a threshold above the
maximum score and achieved 0/100 test recall with 0/100 false positives. With
100 benign normalized-AST groups treated as independent, the
Bonferroni-adjusted 97.5% upper bound
on FPR is 3.62%, so the target is unsupported. The primary result is negative.

Local flow did improve exploratory test ranking: average precision changed
from 0.5837 to 0.5954 (paired group-bootstrap delta +0.0117, 95% CI
[+0.0021, +0.0240]), and decision-margin AURC changed from 0.3775 to 0.3737
(delta -0.0038, 95% CI [-0.0082, -0.0006]). Those metrics do not rescue the
failed operating point. At a post-hoc threshold of 0.50, local flow recovered
four malicious rows with no extra benign rows, but FPR remained 44% and the
paired group test was not significant (`p = 0.125`).

The main diagnosis is score saturation: package-wide additive evidence makes
large legitimate packages too easy to score near one. A legitimate database
client produced a true `FILE_READ -> NETWORK_SEND` path, demonstrating that
exact flow is evidence of movement, not intent. The next experiment must
redesign aggregation and contextual negative evidence before adding model
capacity. See [the complete report](OMCBENCH_PILOT_2026-08-12.md).

### 2.5 Evidence update: capability is not purpose

The obfuscator hard negative exposed a representation failure rather than an
event-extraction failure. Dynamic execution, compilation, imports, encoding, and
file output were real, but isolated capability counts did not explain that the
dominant flow was local source to local generated artifact.

Effect-aware v1 adds entrypoint, origin, destination, transformation, flow, and
conservative purpose-candidate context. This follows
[CodeQL's source/propagation/sink separation](https://codeql.github.com/docs/writing-codeql-queries/about-data-flow-analysis/),
[GraphCodeBERT's data-flow representation](https://arxiv.org/abs/2009.08366),
and prior work that models malicious behavior through
[dependencies between operations](https://www.cs.ucdavis.edu/~devanbu/teaching/289/Schedule_files/Mining%20Specifications%20of%20Malicious%20Behavior-1.pdf)
rather than API presence alone.

Concrete targets are normalized to coarse model classes, filenames become a
constant boundary, compilation is separated from execution, and repeated
literal imports are contextual. The model receives these effect tokens, while
the deterministic capability score remains independently auditable. Inside the
gate, µMal can only raise risk; it cannot lower the capability floor.

On the untracked `ff.py` case, the new checkpoint predicts about 0.36%, the
capability and final risk scores are 48, and the result is `review` with a
high-confidence `local-code-transformer` candidate. This is a targeted
hard-negative regression, not evidence of calibrated intent recognition. The
full decision record is in
[EFFECT_PURPOSE_V1_2026-08-14.md](EFFECT_PURPOSE_V1_2026-08-14.md).

## 3. Research hypothesis

The candidate contribution is an evidence-carrying behavioral compiler plus a
conditional-compute learning system:

1. Compile each language into typed MalIR events with source locations.
2. Construct bounded source-transform-sink motifs during extraction.
3. Resolve clear cases with deterministic evidence and a sparse online model.
4. Invoke a sub-million-parameter behavior-language model only inside an
   uncertainty band.
5. Train and evaluate with package-, campaign-, and time-disjoint splits.
6. Reuse one behavior vocabulary when adding other language frontends.

Expected average cost can be written as:

~~~text
C_average = C_extract + p_uncertain * C_micro
~~~

The engineering target is p_uncertain below 0.15 after calibration. With the
current 6.49 ms median µMal call, that would add under 1 ms average model cost
per scanned package. This is a target, not yet a measured production rate.

## 4. Prototype choices

### 4.1 MalIR instead of raw source tokens

Raw code lets a model learn package names, comments, formatting, and copied
boilerplate. MalIR retains operations, lifecycle phase, target class, order,
evidence location, and a conservative effect/purpose summary. It deliberately
discards concrete filenames, URLs, and most lexical content.

The current extractor first emits events, then uses a cheap candidate gate to
decide whether a bounded provenance pass can produce a supported path. That
pass is name-independent and flow-sensitive for local values. It can expand
eligible unique, unrebound top-level direct calls under explicit depth and
count limits; the 12-event window remains only a weak fallback. A synthetic
summary-path ablation now quantifies common-path cost, but whether summaries
improve real-world recall without unacceptable false positives is still an
open, locked-evaluation question.

### 4.2 Two learned stages

The sparse stage uses signed feature hashing over MalIR one-to-three-grams and
online logistic regression implemented with the Python standard library. It
supports partial_fit-style updates, needs no fitted vocabulary, and its
synthetic smoke checkpoint is 7.3 KB. This follows the streaming motivation of
[HashingVectorizer](https://scikit-learn.org/stable/modules/generated/sklearn.feature_extraction.text.HashingVectorizer.html)
and online linear classifiers, while keeping the core dependency-free.

µMal is not a general-purpose conversational LLM. It is a tiny domain language
model: a 567,746-parameter bidirectional Transformer encoder over hashed MalIR
tokens. Training combines classification with masked-token prediction. No
pretrained weights, natural-language tokenizer, retrieval system, or hosted API
is used.

The detector normalizes targets, compacts repeated semantic event classes, and
adds effect context before bounded overlapping-window inference. A supplied
model is always observable. Inside the uncertainty gate it may raise risk, but
`max(capability, fused)` prevents it from lowering deterministic capability.

The fair test is not “µMal versus a huge LLM.” It is whether µMal improves
low-FPR recall over rules, sparse MalIR, and an equal-parameter raw-source model
enough to justify its bounded CPU cost.

### 4.3 Evidence instead of post-hoc SHAP

Every IR event already contains a file, line, operation, and explanation.
Behavior motifs retain the indexes of supporting events and label their basis
as data flow, proximity, or structure. This makes explanations available during
detection and avoids presenting mere co-occurrence as a proven flow.

This is cheaper than post-hoc perturbation, but faithfulness still needs to be
tested. A rule explanation is faithful to that rule; it is not automatically an
explanation of µMal's probability.

## 5. Research questions

- RQ1: Does MalIR improve package-disjoint and time-split detection over
  lexical hashed features at the same CPU/memory budget?
- RQ2: Does µMal improve recall at 0.1% and 1% false-positive rates over the
  sparse stage, especially on uncertain packages?
- RQ3: What latency does always-observable, windowed inference add versus a
  conditional-compute baseline, and is the advisory probability useful?
- RQ4: Which IR fields—phase, target, category, order, and motifs—drive
  generalization rather than dataset leakage?
- RQ5: Does bounded local provenance reduce false alerts versus proximity-only
  motifs at acceptable CPU cost, and are its paths useful enough for review?
- RQ6: Can a JavaScript frontend reuse the same vocabulary and pretrained
  behavior encoder with less labeled data?

## 6. Dataset protocol

### 6.1 Starting data

OMCBench currently provides 400 packages per language: 200 benign and 200
malicious for Python, and the same for JavaScript. It publishes baseline
procedures and warns that malicious archives must not be installed or executed.
Use its Python subset first, but treat 400 packages as a pilot, not sufficient
evidence for a production model.

Add:

- benign packages sampled by release time, download band, package category, and
  presence of install/build scripts;
- malicious packages from independently curated, licensed sources with family,
  campaign, discovery date, and provenance;
- a hard-negative set of legitimate deployment, networking, packaging,
  obfuscation, backup, browser automation, and security tools;
- a future unlabeled corpus for masked MalIR pretraining only.

No real malware is bundled in this repository. The completed pilot read a
quarantined external OMCBench checkout in an isolated worker; git contains only
payload-free hashes, counts, scores, warnings, timings, and public archive names.

### 6.2 Leakage controls

Deduplicate exact archives and normalized ASTs before splitting, then hash the
exact MalIR/token representation consumed by each model and audit that hash
again after splitting. Group every version of one package, fork, campaign, and
malware family in one split. A time split does not waive these controls. Strip
package-name/path tokens for the main experiment, then measure them only as an
explicit leakage ablation. Freeze the audited manifest fingerprint in the
experiment record before model fitting.

Required evaluations:

1. Random package-group split for debugging only.
2. Family/campaign-disjoint split.
3. Forward time split: train on discoveries before date T, test after T.
4. Open-world benign test from ecosystems/categories absent during training.
5. Cross-dataset test with no threshold retuning.

### 6.3 Safe ingestion

Archive ingestion must run outside the developer Codespace in a worker with no
secrets or outbound network. It must reject path traversal, symlinks, excessive
compression ratio, excessive nesting, and byte/file limits. Extraction is a
separate milestone because a naive unzip routine would violate the threat model.

## 7. Baselines and ablations

Every experiment should include:

| ID | Model |
|---|---|
| B0 | Rule evidence only |
| B1 | Raw lexical character/token hashing + logistic regression |
| B2 | MalIR hashing + logistic regression |
| B3 | 132-style engineered static features + RF/XGBoost |
| B4 | Equal-parameter raw-source tiny Transformer |
| B5 | Always-on µMal |
| B6 | Gated rules + sparse + µMal |
| B7 | Larger pretrained code model, offline upper bound only |

Required ablations remove one item at a time: local data flow, the data-flow
candidate gate, proximity fallback, lifecycle phase, targets, event category,
token order, motifs, masked-token loss, sparse stage, and uncertainty gate.
Sweep vocabulary size, sequence length, model width, and gate thresholds.

For robustness, generate semantics-preserving source variants: import aliases,
identifier renaming, string concatenation, wrapper functions, independent call
reordering, function splitting, and harmless dead code. Contrastive
code-learning literature such as
[ContraCode](https://arxiv.org/abs/2009.02731) motivates consistency training,
but every transform must be checked not to change the security behavior label.

The bundled [µMal effect-context V3 checkpoint](MICRO_TRAINING_V3_2026-08-14.md)
implements a mechanics-only version of this gate: 24 synthetic train groups,
12 representation-disjoint synthetic validation groups, controlled effect
pairs, pair-ranking and variant-consistency losses, and a deterministic
training-support abstention boundary. Seed 29 was selected by validation NLL
from seeds 13, 29, and 47. This validation set is not a test set, and the result
is not evidence for real-package efficacy, calibration, or OOD detection.

## 8. Metrics

Accuracy alone is unacceptable for imbalanced deployment.

Primary quality metrics:

- recall at fixed 0.1% and 1% false-positive rates;
- PR-AUC / average precision;
- false alerts per 10,000 benign packages;
- package-level precision, recall, and F1;
- Brier score and expected calibration error;
- tie-aware risk-coverage curves and AURC for the uncertainty gate;
- one-sided FPR confidence bounds and low-FPR sample-size sufficiency;
- family/campaign and monthly recall with group-bootstrap confidence intervals.

System metrics:

- extraction, rule, sparse, and µMal latency separately;
- median, p95, and p99 package latency;
- peak RSS, checkpoint size, serialized IR bytes, and CPU-seconds/1,000
  packages;
- fraction entering the uncertainty gate;
- alert evidence count and analyst review time.

Explanation metrics:

- evidence precision: cited operations are actually present;
- deletion faithfulness: removing cited MalIR events changes the decision more
  than removing matched non-cited events;
- stability under semantics-preserving transformations;
- blinded analyst usefulness on a sampled alert set.

Use package-level bootstrap confidence intervals and paired tests on identical
test packages. Report every random seed and threshold-selection set.

## 9. Current measured engineering baseline

Target: GitHub Codespace, 2 vCPU, about 8 GB RAM, Python 3.12.1,
PyTorch 2.13.0+cpu, Linux x86-64. Date: 2026-08-12.

### Static pipeline

The ablation creates 1,000 inert Python files in a temporary directory: 95%
ordinary templates and 5% suspicious-shaped templates. Each mode warms once,
then runs 21 scans while tracemalloc is active.

| Mode | Mean | Median | p95 | Throughput | Peak Python allocation |
|---|---:|---:|---:|---:|---:|
| Candidate gate, data flow off | 1,170.64 ms | 1,159.24 ms | 1,272.15 ms | 854.23 files/s | 2,760,277 B |
| Candidate gate, data flow on | 1,214.08 ms | 1,193.69 ms | 1,331.91 ms | 823.67 files/s | 2,782,985 B |

On this synthetic mix, bounded flow adds 3.71% mean, 2.97% median, 4.70% p95,
and 0.82% peak Python allocation. Before the candidate gate, a seven-repeat
probe showed roughly 20% median overhead because every ordinary file paid for
a second AST traversal. That exploratory probe motivated the optimization; the
21-repeat gated result above is the recorded local-only baseline. It predates
the 2026-08-14 direct-call summary implementation.

tracemalloc excludes native allocations and adds overhead. Sequential benchmark
modes can still be affected by host noise. A production benchmark must also
interleave modes, record process RSS, and cover cold filesystem behavior and
real package-size distributions. These numbers measure cost, not detection
quality.

### Direct-call summary ablation

On 2026-08-14, a separate 1,000-file corpus kept both modes on candidate-gated
local flow and changed only direct-call expansion. Ninety-five percent of files
were ordinary inert templates; 5% contained an inert source and sink split
across directly resolved top-level functions. Each mode warmed once and then
ran 21 sequential scans under `tracemalloc`.

| Mode | Mean | Median | p95 | Throughput | Peak Python allocation |
|---|---:|---:|---:|---:|---:|
| Local-only flow | 1,298.14 ms | 1,287.35 ms | 1,472.37 ms | 770.33 files/s | 2,838,444 B |
| Direct-call summaries | 1,331.76 ms | 1,298.90 ms | 1,468.30 ms | 750.89 files/s | 2,988,092 B |

The latest measured delta was +2.59% mean, +0.90% median, -0.28% p95, and
+5.27% peak Python allocation. This isolates the implemented summary path on a
synthetic stress mix. An immediately preceding 21-repeat run on the same host
measured +3.33% mean, +3.30% median, +1.13% p95, and +5.28% allocation.
The spread and negative latest p95 show that sequential mode order is confounded
by host noise; it is not evidence of a speedup. `tracemalloc` also excludes
process/native RSS. This is a cost measurement, not evidence that summaries
improve malware detection. Reproduce it with
`itcs benchmark PATH --compare-summaries` or
`scripts/benchmark_corpus.py --compare-summaries`.

### µMal pipeline

Default configuration: vocabulary 4,096, maximum length 256, width 96, four
attention heads, two encoder layers, FFN 192, 567,746 parameters. The benchmark
uses two Torch threads, ten warmups, and 300 timed single-example predictions.

- V3 FP32 checkpoint with support metadata: 2,295,949 bytes;
- three 300-prediction runs: median 4.2622–4.4685 ms;
- those runs' p95: 10.3704–15.9237 ms;
- optional PyTorch training environment: 992 MB on disk.

A probe of legacy torch.ao dynamic linear quantization was not adopted: the
installed Torch version marks that API deprecated and the quantized
TransformerEncoder failed during inference. The supported FP32 path remains
small and fast; INT8 work should target torchao or ONNX Runtime and must beat
this measured baseline before inclusion.

The V3 checkpoint trains on 72 rows from 24 groups, selects its epoch and seed
on 36 rows from 12 group- and representation-disjoint synthetic validation
groups, and records NLL/Brier/ECE, pair ordering/gaps, variant drift, and a
conservative temperature. Seed 29 reached 36/36 validation-row accuracy with
NLL 0.035035 and temperature 1.0. All 18 validation pair constraints were
ordered correctly. This controlled result demonstrates the training gate,
support boundary, and checkpoint round-trip only; it says nothing about
real-package generalization, calibration, or OOD detection. See
[MICRO_TRAINING_V3_2026-08-14.md](MICRO_TRAINING_V3_2026-08-14.md).

### Test state

Two hundred twelve automated tests currently pass: 188 Python tests and
24 browser tests. They cover extraction ordering, alias resolution, non-execution,
syntax errors and warning isolation, deterministic tokens, symlinks and size
limits, bounded hostile archives, source-set/normalized-AST grouping, local and
direct-call provenance counterexamples and gating, semantic repeat saturation,
model-input compaction, multi-window µMal coverage, paired objectives,
training-support abstention, sparse learning/serialization, µMal
training/loading, manifest leakage, low-FPR power, paired group statistics,
CLI JSON, browser evidence fidelity, Monaco wiring and fallback, and benchmark
output.

## 10. Claim gates

Do not describe the project as accurate, superior, or a VirusTotal replacement
until all corresponding gates pass.

| Claim | Minimum evidence |
|---|---|
| CPU-cheap | Repeated p95/RSS results on target hardware and real package-size distribution |
| Accurate | Locked, package-disjoint real test set with confidence intervals |
| Low false positives | At least tens of thousands of held-out benign packages |
| Temporally robust | Forward time split spanning multiple collection windows |
| Explainable | Evidence faithfulness and blinded analyst evaluation |
| Language-agnostic | At least two independent frontends mapped to one stable IR |
| Breakthrough | Statistically significant gain over strong cheap baselines at equal cost |

## 11. Roadmap

### Phase A — Python research baseline

- Metadata audit, locked evaluation, and paired comparison: implemented.
- Name-independent bounded local value flow and candidate gate: implemented.
- Bounded top-level direct-call summaries with medium-confidence evidence and
  a reproducible synthetic cost ablation: implemented; locked quality and
  interleaved RSS evaluation remains pending.
- Bounded non-extracting archive reader and isolated OMCBench runner: implemented.
- Group-aware 400-package OMCBench pilot: completed; primary claim unsupported.
- Redesign package aggregation and context using the observed hard negatives.
- Evaluate direct-call summaries against local-only flow on the same locked
  artifacts before changing policy weights.
- Build a statistically powered, provenance-rich hard-negative corpus.
- Calibrate only the redesigned score on validation and freeze all decisions.
- Add repeated process RSS/CPU profiling to the experiment record.

### Phase B — model efficiency

- Compare 0.1M, 0.3M, 0.57M, 1M, and 2M µMal variants.
- Distill only from labels/evidence that can legally be retained.
- Export static shapes and evaluate dynamic INT8 quantization using the
  [ONNX Runtime guidance](https://onnxruntime.ai/docs/performance/model-optimizations/quantization.html).
- Measure whether masked-token pretraining helps with limited labels.
- Validate abstention with risk-coverage/AURC and reject-rate drift, not ECE alone.

### Phase C — second language

Implement a JavaScript/TypeScript frontend that maps package install hooks,
environment reads, filesystem, process, dynamic evaluation, and network calls
to the same operations. Freeze the Python encoder first, then compare zero-shot,
few-shot, and joint fine-tuning. Add Go or Rust only after the two-language IR
contract survives evaluation.

## 12. Decision

The low-cost path is technically plausible, and the prototype demonstrates the
required compute envelope. The potentially publishable idea is not “a tiny LLM
that detects malware.” It is:

> A compiler-like, evidence-preserving malware behavior IR with selective
> micro-model inference, evaluated under temporal, low-FPR, and CPU-budget
> constraints.

The completed pilot confirms that local flow is useful evidence but also shows
that the current additive package score saturates. The next highest-value work
is contextual, size-aware aggregation plus a powered hard-negative evaluation—not
adding more Transformer layers.