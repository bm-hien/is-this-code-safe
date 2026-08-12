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
| [MOLOT (2026)](https://arxiv.org/abs/2606.07792) | Interprocedural behavior sequences, BERT, and SHAP explanations | Representation and explanation can dominate latency | Remove full call-graph/SHAP cost from the common path |
| [MalTotal (2026)](https://arxiv.org/abs/2608.03232) | LLM-assisted sensitive-API discovery plus hybrid semantic slicing across five languages | Selective semantic reduction can sharply cut token cost | It still uses an LLM-assisted pipeline; results need independent replication |
| [OMCBench](https://github.com/False-Positive-Community/open-malicious-code-benchmark) | Open malicious-code benchmark for Python and JavaScript | A reproducible public starting point exists | It is small for deep learning and contains real malicious archives |

Reported numbers from papers are not direct measurements of this repository.
MOLOT reports that, on a two-core setting, its BERT inference is roughly
0.58 seconds per package while full call-graph extraction is around 16 seconds
and SHAP explanation is around 99 seconds. MalGuard reports feature extraction
on the order of milliseconds per package for its benchmark. MalTotal reports a
93.1% average F1 across five languages and a 94% token reduction. Those claims
use different datasets and protocols and must not be compared as one leaderboard.

The key conclusion is uncomfortable but useful: behavior sequences are not the
novelty. A larger Transformer is unlikely to be the breakthrough.

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
and evidence location. It deliberately discards most lexical content.

The current extractor is a single AST pass plus a local window. This makes its
cost predictable. A later bounded call-summary pass may improve recall without
recreating a whole-program call graph.

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

The fair test is not “µMal versus a huge LLM.” It is whether µMal improves
low-FPR recall over rules, sparse MalIR, and an equal-parameter raw-source model
enough to justify its conditional CPU cost.

### 4.3 Evidence instead of post-hoc SHAP

Every IR event already contains a file, line, operation, and explanation.
Behavior motifs retain the indexes of supporting events. This makes
explanations available in the same pass as detection.

This is cheaper than post-hoc perturbation, but faithfulness still needs to be
tested. A rule explanation is faithful to that rule; it is not automatically an
explanation of µMal's probability.

## 5. Research questions

- RQ1: Does MalIR improve package-disjoint and time-split detection over
  lexical hashed features at the same CPU/memory budget?
- RQ2: Does µMal improve recall at 0.1% and 1% false-positive rates over the
  sparse stage, especially on uncertain packages?
- RQ3: How much extraction and model latency does conditional compute save
  versus always-on inference?
- RQ4: Which IR fields—phase, target, category, order, and motifs—drive
  generalization rather than dataset leakage?
- RQ5: Are evidence paths useful and faithful enough for an analyst to verify
  an alert quickly?
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

No real malware is bundled or downloaded by the current repository.

### 6.2 Leakage controls

Deduplicate exact archives, normalized ASTs, and near-duplicate MalIR sequences
before splitting. Group every version of one package, fork, campaign, and
malware family in one split. Strip package-name/path tokens for the main
experiment, then measure them only as an explicit leakage ablation.

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

Required ablations remove one item at a time: lifecycle phase, targets, event
category, token order, motifs, masked-token loss, sparse stage, and uncertainty
gate. Sweep vocabulary size, sequence length, model width, and gate thresholds.

For robustness, generate semantics-preserving source variants: import aliases,
identifier renaming, string concatenation, wrapper functions, independent call
reordering, function splitting, and harmless dead code. Contrastive
code-learning literature such as
[ContraCode](https://arxiv.org/abs/2009.02731) motivates consistency training,
but every transform must be checked not to change the security behavior label.

## 8. Metrics

Accuracy alone is unacceptable for imbalanced deployment.

Primary quality metrics:

- recall at fixed 0.1% and 1% false-positive rates;
- PR-AUC / average precision;
- false alerts per 10,000 benign packages;
- package-level precision, recall, and F1;
- Brier score and expected calibration error;
- family/campaign and monthly recall with confidence intervals.

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

The benchmark creates 1,000 inert Python files in a temporary directory:
95% ordinary templates and 5% suspicious-shaped templates. It warms once, then
runs five scans while tracemalloc is active.

- mean: 1,124.57 ms per 1,000-file tree;
- median: 1,111.24 ms;
- p95: 1,190.57 ms;
- throughput: 889.23 files/second;
- peak Python allocations: 2,725,883 bytes.

tracemalloc excludes native allocations and adds overhead. A production
benchmark must also record process RSS and cold filesystem behavior.

### µMal pipeline

Default configuration: vocabulary 4,096, maximum length 256, width 96, four
attention heads, two encoder layers, FFN 192, 567,746 parameters. The benchmark
uses two Torch threads, ten warmups, and 300 timed single-example predictions.

- FP32 checkpoint: 2,280,321 bytes;
- median inference: 6.4882 ms;
- p95 inference: 12.5015 ms;
- optional PyTorch training environment: 992 MB on disk.

A probe of legacy torch.ao dynamic linear quantization was not adopted: the
installed Torch version marks that API deprecated and the quantized
TransformerEncoder failed during inference. The supported FP32 path remains
small and fast; INT8 work should target torchao or ONNX Runtime and must beat
this measured baseline before inclusion.

Training on the bundled 32 synthetic rows for 20 epochs reached 100% training
accuracy. That is only a smoke test demonstrating learnability and checkpoint
round-trip; it says nothing about generalization.

### Test state

Twenty-one automated tests currently pass. They cover extraction ordering, alias
resolution, non-execution, syntax errors, deterministic tokens, symlinks and
size limits, sparse learning/serialization, µMal training/loading, CLI JSON,
and benchmark output.

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

- Add name-independent local value flow and bounded function summaries.
- Build a safe manifest-to-MalIR dataset worker outside the Codespace.
- Run OMCBench and a large hard-negative corpus.
- Calibrate thresholds and uncertainty gates on validation only.
- Add RSS/CPU profiling and reproducible experiment manifests.

### Phase B — model efficiency

- Compare 0.1M, 0.3M, 0.57M, 1M, and 2M µMal variants.
- Distill only from labels/evidence that can legally be retained.
- Export static shapes and evaluate dynamic INT8 quantization using the
  [ONNX Runtime guidance](https://onnxruntime.ai/docs/performance/model-optimizations/quantization.html).
- Measure whether masked-token pretraining helps with limited labels.
- Add selective prediction: abstain when confidence/calibration is poor.

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

The next highest-value work is real, leakage-controlled evaluation—not adding
more Transformer layers.