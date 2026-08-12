# ITCS evaluation protocol

Version 1.0, preregistration template. Complete and freeze this document for a
study before looking at final test results.

## 1. Purpose

This protocol measures whether MalIR and selective µMal inference improve
malicious-package triage under a CPU budget. It is designed to prevent three
common failures:

1. package or malware-family leakage between train and test;
2. impressive F1 on a balanced toy set but unusable false-positive rates;
3. quality comparisons that ignore extraction and explanation cost.

Synthetic fixtures in this repository validate mechanics only. They are never
part of a reported efficacy result.

## 2. Study identity

Record these fields in the experiment report:

| Field | Required value |
|---|---|
| study_id | Immutable identifier |
| hypothesis | One primary hypothesis |
| repository_commit | Full ITCS commit SHA |
| dataset_manifest_sha256 | Hash of the frozen manifest |
| split_manifest_sha256 | Hash of assigned samples |
| collection_cutoff | UTC date fixed before testing |
| seeds | Complete list |
| target_hardware | CPU model, cores, RAM, OS |
| threshold_policy | Validation-only selection rule |
| primary_metric | One metric chosen in advance |
| exclusions | Rules fixed before test inspection |

Save the exact commands, dependency lock, configuration, stdout JSON, and
machine metadata. Do not overwrite an earlier run.

## 3. Manifest schema

Keep malware outside this repository. The research worker consumes a JSONL
manifest with metadata, not an archive checked into git. Each row must contain:

~~~json
{
  "sample_id": "stable opaque id",
  "label": 0,
  "ecosystem": "pypi",
  "package": "normalized-package-name",
  "version": "1.2.3",
  "sha256": "64 lowercase hex characters",
  "first_seen": "2026-01-15",
  "group_id": "package-or-campaign-group",
  "family": null,
  "campaign": null,
  "provenance": "curator/source record",
  "license": "evaluation permission",
  "content_kind": "source-tree"
}
~~~

For malicious samples, group_id must join all known versions, forks, family
variants, and campaign siblings that could leak behavior. For benign samples,
group_id must at least join all versions and renamed forks of one project.

Do not place analyst identity, local absolute paths, credentials, raw URLs with
access tokens, or redistributable sample content in the manifest.

## 4. Inclusion and exclusion

Include Python source packages that the frozen frontend can parse as text.
Record, but do not silently remove, syntax failures, file-limit cases, and empty
source trees.

Exclude only by rules fixed in advance, such as:

- no Python source after safe extraction;
- corrupt archive according to the curator;
- duplicate bytes whose canonical sample is already included;
- missing provenance or permission for the intended evaluation;
- package first seen after the frozen study cutoff.

Never exclude a false positive because it appears “obviously benign” after
viewing a model result. It belongs in the error analysis.

## 5. Safe preparation

Real samples must be prepared in an isolated, disposable worker:

- no reusable credentials or mounted personal directories;
- outbound network disabled by default;
- archive traversal, symlink, device-file, nesting, file-count, byte-count, and
  compression-ratio limits;
- read-only source handoff to the static scanner;
- no pip install, setup.py, import, bytecode compile, or sample execution;
- hashes verified against the frozen manifest;
- complete extraction audit log.

The normal developer Codespace is not the malware ingestion worker.

## 6. Deduplication before splitting

Deduplicate in this order:

1. exact archive SHA-256;
2. exact file-set hash after normalized path ordering;
3. normalized AST hash with literals retained;
4. normalized AST hash with identifiers anonymized;
5. near-duplicate MalIR token similarity;
6. curator family/campaign knowledge.

Keep a map from removed duplicates to the canonical sample. Report counts at
each stage. Tune near-duplicate thresholds on development data only.

## 7. Locked split policy

### 7.1 Debug split

A group-random split may be used for pipeline debugging. Label its results
non-reportable.

### 7.2 Primary temporal split

Choose date T before model testing:

- train: first_seen earlier than T minus the validation window;
- validation: the fixed window immediately before T;
- test: first_seen on or after T.

Apply group closure after dates: if a group crosses boundaries, move the entire
group to its earliest eligible partition or exclude it according to the
preregistered rule. Never split one group.

### 7.3 Campaign/family holdout

Create a second test where no malicious family or campaign appears in train.
Unknown family identifiers remain separate groups based on provenance and
similarity audits; they must not all collapse into one “unknown” group.

### 7.4 Open-world benign holdout

Reserve benign ecosystems, categories, maintainers, or collection sources that
are absent during training. Include hard negatives: installers, deployment
tools, backup/sync clients, package managers, network libraries, browser
automation, obfuscators, debuggers, and security tools.

Publish split counts by label, month, family, category, and extraction status.
Publish hashes or opaque IDs when sample redistribution is prohibited.

## 8. Models and baselines

Run every model on the identical locked split:

- R0: evidence rules only;
- L0: raw lexical hashing plus logistic regression;
- L1: MalIR hashing plus online logistic regression;
- T0: static engineered features plus RF/XGBoost;
- M0: raw-source tiny Transformer matched to µMal parameters;
- M1: always-on µMal;
- C0: ITCS evidence plus sparse plus uncertainty-gated µMal;
- U0: a larger code model as an offline upper bound, when affordable.

Do not compare against only weak public tools. Tune all baselines with the same
validation budget and report their model/extraction cost.

## 9. Model selection and calibration

Select hyperparameters and thresholds using train and validation only. Freeze
them before loading test labels. Save the decision threshold, uncertainty
gates, preprocessing version, and model checkpoint hash.

Calibrate probabilities with a validation-only method if needed. Report Brier
score, expected calibration error, and reliability bins. If calibration drifts
by month, report the drift rather than retuning on test data.

For the cascade, report:

~~~text
p_uncertain = packages invoking µMal / all scanned packages
average_cost = extraction_cost + p_uncertain * µMal_cost
~~~

Sweep gates on validation, then select one operating point by the preregistered
quality/CPU constraint.

## 10. Primary quality metrics

The recommended primary metric is recall at 0.1% false-positive rate. Also
report:

- recall at 1% false-positive rate;
- PR-AUC / average precision;
- false alerts per 10,000 benign packages;
- package-level precision, recall, and F1;
- ROC-AUC only as a secondary metric;
- Brier score and expected calibration error;
- recall by month, family, campaign, and behavior motif;
- abstention/coverage curves when selective prediction is enabled.

With too few benign samples to estimate 0.1% FPR, state that the metric is
underpowered. Do not round zero observed false positives into a zero population
rate; report a confidence bound.

## 11. Uncertainty and statistics

Bootstrap at the group level, not the file level. Use at least 2,000 bootstrap
replicates for 95% confidence intervals. Pair model comparisons on the same
groups.

For the primary hypothesis, report the paired effect size and confidence
interval. Correct for multiple comparisons across secondary hypotheses or
clearly label them exploratory.

Always include the raw numerator and denominator behind rates.

## 12. System measurements

Measure cold and warm runs separately on the declared CPU target. Pin the number
of threads. Run no competing workload. Record:

- file discovery, parse, MalIR, rule, sparse, and µMal time separately;
- package median, p95, and p99 latency;
- throughput and CPU-seconds per 1,000 packages;
- peak resident set size, not only Python tracemalloc;
- source bytes, file count, event count, and sequence length distributions;
- checkpoint and serialized IR size;
- p_uncertain and average cascade cost;
- energy when a reliable platform counter is available.

Warm up model inference before timed warm runs. Randomize package order with a
recorded seed. Repeat enough times to report dispersion.

## 13. Explanation evaluation

An evidence line is useful only if it is correct and helps review.

Automated tests:

- evidence precision: cited operations and locations exist;
- deletion faithfulness: deleting cited MalIR events changes the score more
  than deleting matched uncited events;
- sufficiency: cited events alone retain the decision;
- stability: semantics-preserving variants retain equivalent evidence;
- completeness: known source-transform-sink fixtures cite all required stages.

Analyst test:

- blind analysts to the model variant;
- randomize alert order;
- measure verdict agreement, time to disposition, and evidence usefulness;
- include benign hard negatives and low-confidence cases;
- report inter-rater agreement and disagreements, not just averages.

Rule evidence explains the rule contribution. It must not be presented as a
faithful explanation of µMal unless attribution tests support that claim.

## 14. Robustness suite

Apply label-preserving transformations whose safety has been manually checked:

- import aliases and equivalent import forms;
- identifier renaming;
- constant string concatenation;
- harmless wrapper functions;
- independent statement reordering;
- function extraction/inlining;
- dead benign code insertion;
- known equivalent APIs.

Measure prediction and evidence consistency. Separately test adversarial dead
risky code because it may intentionally inflate static scores.

## 15. Ablations

Remove one component at a time:

- lifecycle phase;
- target values;
- source/transform/sink category;
- event order;
- behavior motifs;
- masked-token objective;
- sparse stage;
- uncertainty gate;
- source locations from the model input.

Sweep hash vocabulary, sequence length, width, layers, and gate boundaries.
Compare on quality, p95 latency, RSS, and p_uncertain—not F1 alone.

## 16. Test freeze and audit

Before final evaluation:

1. hash and make the manifest read-only;
2. materialize split IDs without labels in the analyst workspace;
3. record source commit and environment lock;
4. archive validation decisions and chosen thresholds;
5. run a leakage report and resolve every violation;
6. execute the test exactly once for the primary report;
7. preserve raw predictions for independent metric recomputation.

Additional test runs after viewing results are exploratory and must be labeled.

## 17. Minimum claim gates

| Claim | Required evidence |
|---|---|
| CPU-efficient | Repeated p95/RSS results on real package sizes |
| Accurate | Locked, group-disjoint test with confidence intervals |
| Low false positives | Enough benign data to estimate the stated FPR |
| Temporally robust | Forward split across multiple collection windows |
| Explainable | Automated faithfulness plus blinded analyst study |
| Language-agnostic | Two independent frontends sharing stable MalIR |
| Better than cheap baselines | Significant paired gain at equal CPU budget |
| VirusTotal replacement | Out of scope for the current project |

Until these gates pass, describe ITCS as a research prototype.

## 18. Report checklist

Publish:

- manifest/split hashes and allowed sample identifiers;
- full configuration, commands, seeds, thresholds, and checkpoints;
- extraction failure and exclusion tables;
- all primary and negative results;
- quality, calibration, compute, and explanation metrics;
- confidence intervals and raw counts;
- known leakage risks and limitations;
- a reproduction guide that never requires executing malware.

A negative result—such as sparse MalIR matching µMal—is valuable. In that case,
prefer the cheaper model and report the evidence.