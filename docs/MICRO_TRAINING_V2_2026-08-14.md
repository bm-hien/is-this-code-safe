# µMal effect-context V2 training note

Date: 2026-08-14
Status: reproducible synthetic training milestone, not a production efficacy claim.

## Outcome

The browser checkpoint now uses a group-disjoint effect-context dataset instead
of training and reporting accuracy on the same 44 rows. The architecture remains
the 567,746-parameter, two-layer behavior Transformer and the browser binary
remains 2,270,984 bytes.

The selected checkpoint is seed 29. It was chosen by the lowest validation
negative log-likelihood among three fixed seeds. Its model-visible input is
language-neutral MalIR behavior, effect, flow, motif, and purpose context; it
does not read raw source text or execute inspected code.

## Why V1 was insufficient

The earlier checkpoint used all 44 synthetic examples for fitting and then
reported accuracy on those same rows. That verified plumbing, but it could not
measure generalization or probability calibration. It also made a shortcut easy:
one risky operation or one purpose token could dominate a tiny training set.

V2 does not solve real-world generalization. It makes the local training claim
more honest and creates a reproducible gate before a checkpoint is published.

## Dataset and leakage controls

The file examples/micro_train_v2.jsonl is generated deterministically by
scripts/build_micro_dataset.py.

| Split | Behavior groups | Rows | Negative groups | Positive groups |
|---|---:|---:|---:|---:|
| Train | 20 | 60 | 10 | 10 |
| Validation | 10 | 30 | 5 | 5 |
| Total | 30 | 90 | 15 | 15 |

Each behavior group has three semantic views: a base sequence, an import-context
view, and an explicit-CLI view. A group never crosses the split. The loader also
hashes the exact canonical token sequence and rejects any model-visible
representation that crosses train and validation or receives conflicting labels.

The corpus contains dual-use hard negatives such as local compilers,
obfuscators, artifact publishers, backup clients, telemetry clients, plugin
loaders, build tools, and update caches. Positive roles include credential/file
exfiltration, download-to-execute, encoded execution, persistence, destructive
file actions, install-time execution, and fingerprint transfer.

Paired rows deliberately share surface capabilities while differing in effect:

- artifact upload versus sensitive-file exfiltration;
- backup encoding/upload versus destructive or sensitive flows;
- remote cache download versus download-and-execute;
- ordinary telemetry versus fingerprint transfer; and
- local code generation versus remote dynamic execution.

These are synthetic role fixtures, not claims about a real package or author.

## Training procedure

The published command uses:

- classification cross-entropy with 0.05 label smoothing;
- a 0.05 masked-MalIR auxiliary objective;
- AdamW at learning rate 1e-3;
- batch size 8 and two CPU threads;
- validation-NLL checkpoint selection;
- 80 requested epochs, minimum 12 training epochs, and patience 12;
- validation-only scalar temperature fitting constrained to T >= 1, so
  calibration can soften confidence but cannot make it sharper.

Classification and masked-token passes are now separate. The classifier sees the
unmasked behavior sequence while the auxiliary head reconstructs masked tokens.

The checkpoint records dataset SHA-256, split fingerprint, seed, group counts,
best/completed epochs, label smoothing, validation kind, Brier score, 10-bin ECE,
NLL, and temperature. Python and browser inference apply the same temperature,
and committed smoke vectors verify their numerical parity.

## Seed selection

The primary local selection metric was validation NLL. All values below are on
the same 30-row, 10-group synthetic validation split.

| Seed | Best epoch | Accuracy | NLL | Brier | ECE-10 | ff.py probability |
|---:|---:|---:|---:|---:|---:|---:|
| 13 | 7 | 30/30 | 0.086686 | 0.019452 | 0.073647 | 6.80% |
| **29** | **6** | **30/30** | **0.074126** | 0.011816 | **0.066861** | **1.64%** |
| 47 | 8 | 30/30 | 0.080994 | **0.010542** | 0.074856 | 6.94% |

The fitted conservative temperature for all three seeds was 1.0; therefore the
published probabilities are unchanged by the calibration transform. The
metadata says temperature-scaled-validation because the validation-only fit was
performed, and separately says synthetic-group-disjoint so it cannot be
mistaken for real-world calibration.

Perfect validation accuracy is expected on this small controlled corpus and is
not a security-performance result.

## Selected-checkpoint regressions

The selected seed 29 checkpoint produced these model-only probabilities:

| Behavior | Probability |
|---|---:|
| Local compile and artifact write | 1.44% |
| Authorized backup-like encode and upload | 3.28% |
| Local ff.py obfuscator | 1.64% |
| Download then process execution | 99.04% |
| Sensitive environment value to network | 99.29% |

All five validation counterfactual families ranked every positive view above
every negative view. The smallest worst-case positive-minus-negative gap was
0.512752.

ff.py was statically parsed as data only. It was never imported, compiled, or
executed. Its deterministic capability score and final risk remain 48/review;
the model is advisory and cannot lower that floor.

Repeated equivalent URL sends still collapse before model inference. Repeating a
sink changes occurrence counters but not the canonical model representation or
model contribution.

## Research basis

The implementation follows a deliberately small subset of established methods:

- [Guo et al., calibration of modern neural networks](https://proceedings.mlr.press/v70/guo17a.html)
  motivates validation-only temperature scaling.
- [ContraCode](https://aclanthology.org/2021.emnlp-main.482/)
  motivates checking consistency under semantics-preserving code variants.
- [Supervised Contrastive Learning](https://proceedings.neurips.cc/paper/2020/hash/d89a66c7c80a29b1bdbab0f2a1a94af8-Abstract.html)
  motivates future role-aware objectives; V2 does not add a contrastive loss.
- [Just Train Twice](https://proceedings.mlr.press/v139/liu21f.html)
  motivates hard-example and worst-group analysis; V2 uses curated hard pairs
  but not JTT or group DRO.
- [Deep Anomaly Detection with Outlier Exposure](https://openreview.net/forum?id=HyxCxhRcY7)
  motivates the next OOD/abstention stage; V2 does not claim OOD detection.

## Reproduce

~~~bash
make bootstrap-micro
.venv/bin/python scripts/build_micro_dataset.py
.venv/bin/python scripts/train_web_model.py --train
npm run test:web
~~~

The default seed is 29. To reproduce the seed comparison, pass --seed 13,
--seed 29, or --seed 47 with separate checkpoint and export paths.

## Limits and next gate

V2 still has only 30 synthetic behavior groups and 10 validation groups. It
cannot estimate real false-positive rates, novel-family recall, calibration
drift, OOD behavior, or cross-language transfer. The validation set has already
been used for model selection and is not a test set.

The next publishable model gate requires a new locked, project/family/time-
disjoint corpus with real benign hard negatives, legally usable malicious
samples, at least one unseen-language or unseen-ecosystem slice, and no tuning
after test labels are opened. Report recall at fixed low FPR, group bootstrap
intervals, Brier/ECE, risk coverage/AURC, CPU/RSS, and evidence usefulness.
