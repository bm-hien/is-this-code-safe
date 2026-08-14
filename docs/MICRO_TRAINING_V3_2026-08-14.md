# µMal effect-context V3 training note

Date: 2026-08-14

Status: reproducible synthetic training milestone, not a production efficacy claim.

## Outcome

V3 keeps the 567,746-parameter two-layer behavior Transformer and the
2,270,984-byte browser binary. It changes what the checkpoint is taught and
when its advisory probability is allowed to affect a decision:

- controlled benign/positive pairs now contribute an explicit ranking loss;
- three context variants of each behavior contribute a consistency loss;
- generic file-to-network behavior is represented as a dual-use hard negative;
- the local `ff.py` obfuscator context is represented as a benign
  local-code-transformer hard negative; and
- a checkpoint-bound support profile makes the model abstain on unsupported
  MalIR while leaving the deterministic capability score unchanged.

Seed 29 was selected by the lowest validation negative log-likelihood among the
fixed seeds 13, 29, and 47. The model consumes MalIR, not raw source, and no
inspected source was imported, compiled, installed, or executed.


## Why V2 was not enough

V2 fixed train/validation leakage and learned effect context, but its classifier
could still assign high probability to hashed tokens it had never seen. In a
four-probe audit, an invented future-language operation received a raw
probability above 84%. That number had no semantic support and must not
participate in fusion.

A second ablation showed that removing motif/effect/purpose context reduced V2
validation accuracy to 60%, while effect-only views retained 100%. Effect
context is therefore useful, but the model needs controlled comparisons and an
explicit boundary around what training actually supports.

V3 does not claim to solve open-set recognition. It converts unsupported input
from an unqualified probability into an auditable abstention.

## Dataset and leakage controls

`examples/micro_train_v3.jsonl` is generated deterministically by
`scripts/build_micro_dataset_v3.py`.

| Split | Groups | Rows | Negative groups | Positive groups |
|---|---:|---:|---:|---:|
| Train | 24 | 72 | 12 | 12 |
| Validation | 12 | 36 | 6 | 6 |
| Total | 36 | 108 | 18 | 18 |


Every group has base, import-context, and explicit-CLI variants. Group IDs and
exact canonical representations cannot cross train/validation. The dataset has
seven train pair families and six validation pair families, producing 21 train
and 18 validation pair constraints after variant alignment.

The new controlled families include:

- sensitive local artifact versus encoded sensitive network transfer;
- local template compilation/execution versus remote-origin execution;
- generic artifact/backup transfer with `file_to_network` versus sensitive
  transfer; and
- local obfuscator effects, including code generation, local-file output,
  runtime/import context, and import-time effects.

These are synthetic behavior roles, not claims about author intent.

Published fingerprints:

- dataset SHA-256:
  `160771dd0aab4e3119f01a3ec03e05d4f42f3336c5fc769bdde825fd1fd9e1cb`;
- split fingerprint:
  `6651913aa8fb6d5b92d6c35a13c5b2a75447f37ddcc1d632f86dc4d9743c1bb5`;
- selected checkpoint SHA-256:
  `ef592edc0844ba3daf6a59474f3b57a9d62d16724ef19593a3db61d6e90438d3`;
- browser binary SHA-256:
  `f9256258874fa0f0a7f10dd857fade7b67f84a217d94d18897f040509547b316`.

## Objective

The base objective remains classification cross-entropy with 0.05 label
smoothing plus a 0.05 masked-MalIR auxiliary loss. V3 adds one structured update
per epoch over the bounded 72-row train split:

- pair ranking: hinge loss on malicious-class logit difference, margin 1.0,
  weight 0.15;
- variant consistency: mean within-group logit variance, weight 0.05.

AdamW, learning rate 1e-3, batch size 8, two CPU threads, 80 requested epochs,
minimum 12 epochs, patience 12, and validation-NLL checkpoint selection remain
unchanged. Temperature fitting is validation-only and constrained to
`T >= 1`.


## Training-support abstention

The checkpoint stores `malir.support-profile.v1` with:

- the canonical token vocabulary observed in train;
- one token-set prototype per train group;
- minimum unique-token coverage 1.0; and
- minimum nearest-prototype Jaccard similarity 0.20.

A sequence is supported only when both thresholds pass. Unsupported inference
still computes and reports a probability for debugging, but
`model_abstained = true`, `model_used = false`, and fusion is skipped.
Python and browser runtimes enforce the same rule.

The 0.20 threshold is a conservative engineering boundary, not a statistically
calibrated OOD threshold. It was fixed before the final seed comparison. All 36
validation rows pass with 100% token coverage; their minimum nearest similarity
is 0.50. The statically parsed `ff.py` sequence passes with 100% coverage and
nearest similarity 0.782609.

## Seed selection

All values below use the same 36-row, 12-group synthetic validation split.

| Seed | Best epoch | Accuracy | NLL | Brier | ECE-10 | Min pair gap | Max variant drift | ff.py |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 13 | 47 | 36/36 | 0.037204 | 0.002947 | 0.035586 | 0.779821 | **0.046968** | 1.74% |
| **29** | **10** | **36/36** | **0.035035** | **0.002430** | **0.033729** | **0.840963** | 0.072694 | 2.03% |
| 47 | 67 | 36/36 | 0.051160 | 0.005946 | 0.047661 | 0.661567 | 0.150636 | 1.93% |


All three seeds order every paired positive above its paired negative. Seed 29
wins the preregistered primary metric, validation NLL. Its fitted conservative
temperature is 1.0. Perfect accuracy on this small controlled corpus is expected
and is not a real security-performance result.

## Selected-checkpoint regressions

| Behavior | Raw probability | Support |
|---|---:|---|
| Local compile and artifact write | 1.35% | supported |
| Authorized encoded backup upload | 2.05% | supported |
| Local `ff.py` obfuscator | 2.03% | supported |
| Local sensitive artifact | 1.94% | supported |
| Encoded sensitive network transfer | 94.55% | supported |
| Sensitive-file exfiltration | 98.62% | supported |
| Remote shell execution | 99.14% | supported |

For `ff.py`, the deterministic capability and final risk remain 48/review.
The model is consulted but cannot lower that floor. The file was parsed
statically as data only.

Repeated equivalent URL sends still collapse into one canonical event/motif
sequence. Repetition changes occurrence counts, not rule score, model input, or
model contribution.


## Unsupported probes

`examples/micro_ood_v3.jsonl` contains non-executable synthetic MalIR probes.

| Probe | Raw probability | Coverage | Nearest | Result |
|---|---:|---:|---:|---|
| Unknown camera source | 9.37% | 0.500 | 0.250 | abstained |
| Unknown mining sink | 39.63% | 0.500 | 0.250 | abstained |
| Unknown transform/purpose | 7.93% | 0.250 | 0.125 | abstained |
| Future-language unsafe operation | 84.69% | 0.667 | 0.286 | abstained |

The last row is the important failure-mode check: a high raw neural probability
does not become decision authority without supported MalIR semantics.

## Research basis

- [ContraCode](https://aclanthology.org/2021.emnlp-main.482/) motivates
  invariance across semantics-preserving program transformations.
- [Learning to Recognize Programs with Property Contrasts](https://aclanthology.org/2022.acl-long.436/)
  motivates controlled program contrasts and hard negatives.
- [SelectiveNet](https://proceedings.mlr.press/v97/geifman19a.html) motivates
  explicit selective prediction and risk/coverage evaluation.
- [Outlier Exposure](https://openreview.net/forum?id=HyxCxhRcY7) motivates
  measuring behavior on auxiliary outliers rather than trusting closed-set
  confidence.

V3 implements a small paired-ranking and deterministic support mechanism. It
does not implement full contrastive pretraining, SelectiveNet, or Outlier
Exposure training.


## Reproduce

~~~bash
make bootstrap-micro
.venv/bin/python scripts/build_micro_dataset_v3.py
.venv/bin/python scripts/train_web_model.py --train
npm run test:web
~~~

The default seed is 29. For seed comparison, pass `--seed 13`, `--seed 29`,
or `--seed 47` with separate checkpoint and export paths.

## Limits and next gate

The validation set selected the epoch and seed, so it is not a test set. V3
cannot estimate real-package false-positive rate, novel-family recall,
calibration drift, selective risk, or cross-language transfer.

A publishable efficacy claim still requires a new locked
project/family/time-disjoint corpus, real benign hard negatives, legally usable
positive samples, an unseen-language or unseen-ecosystem slice, and no tuning
after test labels are opened. Report recall at fixed low FPR, group-bootstrap
intervals, Brier/ECE, risk coverage/AURC, abstention coverage, CPU/RSS, and
evidence usefulness.
