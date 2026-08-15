# MalIR / µMal dated research note — 2026-08-15

Status: implemented research revision, not a production efficacy claim.

Selected contract: `malir.effect-context.2026-08-15-r3`.
Selected checkpoint seed: 13.

## Scope

This revision follows three representation failures found by static counterexample
analysis. No inspected package source was executed, imported, installed, or
compiled. The sealed PyPI holdout and OMCBench test split were not scored.

The checkpoint remains the 567,746-parameter, two-layer behavior Transformer.
The change is primarily what MalIR preserves for the model and which controlled
contrasts appear in its synthetic training corpus.

## r1 — preserve evidence strength

Earlier model input collapsed `dataflow:high` and `proximity:low` into the same
`MOTIF:<name>` token. A real environment-to-network flow and an unrelated secret
read plus harmless telemetry therefore received the same µMal probability.

Dated path tokens now use:

`PATH:<motif>|K:<evidence-kind>|Q:<confidence>`

Purpose tokens now carry qualitative confidence. A `proximity` path remains
visible for review but no longer creates a causal `EFFECT:FLOW` value.

On the selected checkpoint, the AST counterexample changed from an identical
~98% prediction to:

| Probe | Rule | µMal | Final |
|---|---:|---:|---|
| Unrelated secret + telemetry | 24 | 1.97% | 24 / low-signal |
| Exact sensitive-data flow | 58 | 98.71% | 72.25 / suspicious |

Browser MalIR-Lite cannot prove value flow, so its lexical exfiltration demo
remains `proximity:low`: rule 28, µMal 6.85%, final 28 / review.

## r2 — deletion context

A single `os.remove("cache.tmp")` previously had the same model-visible
representation as the synthetic destructive-delete positive. Training could not
solve contradictory labels without changing the IR.

Deletion targets now use coarse classes: `delete_temporary`,
`delete_user_data`, `delete_broad`, or `delete_generic`. Temporary/build cleanup
does not create `destructive_file_action`; broad, user-data, and non-temporary
recursive deletion remain structural evidence.

Selected-checkpoint probes:

| Probe | Rule | µMal | Final |
|---|---:|---:|---|
| `cache.tmp` cleanup | 10 | 1.40% | 10 / low-signal |
| `user_documents` delete | 28 | 98.39% | 52.64 / suspicious |

## r3 — process target context

Install-time process execution also had an exact representation conflict:
`setup.py` invoking a compiler, shell, or Python interpreter all compacted to
`PROCESS_EXEC|T:generic`.

The extractor now resolves the command head for common subprocess forms. Model
targets use coarse classes: `process_compiler`, `process_shell`,
`process_interpreter`, `process_build_tool`, `process_package_tool`, or
`process_generic`. Concrete commands remain outside model vocabulary.

Selected-checkpoint probes:

| Probe | Rule | µMal | Final |
|---|---:|---:|---|
| install compiler | 48 | 2.12% | 48 / review |
| install shell | 48 | 98.35% | 65.62 / suspicious |

The deterministic floor is intentionally unchanged in this revision; model
training cannot lower concrete capability evidence.

## Dataset

`examples/micro_train_2026_08_15_r3.jsonl` contains 144 synthetic rows:

| Split | Rows | Groups |
|---|---:|---:|
| Train | 90 | 30 |
| Validation | 54 | 18 |

The dated additions use source-first records passed through the production
Python extractor, including `source_path="setup.py"` for lifecycle-sensitive
examples. The loader rejects group crossings, representation crossings, and
conflicting labels. Two representation overlaps and one conflicting-label audit
were discovered and fixed during construction; the guards were not weakened.

Fingerprints:

- dataset SHA-256: `431b5ae6275fc2a632fdb0ad77408f2a08f4ffe37cf065b35bd80051edd8d70b`;
- split fingerprint: `b47a170d81384b8cf41a2db712adfde09459f3e6ae61aeca54a38def2caca0c7`;
- selected checkpoint SHA-256: `abb7d1465a660a29932804311b605902e71f1f7b3a3d83fd4edec562e7478c03`;
- browser binary SHA-256: `e2739c0d40b7471eb4846fc30e64c62714df34beec02dd3b936572bfe06fe42a`.

## Seed selection

Seed selection remained validation-NLL based.

| Seed | Best epoch | Val accuracy | NLL | Brier | ECE-10 | Min pair gap | Max variant drift |
|---:|---:|---:|---:|---:|---:|---:|---:|
| **13** | **30** | **54/54** | **0.040185** | **0.002550** | **0.038825** | **0.753864** | **0.080604** |
| 29 | 13 | 53/54 | 0.101547 | 0.022160 | 0.059608 | 0.251861 | 0.423905 |
| 47 | 40 | 52/54 | 0.097346 | 0.023170 | 0.060620 | 0.288006 | 0.625018 |

Seed 13 is selected. Temperature fitting remained conservative and returned
`T = 1.0` for all three runs.

## Negative results and limits

The dated corpus is still synthetic and remains too easy for an efficacy claim.
A hand-written rule that uses high-confidence path identity plus one
`process_compiler` exception classifies all 90 train and 54 validation rows.
Therefore perfect seed-13 validation does not justify the Transformer by itself.

A dependency-free sparse MalIR logistic baseline reached 51/54 validation rows
at 50–200 epochs. This is worse than selected µMal on the synthetic split but
still too close, and neither result substitutes for a locked real-package test.

The current `malir.support-profile.v1` also remains intentionally strict. Scanning
ITCS `src/` gives 92.3% unique-token coverage and abstains because
`EFFECT:ENTRY:module_import` is legal MalIR but absent from the training token
set. The threshold was not relaxed to hide this limitation.

The four legacy OOD probes all still abstain. Their selected-checkpoint raw
probabilities are 4.49%, 1.39%, 15.14%, and 8.87%; a high unsupported raw
probability is no longer required as a regression invariant.

The exposed development study still indicates a larger extractor/scorer problem:
21/53 OMCBench validation malicious groups score below the current 20-point µMal
gate, while 17 missed groups lie in the 20–38 ambiguity region. µMal cannot
recover behavior that MalIR does not represent.

## Verification

- Python: `198 passed`.
- Browser: `27 passed`.
- Ruff passes on all changed ITCS Python files; repository-wide Ruff remains
  noisy only because the pre-existing untracked `ff.py` test file is excluded
  from this work.
- PyTorch and browser smoke vectors match with the exported model binary.

## Reproduce

~~~bash
make bootstrap-micro
.venv/bin/python scripts/build_micro_dataset_2026_08_15_r3.py
.venv/bin/python scripts/train_web_model.py --train --seed 13
.venv/bin/python -m pytest -q
npm run test:web
~~~

Future efficacy work still requires a locked project/family/time-disjoint corpus,
real dual-use hard negatives, selective-risk reporting, and no tuning after test
labels or sealed holdout scores are opened.

## Development rescore status

A strict development-only rerun was attempted with the existing 450-group PyPI
development split and 200 OMCBench validation artifacts. The runner failed
closed before writing predictions because the current normalized-AST fingerprint
for `setuptools 84.0.0` differed from the frozen preparation manifest.

Its archive/source-set fingerprint still matched exactly. The normalized-AST
expected value was `a5470e6c...caf1d`; the current value was
`40413bc1...f01c`. No holdout or OMCBench test row was selected, and no partial
score file was used. The prior 15/53 context-causal-v6 development result is
therefore historical context only, not a post-r3 validation result.

A future dated study must either reproduce the original fingerprinting worker or
materialize a newly locked development/test corpus under a new study identity;
the fingerprint check must not be bypassed for a claim.
