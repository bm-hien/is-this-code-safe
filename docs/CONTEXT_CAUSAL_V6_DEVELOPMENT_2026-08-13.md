# Context-causal V6 development result — 2026-08-13

Status: **passes the existing development eligibility gate, but the PyPI holdout remains sealed**.
No PyPI holdout score and no OMCBench test score was read during this work.

The purpose of this iteration was to reduce hard-negative alert saturation without
obtaining a vacuous threshold. The acceptance rule is unchanged from
`PYPI_HARD_NEGATIVE_PROTOCOL_2026-08-12.md`: choose the threshold strictly above
the maximum development-benign group score, then require at least 20% OMCBench
validation malicious-group recall before any holdout is authorized.

## Development result

| Aggregation | Max development-benign | Frozen threshold | OMC validation malicious-group recall | Eligible |
| --- | ---: | ---: | ---: | --- |
| `legacy-top8` (published V2 baseline) | 100 | >100 | 0/53 (0%) | no |
| `context-max-v1` | 93 | 93.00000000000001 | 4/53 (7.55%) | no |
| `context-cover-v2` | 53 | 53.00000000000001 | 8/53 (15.09%) | no |
| `context-role-v3` | 43 | 43.00000000000001 | 9/53 (16.98%) | no |
| `context-role-v4` | 46 | 46.00000000000001 | 5/53 (9.43%) | no |
| `context-causal-v5` | 42 | 42.00000000000001 | 10/53 (18.87%) | no |
| `context-causal-v6` | **38** | **38.00000000000001** | **12/53 (22.64%)** | **yes, development only** |
| `context-causal-v6` + staged-file provenance | **38** | **38.00000000000001** | **15/53 (28.30%)** | **yes, development only** |

V3, V4, and V5 are recorded as negative development experiments only; their
implementations are not retained in the final scorer surface. V3 reduced structural
evidence too broadly, V4 suppressed real malicious installer activation, and V5
stopped just below the non-vacuity gate.

## Semantic fixes discovered from hard negatives

Three false-positive mechanisms were fixed before tuning aggregation:

1. `setUp()` was lower-cased to `setup` and therefore mislabeled as an install
   hook. Install-hook matching is now case-sensitive, so unittest lifecycle
   methods remain runtime code.
2. Method writes such as `handle.write(payload)` used the payload as the file
   target. Text containing `pth` or persistence-like strings could therefore
   become `PERSISTENCE_WRITE`. File-method targets now come from the receiver
   path where it can be resolved, and `.pth` matching is filename-based rather
   than an arbitrary substring search.
3. A module-defined helper named `compile` was indistinguishable from
   `builtins.compile`. Module callables are now predeclared for name resolution,
   so local helpers do not become `DYNAMIC_EXEC`; explicit `builtins.compile`
   remains detected.

These are extraction/name-resolution corrections, not score exceptions for
specific packages. Browser MalIR-Lite received the phase and persistence-path
semantic fixes; module-callable shadowing remains an AST-backend precision
feature.

## Context-causal aggregation

`context-cover-v2` first stops high-confidence paths from double-counting their
constituent events. V5/V6 then make the aggregation causal rather than simply
adding every unique operation observed anywhere in one callable:

- exact `dataflow:high` paths retain their full motif score and cover their
  constituent event evidence;
- `proximity:low` becomes the strongest covered event plus only the weak
  relation bonus, instead of event A + event B + motif;
- standalone destructive-file structure falls back to the underlying delete
  event weight rather than receiving a second structural amplification;
- ambient/context operations contribute at most one contextual term in ordinary
  code unless a path makes them causal;
- auxiliary test/docs/example/benchmark code keeps its strongest contribution
  instead of summing unrelated test-harness APIs;
- orchestration code only combines install/persistence activation with exact
  dataflow; unrelated build/cleanup operations do not accumulate into a high
  score.

V6 adds one narrower rule to V5: a standalone `UNSAFE_DESERIALIZE` event is a
context-only contribution unless it participates in a proximity or data-flow
path. This fixed the remaining development outlier where a large subprocess
implementation contained `PROCESS_EXEC`, `pickle.loads`, environment access,
and file writes in the same large function but with no evidence connecting the
deserialization to execution. Linked `UNSAFE_DESERIALIZE -> DYNAMIC_EXEC`
continues to score through `encoded_execution`.

The top PyPI development scores after V6 were `dill=38`, `gevent=35`,
`mysql-connector-python=35`, and `swebench=35`. The maximum OMCBench validation
reference-benign score was 34.

## Staged-file provenance extension

A false-negative audit found packages that downloaded remote bytes, wrote those
bytes to a symbolic filename, then executed that same filename. The earlier
intraprocedural pass lost provenance at the filesystem boundary and therefore
produced only weak proximity evidence. The bounded flow pass now carries remote
provenance through a file write when the destination is a resolvable path
variable, then joins it only when the same path variable appears in an execution
position. Reassigning the path kills the staged provenance, and executing a
different path does not inherit it.

Execution-position handling is deliberately narrower than generic subprocess
co-occurrence. Direct staged paths and known launchers/interpreters such as
`python`, `sh`, `start`, and `sys.executable` qualify; permission preparation such
as `chmod +x file` does not become exact payload execution. When an exact
`download_execute:dataflow` path exists, weaker proximity paths for the same motif
are dominated rather than added as a second score contribution.

The final development-only rerun kept the maximum benign score at **38** and
raised OMCBench validation malicious-group recall from **12/53 (22.64%)** to
**15/53 (28.30%)**. Relative to the post-cleanup V6 run, **0/451 PyPI development
artifact scores changed**. Newly recovered groups included a staged binary
downloader/executor, a download-to-Python-execution chain, and one normalized-AST
post-install malware family represented by multiple package names. Two already
detected malicious samples dropped from 100 to 67 after exact evidence correctly
dominated redundant proximity, but remained above threshold.

The final staged-flow run used the same sealed-development boundary and produced
`maximum_omc_validation_benign_score=34`. Its wall time was 659.80 seconds under
concurrent low-priority research scanning on the host; child CPU time was 984.59
seconds, so that wall time should not be compared as a clean performance result.
The payload-free output is outside Git at
`/workspaces/itcs-quarantine/context-causal-staged-flow-final-2026-08-13/`.

## Development support and isolation

The V6 run used exactly the same development support as the failed V2 study:

- PyPI reference-benign development: 451 artifacts / 450 normalized-AST groups;
- OMCBench validation reference-benign: 100 artifacts / 100 groups;
- OMCBench validation malicious: 100 artifacts / 53 groups;
- PyPI holdout artifacts scored: **0**;
- OMCBench test artifacts scored: **0**.

The full rescore ran in the pinned Python worker image
`python@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36`
with network disabled, a read-only root/repository/corpus, all capabilities
dropped, `no-new-privileges`, non-root UID, 2 CPUs, 3 GiB RAM, and 64 PIDs.
Archive, source-set, and normalized-AST fingerprints were checked before score
production. Wall time was 545.61 seconds; child CPU time was 960.48 seconds.

The payload-free development output is currently outside Git at
`/workspaces/itcs-quarantine/context-causal-v6-development-2026-08-13/`.

## Holdout status and freeze requirement

Passing the development gate does **not** authorize an ad-hoc holdout run. The
existing protocol requires an immutable study lock containing a full repository
commit, clean-worktree assertion, worker image, input/output hashes, thresholds,
and a candidate code/configuration fingerprint before the one-shot holdout may
be scored.

The study runner now accepts `--study-id`, `--baseline-rule-aggregation`, and
`--candidate-rule-aggregation` while retaining the V2 defaults. A future frozen
V6 study can therefore use the existing lock verifier rather than a parallel
confirmation path. The intended candidate setting is:

~~~text
--study-id itcs-context-causal-v6-2026-08-13
--baseline-rule-aggregation legacy-top8
--candidate-rule-aggregation context-causal-v6
~~~

The current worktree is intentionally **not** claimed as that immutable lock:
this development work is uncommitted and a pre-existing V2 result directory is
also untracked. The PyPI holdout remains sealed until a clean committed snapshot
is explicitly frozen. No threshold or V6 scoring rule may be changed after any
holdout score becomes visible.

## Interpretation

This is a development result, not a production malware-detection claim. The
improvement is useful because it crosses the preregistered non-vacuity guard
without observing the reference-benign holdout, but it can still fail the
confirmatory one-shot FPR test. If the holdout fails, that failure must be
published without threshold adjustment; a V7 would require a new study and a
fresh, independent confirmatory corpus.
