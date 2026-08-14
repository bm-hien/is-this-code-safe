# Effect and purpose context v1

Status: implemented research prototype, 2026-08-14.

This iteration addresses a specific failure mode: a detector can identify real
capabilities yet misclassify a dual-use program when it treats those capabilities
as the program's purpose. MalIR now records both without claiming to infer human
intent.

## Decision model

| Layer | Question | Output |
|---|---|---|
| Event evidence | What security-relevant operations appear? | Located MalIR events and occurrence counts |
| Behavior paths | Does a supported value or dependency reach a sink? | Data-flow, summary, proximity, or structural motifs |
| Effect summary | What enters, changes, and leaves the program? | Entry points, origins, destinations, transforms, and flows |
| Purpose candidate | Which whole-file role best explains those effects? | Label, qualitative confidence, reason, and supporting lines |
| Capability policy | How much reviewable capability is present? | Deterministic `capability_score` |
| µMal advisory | How similar is the context to its training roles? | Uncalibrated probability used only as bounded uplift |

Capability is not maliciousness. For example, `compile`, dynamic loading,
encoding, and file output can describe a compiler, packer, plugin host, malware
builder, or malware. A label such as `local-code-transformer` explains a
supported local input-to-artifact pipeline; it does not declare the output safe
or identify the author's intent.

## Static obfuscator case study

The user-supplied `ff.py` was inspected statically and kept untracked. It was
never imported, compiled, or executed, and no source text was copied into the
training set. Only sanitized role-shaped hard negatives were added.

The program's dominant observable pipeline is:

1. accept an input and output path from the CLI;
2. read local Python source;
3. parse and transform AST/VM structures;
4. compile, encode, compress, and render generated code; and
5. write a local generated artifact.

It has no detected network or subprocess operation. One import-time `exec`
creates AST aliases and remains reviewable. Of 858 calls to `__import__`, 857
use constant module names and are now contextual imports; only the variable
module name remains `DYNAMIC_IMPORT`. Calls to `compile` are represented as
`CODE_COMPILE`, not execution. Untyped `object.write(...)` is no longer presumed
to be a filesystem write.

| Measurement | Earlier behavior | Effect-aware v1 |
|---|---:|---:|
| Repeated signals/events shown by the browser | about 947 | 196 lexical events |
| Deterministic capability score | 46 | 48 |
| µMal probability | about 95.6% | about 0.36% |
| Final result | 63, suspicious | 48, review |
| Primary purpose candidate | none | `local-code-transformer` |

The capability score did not collapse because the file still contains operations
that deserve human review. The model can raise an in-gate decision, but it can
never lower this deterministic floor: `risk = max(capability, fused)`. This
prevents a weak or poisoned checkpoint from erasing concrete capabilities.

## EffectSummary contract

A file summary contains:

- `entrypoints`: for example `explicit-cli`, `library-callable`, or
  `import-time-effects`;
- `data_origins` and `data_destinations`;
- `transformations`, including code generation and code compilation;
- `flows`, such as `local-file-to-local-artifact` or
  `sensitive-data-to-network`;
- `purpose_candidates`, each with a label, confidence, reason, and lines; and
- `primary_purpose`, the strongest conservative candidate.

The Python frontend derives this from AST structure and event/motif evidence.
MalIR-Lite emits the same concepts from bounded lexical structure at lower
confidence. Neither frontend treats a candidate as proof of intent.

Model-visible tokens use a constant `FILE` boundary and coarse target classes
such as `file`, `network`, and `sensitive`. Concrete filenames, URLs, and package
identifiers no longer become unrelated hashed vocabulary entries. Effect and
purpose tokens are appended after normalized events and motifs. Repeated
semantic events are compacted before bounded-window inference.

The bundled V3 checkpoint trains on 72 rows from 24 behavior groups and
selects its epoch on 36 rows from 12 disjoint synthetic validation groups. The
loader rejects group or exact model-visible representation leakage. The
checkpoint and browser manifest declare
`feature_schema = malir.effect-context.v3`,
`calibration = temperature-scaled-validation`, and
`validation_kind = synthetic-group-disjoint-paired-effects`. V3 also binds
its training-support profile to the checkpoint so unsupported semantic context
cannot affect the capability score. These mechanics and validation results are
not a real-world security claim; see
[MICRO_TRAINING_V3_2026-08-14.md](MICRO_TRAINING_V3_2026-08-14.md).

## Research basis and limits

This design follows several complementary ideas:

- [CodeQL data-flow analysis](https://codeql.github.com/docs/writing-codeql-queries/about-data-flow-analysis/)
  separates sources, sinks, and propagation while warning that global flow costs
  more than local flow.
- [GraphCodeBERT](https://arxiv.org/abs/2009.08366) shows that where values come
  from is useful code structure beyond flat token sequences.
- [Mining Specifications of Malicious Behavior](https://www.cs.ucdavis.edu/~devanbu/teaching/289/Schedule_files/Mining%20Specifications%20of%20Malicious%20Behavior-1.pdf)
  models malicious behavior through dependencies between operations rather than
  isolated API presence.
- [Abstract interpretation](https://pcousot.github.io/publications/Cousot-SAS-97-LNCS-n1302-p388--394.pdf)
  motivates conservative semantic approximation without executing a program.
- [Limits of static malware analysis](https://sites.cs.ucsb.edu/~chris/research/doc/acsac07_limits.pdf)
  explain why obfuscation and dynamic behavior prevent complete conclusions.
- [SelectiveNet](https://proceedings.mlr.press/v97/geifman19a.html) motivates
  explicit abstention and risk/coverage reporting. V3 implements only a
  deterministic training-support boundary; the synthetic corpus cannot
  calibrate real-world selective risk.

Effect-aware v1 is a false-positive regression and representation change, not a
validated intent classifier. The next locked experiment needs a real,
project-disjoint dual-use corpus with compilers, minifiers, obfuscators, plugin
hosts, packers, build tools, malware builders, and malicious payloads. Useful
next steps are multi-task heads for capability/effect/maliciousness, explicit
out-of-distribution detection, calibrated risk-coverage thresholds, and
language-specific frontends that share the effect contract.
