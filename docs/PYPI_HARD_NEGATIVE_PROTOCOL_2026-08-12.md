# PyPI hard-negative study protocol (2026-08-12)

Study ID: `itcs-pypi-hard-negative-2026-08-12-v1`

Status: preregistered before acquiring artifacts or computing any score in
the new corpus. This document may receive typo-only corrections after the
protocol commit; substantive deviations must be listed in the final report.

## 1. Research question and primary gate

Does a CPU-cheap, context-concentrated rule aggregation avoid alert saturation
on large legitimate Python packages while retaining non-zero sensitivity to
malicious packages on development data?

The confirmatory outcome is candidate performance on 450 independently
grouped, popular-PyPI reference-benign holdout groups. The primary gate passes
only if all of the following hold:

1. the candidate threshold is selected without holdout scores;
2. the threshold is at most 100 and detects at least 20% of OMCBench
   validation malicious groups;
3. the holdout has at least 450 normalized-AST groups;
4. zero holdout groups alert; and
5. the exact one-sided 97.5% upper FPR bound is below 1%.

With 450 zero-alert groups, that bound is about 0.816%. These packages are
called *reference-benign*, not ground-truth benign. A zero observed count is
never described as proof of zero population false positives.

## 2. Contamination firewall

The published OMCBench test results have already been inspected. Every
OMCBench row whose frozen split is `test` is claim-ineligible and must be
rejected by the study runner before scoring.

Allowed development inputs are:

- OMCBench `validation` rows, for malicious-sensitivity and legacy-benign
  checks only;
- the fresh PyPI development half, for hard-negative threshold selection;
- synthetic repository fixtures, for implementation mechanics only.

The PyPI holdout assignment is materialized without detector scores. Once the
candidate, code commit, configuration, and threshold have been frozen, the
holdout is scored exactly once. Any rerun after inspecting those results is
exploratory and must use a new study ID.

## 3. Frozen population source

Project ranking is the Top PyPI Packages monthly snapshot:
`https://hugovk.dev/top-pypi-packages/top-pypi-packages.min.json`.

Frozen snapshot metadata:

- `last_update`: `2026-08-01 06:34:08`;
- byte SHA-256: `bb36eb336787975315f66eb0834073e9b0a72593c486cd2d704991046f465b04`;
- expected rows: 15,000;
- ranking is used only to select popular project names.

Artifact metadata, URLs, sizes, yanked flags, versions, and hashes come from
the official PyPI project JSON endpoint. The acquisition plan takes projects
in ranking order and requests the latest version reported by PyPI.

OpenSSF OSV is queried for each exact PyPI name/version. A candidate is
excluded if any returned advisory ID starts with `MAL-`. No OSV result means
only “no known OSV malicious-package advisory at collection time.”

## 4. Deterministic artifact selection

For each latest release, consider only non-yanked files with a lowercase
SHA-256, a positive declared size, and size at most 25 MiB. Choose one file by
this stable preference order, then by filename and SHA-256:

1. source distribution ending `.tar.gz`;
2. source distribution ending `.zip`;
3. universal wheel ending `-py3-none-any.whl` or `-py2.py3-none-any.whl`;
4. any `.whl`.

Unsupported extensions, missing releases, API inconsistencies, known OSV
`MAL-` records, hash mismatch, size mismatch, and download failure are logged
as exclusions. No label- or detector-dependent exclusion is permitted.

Acquisition stops after 1,050 verified artifacts or 4 GiB of declared bytes,
whichever comes first. If fewer than 900 normalized groups remain, the study
fails rather than changing limits after scores are seen.

## 5. Isolation and non-execution

Network acquisition runs in a disposable child Docker worker with no mounted
credentials or host home, a read-only root filesystem, dropped capabilities,
`no-new-privileges`, bounded CPU/RAM/PIDs, and only a quarantine output mount.

Artifact analysis runs in a separate worker with `--network none`. Both
workers:

- never run `pip`, installers, build backends, or package metadata code;
- never import, compile, or execute package source;
- never extract payload files onto disk;
- validate archive paths, member types, counts, sizes, compression ratio, and
  nested-archive limits;
- read supported Python members as bounded bytes in memory;
- mount the ITCS repository and corpus read-only during scanning.

Raw archives and source stay outside Git. Only hashes, package metadata,
aggregate metrics, commands, and payload-free audit records may be published.

## 6. Grouping and blind split

Before any detector score is computed, successful artifacts are grouped by:

1. exact archive SHA-256;
2. exact normalized Python source-set hash; then
3. identifier- and literal-normalized AST hash.

Closure is transitive: any collision at a stage joins the same group. The
canonical group rank is the minimum popularity rank among members. The first
900 groups by `(canonical_rank, group_id)` form the locked corpus; later groups
are reserve-only and must not replace a scored holdout failure.

Groups are assigned using SHA-256 of
`itcs-pypi-hard-negative-2026-08-12-v1|group_id`. Sort by that value; even
positions become development and odd positions become holdout until each has
450 groups. The split manifest and its SHA-256 are frozen before scoring.

One project cannot cross splits. Any exact source-set, normalized-AST, archive,
project-name, or representation overlap across splits is fatal.

## 7. Frozen candidate: `context-max-v1`

The extraction frontend is identical for baseline and candidate and has local
data-flow enabled. Evidence generation and individual weights are unchanged.

The baseline uses the existing `legacy-top8`: sort all package evidence and
sum its top eight scores, capped at 100.

The candidate groups evidence by `(source path, enclosing function)`. Module
scope is a distinct function context. Inside each context:

- event evidence is deduplicated by operation, keeping the highest score;
- behavior-path evidence is deduplicated by `(motif, evidence_kind)`, keeping
  the highest score;
- `ANALYSIS_LIMIT` remains a distinct operation;
- the four highest retained items are summed and capped at 100.

The package rule score is the maximum context score, or zero when empty.
The ranked, bounded explanation list remains global and is not altered by
aggregation. The optional micro-model cascade is disabled in this study.

This scorer is intentionally small: one pass over evidence plus bounded sorts;
it introduces no learned weights, graph neural network, embedding, or LLM.

## 8. Development and threshold freeze

Neither scorer may be changed after any PyPI holdout score is visible.

For each system independently, use OMCBench validation benign groups plus the
450 PyPI development groups. Its frozen threshold is the next representable
floating-point value above the maximum benign development score. A system is
operating-point eligible only when that threshold is at most 100.

At that threshold, report OMCBench validation malicious group recall with raw
counts. Candidate eligibility additionally requires at least 20% recall. This
is a guard against obtaining low FPR with a vacuous never-alert threshold.

After development, write an immutable lock containing:

- full repository commit and clean-worktree assertion;
- worker image digest and complete command/configuration;
- corpus, audit, split, and development-prediction SHA-256 values;
- candidate and baseline thresholds;
- candidate source/config fingerprint;
- all exclusions and protocol deviations.

Only then may the holdout scoring command accept the lock.

## 9. Confirmatory analysis

The primary unit is the normalized-AST group. A group is a false alert if any
member score is greater than or equal to the frozen candidate threshold.

Report the raw alert-group numerator/denominator, empirical FPR, and exact
Clopper–Pearson one-sided 97.5% upper bound. Also report project-row results,
score distribution, size/file-count strata, and candidate-versus-baseline
paired transitions as secondary descriptive outcomes.

No malicious recall, precision, F1, PR-AUC, or production-wide safety claim is
made from this fresh corpus because it contains no new malicious holdout.

CPU measurements are descriptive: wall time, CPU time, peak RSS, package
median/p95/p99 latency, source bytes, Python file counts, and throughput. The
same worker, order, and extraction cache policy are used for both scorers.

## 10. Failure and stop rules

The confirmatory study fails, without threshold adjustment, if:

- snapshot hash or PyPI artifact hash verification fails;
- acquisition or grouping yields fewer than 900 eligible groups;
- a split leakage audit fails;
- the candidate development eligibility gate fails;
- the lock cannot reproduce the exact candidate fingerprint;
- holdout labels/scores are accessed before lock validation;
- the worker violates a resource, archive, or isolation constraint.

Failures and negative results are published. A failed group is never replaced
after holdout scoring begins. Operational interruption before any holdout score
is produced may resume only from verified immutable inputs.

## 11. Planned payload-free outputs

- acquisition source and unit tests;
- `collection.json` with source digests and exclusion counts;
- metadata-only `artifacts.jsonl` with project/version/hash/size;
- deduplication map and locked split manifest without source;
- development predictions and study lock;
- one holdout prediction file per frozen system;
- statistical summary and machine-readable report;
- human-readable report with limitations and exact reproduction commands.

All output files receive SHA-256 entries in a canonical checksum manifest.

## 12. Rationale and primary references

PyGuard reports that context-blind Python-package scanners produce many false
positives on complex popular packages and uses recent popular packages as hard
negatives. DONAPI likewise motivates ordered behavior combinations over
isolated suspicious APIs. MalGuard shows that small static feature models can
be competitive while raw sensitive-API presence is insufficient; its graph
analysis also motivates concentration rather than package-wide counting.

The ACSAC 2025 cross-ecosystem study shows benchmark-to-live degradation and
that deployment stakeholders require far lower FPR than balanced benchmark
metrics imply. Official PyPI JSON/Index specifications define artifact hashes,
sizes, yanked state, and project metadata; OSV defines the batch advisory API.

These references motivate the hypothesis but do not determine outcomes. The
exact URLs and access dates are recorded in the final report.