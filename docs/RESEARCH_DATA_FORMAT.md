# Research data format

This contract lets ITCS audit experiments without storing, opening, importing,
or executing a package. Both files are newline-delimited JSON. The commands
bound total bytes, line bytes, and row counts, and reject non-finite numbers.

The examples in `examples/research_*.jsonl` are synthetic metadata and scores.
They are documentation fixtures, not efficacy evidence.

## Dataset manifest

One row identifies one immutable artifact:

~~~json
{
  "sample_id": "opaque-study-id",
  "label": 0,
  "ecosystem": "pypi",
  "package": "normalized-name",
  "version": "1.2.3",
  "sha256": "64 lowercase hex characters",
  "first_seen": "2026-01-15",
  "group_id": "closed-package-family-group",
  "provenance": "curator record",
  "license": "evaluation permission",
  "content_kind": "source-tree",
  "split": "test",
  "representation_hash": "64 lowercase hex characters",
  "family": null,
  "campaign": null
}
~~~

### Required fields

| Field | Meaning |
|---|---|
| `sample_id` | Stable opaque identifier, unique in the study |
| `label` | `0`/benign or `1`/malicious |
| `ecosystem` | Registry or source ecosystem |
| `package`, `version` | Artifact identity used for grouping and audit |
| `sha256` | SHA-256 of the immutable artifact bytes |
| `first_seen` | ISO calendar date, never a model collection timestamp invented later |
| `group_id` | Closure over versions, forks, and known related samples |
| `provenance` | Curator/source record without credentials |
| `license` | Permission or license governing evaluation |
| `content_kind` | Source tree, sdist, wheel, or other declared artifact kind |

### Optional audit fields

| Field | Meaning |
|---|---|
| `split` | Exactly `train`, `validation`, or `test` |
| `representation_hash` | Hash of the final ordered tokens visible to the model |
| `family` | Curator malware-family identity when known |
| `campaign` | Curator campaign identity when known |

Use `malir.manifest.hash_representation(tokens)` for the model-visible hash.
It length-prefixes every UTF-8 token before SHA-256, so token sequences such as
`["a", "bc"]` and `["ab", "c"]` cannot collide merely because of joining.

The manifest deliberately rejects payload-bearing fields including `source`,
`tokens`, `content`, `path`, and `archive_path`. Keep sample storage and
safe extraction in the isolated worker described by the threat model.

## Audit semantics

~~~bash
itcs audit-manifest manifest.jsonl --strict --json
~~~

The audit reports:

- duplicate sample IDs;
- exact-byte duplicates and conflicting labels;
- normalized package identities crossing splits or fragmented across groups;
- artifact groups crossing splits;
- identical model-visible representations crossing splits;
- family/campaign overlap;
- non-forward temporal ordering;
- missing split or representation hashes;
- label, split, and ecosystem counts;
- a canonical manifest fingerprint.

Artifact/group/representation leakage is an error. Family, campaign, temporal,
and missing-field findings are warnings because a debug study may intentionally
use a non-temporal or non-family-disjoint design. `--strict` makes warnings
fail the command too. Exit code 2 means the selected audit policy failed.

The schema is closed: unknown fields fail instead of being silently omitted from
the fingerprint. The fingerprint covers all accepted fields after canonical
sorting. Put it beside the repository commit and dependency lock in every
experiment record.

## Prediction file

Predictions are exported before metric computation. A row contains:

~~~json
{
  "sample_id": "opaque-study-id",
  "label": 1,
  "score": 0.83,
  "split": "test",
  "group_id": "closed-package-family-group",
  "period": "2026-07",
  "model_invoked": true,
  "latency_ms": 7.4
}
~~~

Required fields are `sample_id`, binary `label`, malicious probability
`score` in `[0, 1]`, `split`, and `group_id`. Optional `period`,
`model_invoked`, and `latency_ms` enable drift and conditional-compute
reporting. Sample IDs must be unique; unknown fields and symlinked input files
are rejected. The report includes an order-independent prediction fingerprint.

At minimum, the file needs non-empty validation and test splits. Training rows
may be retained for traceability but are not used by the evaluator.

## Locked evaluation

~~~bash
itcs evaluate-predictions predictions.jsonl \
  --target-fpr 0.001 --bootstrap 2000 --seed 0 --json
~~~

The evaluator:

1. chooses the lowest threshold satisfying empirical target FPR on validation;
2. freezes that threshold and applies it to test;
3. reports confusion counts, recall, precision, F1, AP, Brier, and ECE;
4. compares max-probability confidence with normalized distance from the
   locked operating threshold;
5. reports tie-aware risk-coverage points and AURC for both confidence rules;
6. bootstraps complete `group_id` units;
7. reports per-period metrics and conditional model usage when present;
8. reports both package-row and conservative `group_id` FPR bounds, and
   tests whether independent benign groups support the requested claim.

AURC is not a replacement for calibration, and calibration is not a replacement
for AURC. ECE asks whether probabilities match observed frequency. AURC asks
whether confidence ranks errors well enough for abstention. Decision-margin
AURC is the primary gate diagnostic because the low-FPR operating threshold is
usually not 0.5; max-probability AURC is retained as a declared comparator.

For zero false-positive groups in `n` independent benign groups, the exact
one-sided 95% upper bound is `1 - 0.05 ** (1 / n)`. A target of 0.1% needs at
least 2,995 groups even with no false alert. The report also shows row-level
FPR, but the claim gate uses the conservative group bound.

## Reproducibility boundary

The format records predictions rather than loading model checkpoints during
evaluation. This separates model execution from metric computation and lets
another researcher recompute the report without receiving malware or a model.

Do not edit test scores after seeing metrics. Preserve the raw prediction file,
its SHA-256, the audited manifest fingerprint, full command, seed, threshold
policy, repository commit, and environment lock. Any later run after inspecting
test labels is exploratory and must be labeled as such.
