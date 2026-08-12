# OMCBench Python pilot metadata

These files are the payload-free outputs of the 2026-08-12 ITCS paired pilot.
The experiment compared proximity-only rules with candidate-gated local flow on
400 pinned OMCBench Python archives.

No package archive, Python source, extracted payload, token sequence, or source
snippet is present here. `sample_audit.jsonl` contains public archive names and
hashes plus aggregate counts, timings, warnings, and scores.

Read the [full report](../../../docs/OMCBENCH_PILOT_2026-08-12.md) before
interpreting the metrics. The locked low-FPR claim was unsupported; secondary
ranking results are exploratory.

## Files

- `study.json`: frozen provenance, limits, grouping, support, and hashes.
- `paired_report.json`: aligned comparison and group-bootstrap results.
- `proximity_predictions.jsonl`: baseline metadata-only predictions.
- `local_flow_predictions.jsonl`: candidate metadata-only predictions.
- `sample_audit.jsonl`: one safe-ingestion audit row per public archive.
- `SHA256SUMS`: independent digests for all five generated result files.

## Integrity

~~~text
c5d7b6778212c69fcacc8e8cc46774cfb27571ab51b164bb41dde060c57c6c45  local_flow_predictions.jsonl
6af9a4f9fe4628f01ea2043cfa03b408048c5b7e289531f202e0b754ad4fa04c  paired_report.json
0df64641118ca675f4f87cef8d0a01cc7e78a650332159bd8cc23d3567cb5da0  proximity_predictions.jsonl
654738c01823a4e7dd6919563f7c056db1e85e29acdb5c2531bfcc3ca7b5263f  sample_audit.jsonl
0481e7ed3fc7469593e86941597790e54a001bd120a3431ecfa0c2dd286f31fe  study.json
~~~

`study.json` is intentionally absent from its own embedded output-hash map to
avoid recursion; `SHA256SUMS` independently covers it. The study records the
pinned OMCBench commit, manifest SHA-256, archive-set fingerprint, repository
commit, and immutable worker-image digest.

The JSON reports carry schema identifiers. Prediction rows follow the public
metadata contract consumed by `itcs compare-predictions`.
