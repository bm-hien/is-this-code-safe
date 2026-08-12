# OMCBench Python pilot — 2026-08-12

Status: completed exploratory pilot. This is not evidence that ITCS is ready
for production malware classification.

## Bottom line

The candidate-gated local-flow pass improved ranking over the proximity-only
baseline, but neither system found a useful operating point at the locked 1%
false-positive-rate target. Both validation-selected thresholds were greater
than 1, so both systems detected 0/100 malicious test packages. The primary
claim is therefore unsupported.

Secondary, group-bootstrap ranking metrics moved in the expected direction:

| Test metric | Proximity only | Local flow | Paired delta | 95% group CI |
|---|---:|---:|---:|---:|
| Average precision | 0.5837 | 0.5954 | +0.0117 | [+0.0021, +0.0240] |
| Decision-margin AURC | 0.3775 | 0.3737 | -0.0038 | [-0.0082, -0.0006] |

These are exploratory ranking results, not a low-FPR detection claim. The rule
score is a heuristic risk score, not a calibrated probability; Brier score and
ECE in the raw report must not be interpreted as calibration evidence.

## Corpus and provenance

- Corpus: [Open Malicious Code Benchmark (OMCBench)](https://github.com/False-Positive-Community/open-malicious-code-benchmark)
- Pinned OMCBench commit: `f0722971eddb654c308106c9086ff69da5b0484b`
- ITCS analysis commit: `dbee8d05da6c46fc22088056f747fd6b190e8006`
- Manifest SHA-256: `c3b65ae73dbe78f5a9dbf18a77fb604c431848e4ed093f4c4b078eb6765fb84c`
- Archive-set fingerprint: `6ac772270e1f4ae824d981bcf93b0bb0a4c577660a106a1bdd5d900afe43d93a`
- Python packages: 400 total; 200 benign and 200 malicious
- Archive formats: wheel, ZIP, and TAR.GZ
- Python source analyzed: 10,208 files and 99,801,279 bytes
- Result status: 400/400 archives accepted by the bounded reader
- Parse-error files: 21; truncated files: 6
- Behavior paths: 182 proximity-only baseline paths; local-flow mode retained
  98 fallback proximity paths and proved 89 exact dataflow paths

OMCBench contains real malicious packages. No archive or source payload is
committed to this repository. The checked-in artifacts contain labels, hashes,
timings, counts, scores, warnings, and public archive names only.

## Isolation and non-execution boundary

The normal Codespace was treated as credential-bearing and therefore not as a
malware sandbox. Research ran inside a second short-lived Docker worker with:

- no network namespace (`--network none`);
- read-only root filesystem and read-only corpus/repository mounts;
- a separate output-only writable mount;
- all Linux capabilities dropped and `no-new-privileges` enabled;
- non-root UID, 2 CPU limit, 3 GiB memory limit, and 64 PID limit;
- a 256 MiB `noexec,nosuid,nodev` temporary filesystem.

The immutable worker image was
`python@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36`.
The worker had no Codespace home directory or GitHub credential mount.

The runner did not call pip, import package modules, execute setup hooks,
compile bytecode, or launch package code. It never extracted an archive to
disk. It read bounded `.py` members into memory and passed their bytes to
`ast.parse` through the ordinary ITCS extractor.

The archive reader rejects traversal paths, duplicate case-folded paths,
symlinks, non-regular TAR members, encrypted ZIP entries, excessive member or
byte counts, oversized source members, long paths, and excessive compression
ratios. Unsupported archive formats fail closed.

## Split and duplicate control

Exact file-set hashing found 400 distinct Python source sets. Identifier- and
literal-normalized AST hashing reduced them to 338 provisional analysis groups:

| Grouping fact | Count |
|---|---:|
| Normalized-AST groups | 338 |
| Duplicate groups | 16 |
| Packages inside duplicate groups | 78 |
| Largest group | 21 |
| Cross-label normalized groups | 0 |

All members of a normalized group were closed into one split before any
prediction was evaluated. Bootstrap resampling used `group_id`, not package
rows. This prevents renamed or lightly modified family variants from making
the confidence interval artificially narrow.

Deterministic split support was:

| Split | Benign packages/groups | Malicious packages/groups |
|---|---:|---:|
| Validation | 100 / 100 | 100 / 53 |
| Test | 100 / 100 | 100 / 85 |

The split is group-random because OMCBench does not provide enough family and
time metadata for the locked temporal study. It is suitable for a pilot only.

## Locked primary result

Each system selected its own threshold on validation at target FPR 1%, then
applied that threshold unchanged to test. The two-system claim gate used a
Bonferroni-adjusted 97.5% one-sided bound for each system.

| Quantity | Proximity only | Local flow |
|---|---:|---:|
| Validation-selected threshold | 1.0000000000000002 | 1.0000000000000002 |
| Test recall | 0/100 (0%) | 0/100 (0%) |
| Test false positives | 0/100 | 0/100 |
| Empirical test FPR | 0% | 0% |
| 97.5% FPR upper bound | 3.62% | 3.62% |

With 100 benign normalized-AST groups treated as independent in test, zero
observed false alerts still permits a population FPR as high as 3.62% at the
declared confidence. Missing maintainer/family metadata may reduce the true
effective support further.
At least 368 independent benign groups with zero alerts would be needed for
this joint 1% gate. Claim status: `underpowered-target-fpr`.

## Exploratory fixed-threshold error analysis

These thresholds were inspected after the locked result and are explicitly
claim-ineligible:

| Threshold | Baseline TP/FP | Candidate TP/FP | Delta TP/FP | Group p-value |
|---:|---:|---:|---:|---:|
| 0.25 | 72 / 55 | 72 / 55 | 0 / 0 | 1.000 |
| 0.50 | 51 / 44 | 55 / 44 | +4 / 0 | 0.125 |
| 0.75 | 40 / 28 | 42 / 29 | +2 / +1 | 1.000 |
| 1.00 | 32 / 21 | 34 / 21 | +2 / 0 | 1.000 |

At threshold 0.50 the local-flow candidate recovered four malicious rows and
introduced no extra benign row, but the exact two-sided paired group test was
not significant (`p = 0.125`) and FPR remained unusably high at 44%.

Local flow changed 16 package scores: 15 malicious and one benign, spanning 12
normalized-AST groups. The recovered evidence included exact flows such as
`ENV_READ -> ENCODE -> NETWORK_SEND`, `FILE_READ -> NETWORK_SEND`, and
`DECODE -> DYNAMIC_EXEC`.

The benign changed package was `databricks-sql-connector` with a real
`FILE_READ -> NETWORK_SEND` path in client code. This is an important hard
negative: exact value flow proves data movement, not malicious intent.

## CPU observations

The complete run, including normalized-AST fingerprinting, two scan variants,
and 2,000 paired group bootstraps, took 158.78 seconds on the limited worker.

| Package timing | Proximity only | Local flow |
|---|---:|---:|
| Analysis median | 8.07 ms | 8.52 ms |
| Analysis p95 | 326.55 ms | 363.55 ms |
| Total median incl. archive read | 21.27 ms | 21.84 ms |
| Total p95 incl. archive read | 883.08 ms | 927.55 ms |

On test rows, mean total latency delta was +1.96 ms with a paired 95% group CI
of [-0.94, +4.67] ms; the median delta was +0.88 ms with CI
[-2.12, +2.10] ms. One randomized pass is adequate for a pilot but not a
strong CPU-performance claim.

## Interpretation

The experiment supports keeping bounded local flow as an evidence primitive:
it improved ordering and exposed concrete source-to-sink paths at small
observed cost. It does not support the current package-level score as a
detector. The additive rule score saturates on large legitimate packages, so
validation can meet 1% FPR only by selecting an unreachable threshold.

This result changes the next research priority. Adding a larger model now
would hide the scoring problem rather than solve it.

## Next experiments

1. Replace package-wide evidence summation with per-file/per-callable
   aggregation, top-k pooling, and explicit package-size normalization.
2. Split generic file-to-network behavior into sensitive-source, public-data,
   protocol-client, and unknown-context variants; use benign network clients as
   mandatory hard negatives.
3. Add negative/context evidence for legitimate installers, SDKs, backup tools,
   package managers, and security utilities.
4. Fit any probability calibration on validation only after the score has been
   redesigned; do not calibrate the current saturated rule score.
5. Collect at least 368 independent benign groups for the 1% joint gate, and
   thousands more for a meaningful 0.1% target.
6. Obtain provenance dates and family/campaign metadata for a true forward-time
   and family-disjoint study.
7. Compare redesigned rules with sparse MalIR logistic regression before
   spending CPU on µMal.

## Reproduction

The runner requires a pinned local OMCBench checkout. It intentionally does not
download data or weaken isolation automatically. Run it only from a disposable
worker with no reusable credentials:

~~~bash
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 64 \
  --memory 3g --memory-swap 3g --cpus 2 --user 1000:1000 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=256m \
  -v /path/to/itcs:/repo:ro -v /path/to/omcbench:/corpus:ro \
  -v /path/to/empty-output:/out:rw -w /repo \
  python@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36 \
  python scripts/omcbench_pilot.py /corpus -o /out \
  --seed 20260812 --target-fpr 0.01 --bootstrap 2000 \
  --container-image python@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36
~~~

The output directory must be empty. The runner verifies the corpus commit and
manifest hash, records the immutable image digest, randomizes variant order per
package, and refuses to overwrite prior results.

## Published metadata

The reproducible, payload-free outputs are in
[`research/results/omcbench-python-2026-08-12/`](../research/results/omcbench-python-2026-08-12/):

- `study.json`: provenance, configuration, grouping, environment, support, and
  output SHA-256 values;
- `paired_report.json`: primary gate, paired bootstrap, ranking, transitions,
  and exploratory threshold tables;
- `proximity_predictions.jsonl` and `local_flow_predictions.jsonl`: aligned
  metadata-only package predictions;
- `sample_audit.jsonl`: archive hashes, safe-reader counts, warnings, timings,
  and aggregate evidence counts;
- `SHA256SUMS`: independent digests for all five generated result files.

Recorded SHA-256 values:

~~~text
c5d7b6778212c69fcacc8e8cc46774cfb27571ab51b164bb41dde060c57c6c45  local_flow_predictions.jsonl
6af9a4f9fe4628f01ea2043cfa03b408048c5b7e289531f202e0b754ad4fa04c  paired_report.json
0df64641118ca675f4f87cef8d0a01cc7e78a650332159bd8cc23d3567cb5da0  proximity_predictions.jsonl
654738c01823a4e7dd6919563f7c056db1e85e29acdb5c2531bfcc3ca7b5263f  sample_audit.jsonl
0481e7ed3fc7469593e86941597790e54a001bd120a3431ecfa0c2dd286f31fe  study.json
~~~

`study.json` is excluded from its own embedded output-hash map to avoid a
recursive digest; `SHA256SUMS` independently covers it. The raw corpus remains
quarantined outside git.
