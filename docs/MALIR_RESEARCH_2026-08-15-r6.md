# MalIR 2026-08-15-r6 and residual-model study

## Scope

This note continues development-only research after `2026-08-15-r5`
(`8f4e094`). The sealed PyPI holdout and OMCBench test split remain unopened.
No new µMal checkpoint is promoted; production µMal remains
`2026-08-15-r3` seed 13.

The accepted deterministic r6 change is exact tuple/list assignment binding.
The model section records why the current exposed residual corpus is not a
sufficient model-selection benchmark despite apparently strong sparse scores.

## Exact destructuring assignment

Python evaluates all right-hand values before rebinding destructured targets.
r6 models flat tuple/list assignments only when target/value arity is exact and
there is no starred target. All RHS aliases are resolved before any target
binding is applied, so swaps such as `a, b = b, a` are not corrupted.

The change is generic Python semantics, not an obfuscation signature. Starred,
nested, or otherwise dynamic unpacking remains conservative.

### Prevalence and target case

A read-only AST survey covered 551 benign development/validation artifacts:
450 PyPI development groups plus OMC validation benign artifacts. Exact flat
destructuring assignments occurred in 283 packages. None directly aliased the
checked execution/process/network primitives such as `exec`, `eval`, `compile`,
`__import__`, `os.system`, `subprocess.run`, or `requests.post`.

The OMC malicious package `xolotxobrzatpu-0.0.0` contains a direct assignment
whose first pair is effectively `Theory = exec`. r5 missed it completely. r6
recovers one `DYNAMIC_EXEC` event and raises `context-causal-v6` from 0 to 27.

Across all 53 malicious validation groups, this is the only score change:

- r5 buckets: `>36: 24`, `20-36: 20`, `<20: 9`;
- r6 buckets: `>36: 24`, `20-36: 21`, `<20: 8`.

No malicious group decreases.

## Strict development result

The strict run used the frozen Python 3.12.13 preparation image, two workers,
network disabled, bounded archive loading, and the frozen split manifests.
It scored 451 PyPI development artifacts / 450 groups and 200 OMC validation
artifacts. The runner explicitly refuses PyPI holdout and OMCBench test rows.

For `context-causal-v6`:

- maximum development benign score: **36**;
- threshold: `nextafter(36, +inf)`;
- malicious alerts: **24/53 (45.28%)**;
- benign residual groups (20-36): **163**;
- malicious residual groups (20-36): **21**;
- malicious groups below 20: **8**;
- wall time: **616.04 s**; child CPU: **1119.01 s**.

Paired against r5, zero PyPI development artifacts and zero OMC validation
benign groups change `context-causal-v6` score.

Strict output directory:
`/workspaces/itcs-quarantine/context-causal-r6-destructure-2026-08-15-strict`.
SHA-256 values:

- `report.json`: `6819deffae978c2b6d0da1842935aa285c1ad47c88ee448d216edb208b04eefa`;
- `pypi-development-predictions.jsonl`: `5191f364c38521354db0352835102563b72a9f262309d43b4464e1d10ab751db`;
- `omc-validation-predictions.jsonl`: `370d43abc617353c70d02ae9981bbd6550e32792a16d236c94d0383ce3134440`.

## Residual corpus and apparent sparse advantage

The r5 residual token corpus contains 183 group representatives: 163 benign
and 20 malicious at capability score 20-36. It preserves the exact production
model token sequence plus a semantic-deduplicated diagnostic view. Corpus
SHA-256 is
`ba3e5a479480e983d5c9c917ccf144679ce8afc1a2a98f25869b42b6b5c9a09e`.

Frozen µMal r3 raw ranking has AP 0.462 on these rows, while support v1 accepts
0/183 rows. A 100-epoch sparse logistic baseline appears much stronger: at
positive-token Jaccard 0.40 cluster-disjoint stress, raw-sequence AP is 0.721
and semantic-deduplicated AP is 0.632.

Those sparse numbers are **not model-selection evidence**. Package size/layout
is strongly confounded with label. Across the residual corpus, median exact
token count is 33 for benign versus 13 for malicious; median `FILE` boundary
count is 10 versus 2.

The confound persists inside OMC alone (20 benign residual vs 20 malicious):

- `-FILE count` alone: AP **0.935**, AUC **0.950**;
- `-raw token count` alone: AP **0.871**;
- sparse raw, cluster threshold 0.40: AP **0.913**;
- `-semantic token count` alone: AP **0.838**;
- sparse semantic, cluster threshold 0.40: AP **0.832**.

After removing `FILE`, generic imports, and module/library entry context, sparse
behavior-only AP is 0.717 while negative behavior-token count alone is 0.823.
At about 1-5% FPR that behavior-only model recovers only 1/20 positives.

Therefore the current residual corpus cannot justify promoting sparse or µMal.
A future residual benchmark must be family-aware **and** match package size/file
count (or otherwise remove that nuisance variable) before model selection.
Evaluation JSON SHA-256:
`85d503d465c97a10dfa239cee5b41d6d9ace407ffd05cfcd90fa3a39721bd6c8`.

## Remaining deterministic blind spots

After r6, eight malicious validation groups remain below capability score 20.
They are not one problem class. Current candidates include browser-session
sources (`browser_cookie3`), DNS side-channel shape, broad user-file transfer,
and install-time constant GET beacons. Legitimate SDK/scraper examples also
remain in the labelled set and should not be forced upward merely to improve
benchmark recall.

The earlier DNS experiment remains rejected because ordinary
`gethostname() -> gethostbyname(hostname)` resolution produced benign uplift.
The next DNS design needs an explicit `DNS_LOOKUP` operation plus bounded
static-domain-shape context. Browser cookies likewise need a dedicated source
operation rather than being mislabeled as generic sensitive-file reads.
