# MalIR 2026-08-15-r4 research note

Status: development research. The deterministic MalIR changes in this note are
candidate production hardening; µMal remains the 2026-08-15-r3 checkpoint unless
an explicitly described later experiment is promoted.

## Evaluation boundary

All efficacy work in this revision uses only exposed development data:

- PyPI hard-negative **development** groups.
- OMCBench **validation** groups.
- Synthetic/source fixtures for regression mechanics.

PyPI holdout and OMCBench test remain sealed. The strict runner rejects those
splits, and the final development report states that neither was scored.

Historical corpus fingerprints are runtime-bound. The PyPI preparation was made
with Python 3.12.13 in the pinned image
`python@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36`.
The same source can produce a different normalized-AST hash under the Codespace
Python 3.12.1 runtime. Re-running verification in the pinned 3.12.13 image
reproduces the frozen source-set and normalized-AST hashes exactly; historical
manifests are therefore not rewritten.
## Accepted deterministic changes

The r4 candidate fixes representation and extraction failures that were found by
real development packages rather than by synthetic fixtures alone:

- Whitespace-only process targets are classified as `generic` instead of
  crashing `process_target_class()`.
- Literal single-component `__import__()` call chains are resolved conservatively,
  recovering nested `base64 -> compile -> exec` behavior. Dotted module names are
  deliberately not treated as full-module returns because Python `__import__`
  semantics depend on `fromlist`.
- `urllib.urlopen` is recognized as legacy network receive and `os.startfile` as
  process execution.
- The local flow pass tracks handles assigned by `handle = open(...)`, not only
  `with open(...) as handle`, retains literal file paths, and can connect a staged
  network file to later execution through a literal/basename path reference.
- Generic environment variables are no longer automatically credential sources.
  Credential-transfer motifs require a sensitive-named environment variable or
  a sensitive-file source.

These changes recover real causal chains such as staged download-to-execute and
encoded install-time execution without broad method-suffix matching.
## Strict development operating point

The final-scope strict run uses the frozen Python 3.12.13 preparation image and
scores 451 PyPI development artifacts (450 groups) plus 200 OMCBench validation
artifacts. For `context-causal-v6`:

| Metric | 2026-08-13 staged | 2026-08-15-r4 |
|---|---:|---:|
| Maximum development benign score | 38 | **36** |
| Frozen threshold | nextafter(38) | **nextafter(36)** |
| OMC malicious alert groups | 15 / 53 | **24 / 53** |
| OMC malicious group recall | 28.30% | **45.28%** |

For `context-cover-v2`, the benign ceiling falls from 53 to 50 while malicious
alerts increase from 10/53 to 16/53. `context-max-v1` keeps a benign ceiling of
93 but increases from 4/53 to 9/53 malicious alerts.

Paired group transitions for `context-causal-v6` are 29 `0->0`, 9 `0->1`,
0 `1->0`, and 15 `1->1`. The nine gained groups move from scores of 1, 7, or 18
to 40, 43, or 70; the gain is not merely an artifact of lowering the benign
threshold. A 20,000-resample paired group bootstrap gives a recall-difference
interval of roughly +7.5 to +28.3 percentage points around the observed +17.0.
## Rejected or deferred semantics

Two experiments improved individual malicious samples but are not part of the
final deterministic r4 scope:

- Treating GET-like calls as outbound sensitive transfer found direct secrets in
  request URLs, but it also labeled legitimate JupyterHub authentication in
  `mlflow-tracing` as credential exfiltration. The causal provenance was real;
  the semantic label was too strong. A future IR should distinguish network
  request/authentication from exfiltration rather than overload RECEIVE/SEND.
- Mapping `browser_cookie3.*` to `SENSITIVE_FILE_READ` recovered a cookie-to-
  webhook sample, but browser-session state is not a file semantic. A future
  operation such as `BROWSER_COOKIE_READ` and a session-transfer relation would
  preserve meaning without abusing the current vocabulary.

A further backlog item is bounded socket-receiver typing. The extractor already
tracks `socket.socket()` aliases, but wrappers such as `ssl.wrap_socket(sock)`
can erase that receiver type. Any fix must be exact/bounded and validated on
benign socket code; broad `.send()` or `.connect()` suffix matching is rejected.

Object-attribute provenance and network beacon/request semantics are also kept
for later work rather than being added package- or domain-specifically.
## µMal support experiment

The existing `malir.support-profile.v1` conflates schema legality with training
frequency. For example, `EFFECT:ENTRY:module_import` is a legal and very common
production token but is absent from the synthetic r3 train groups.

A temporary research implementation separated schema legality from training
frequency: legal unseen tokens did not reduce token coverage, while genuinely
unknown operations/effects still abstained. This implementation was used only
to test the hypothesis; it is not retained in the r4 production code.

The support unlock is **rejected for production**. On 164 benign ambiguity
representatives from the exploratory residual set, the same r3 weights became
supported on all rows and falsely escalated 12/164 (7.3%) to risk >= 50. Most
were legitimate package/build systems with install-time execution. This shows
that v1 support had been masking a training-distribution problem rather than
solving it. Production therefore remains on `malir.support-profile.v1`; the
correct next step is retraining/evaluating the residual model, not weakening
abstention to make coverage look better.
## Residual model baseline

The final r4 ambiguity region is capability 20-36 and contains 180 development
groups: 163 benign and 17 malicious. Canonical model tokens were regenerated in
the same frozen Python 3.12.13 runtime used for strict scoring. The payload-free
corpus SHA-256 is
`70cd5dd1ba36fa2b8cfe9afb47424f22445824a8079511f99bbb2364b53d33bb`.

A hashed sparse logistic baseline trained on these real residual tokens gives:

- Random stratified 5-fold OOF: AP 0.847, ROC AUC 0.983 at 200 epochs.
- At 100 epochs, about 1% FPR recovers 7/17 malicious groups and about 2% FPR
  recovers 13/17.
- Positive token-similarity clustering at Jaccard >= 0.5 produces seven clusters
  with sizes `[10, 2, 1, 1, 1, 1, 1]`.
- Keeping those positive clusters disjoint across folds drops AP to about 0.64,
  confirming substantial campaign/behavior concentration.
- Under the cluster-disjoint stress test, about 2% FPR recovers 8-9/17 and about
  5% FPR recovers 14/17, depending on training duration.

The representation therefore contains useful residual signal, but random-fold
results are optimistic. Campaign-aware evaluation is mandatory before efficacy
claims or model promotion.
## Remaining blind spots and hard negatives

After final deterministic r4, the 53 OMC malicious validation groups split into
12 below 20, 17 at 20-36, and 24 above 36. The remaining low-score cases include
several distinct research problems rather than one missing weight:

- receiver typing through wrappers such as `ssl.wrap_socket(sock)`;
- browser cookie/session sources that deserve a dedicated semantic type;
- object-attribute provenance for values assembled into requests;
- network beacon/request semantics where a callback is suspicious by context but
  carries no proven sensitive local value;
- generic file-to-network and local file-to-process cases that need more context
  before their policy scores can safely increase.

`ff.py` remains a useful dual-use hard negative rather than training evidence.
Under final r4 Python extraction it has capability 34/review and raw r3 µMal
probability about 2.1%; the production v1 support profile abstains. No causal
malware behavior path is produced. This is desirable: dynamic execution,
encoding, compilation, and imports remain reviewable capabilities without
forcing a local transformer/obfuscator into a malware-like label.

The current benign ceiling is pywin32 at 36. Several near-ceiling benign packages
contain build/install deletion or execution behavior, so future scorer work must
model lifecycle and deletion target/scope rather than simply increasing weights.
## Representation capacity observation

The final residual corpus contains only 98 distinct semantic token strings. The
current 4,096-bucket hashed tokenizer maps them to 97 buckets and still exhibits
one real collision: bucket 3167 contains both
`EFFECT:FLOW:local_file_to_network` and
`P:runtime|C:transform|O:CODE_COMPILE|T:generic`.

This is the same semantic collision previously observed in synthetic V3 data.
Meanwhile, the 4,096 x 96 token embedding table contributes 393,216 parameters,
roughly 69% of the 567,746-parameter model. On the current residual support this
is poor parameter efficiency: the model spends most capacity on unused hash
buckets while preserving a collision among observed tokens.

Future µMal experiments should therefore compare explicit/factorized semantic
embeddings against the hashed model at equal or lower CPU/parameter budget.
Scaling the existing hashed Transformer is not justified by the current data.
### Cluster-definition sensitivity

Token-similarity clustering is only a proxy for malware family/campaign identity.
At 100 sparse epochs, changing the positive connected-component threshold changes
the apparent OOF difficulty materially:

| Positive Jaccard edge | Cluster sizes | AP | TP at ~2% FPR |
|---:|---|---:|---:|
| 0.4 | `[12, 3, 1, 1]` | 0.52 | 4 / 17 |
| 0.5 | `[10, 2, 1, 1, 1, 1, 1]` | 0.64 | 8 / 17 |
| 0.6 | many small clusters | 0.78 | 13 / 17 |
| 0.7 | all singletons | 0.82 | 14 / 17 |

Therefore no single similarity threshold is treated as a family ground truth.
The strong sensitivity is itself evidence that the current 17 positive residual
groups do not support a robust generalization claim. Future locked evaluation
needs real family/campaign metadata or substantially broader malicious support.
## µMal residual nested-CV

Frozen production µMal r3 ranks the final residual corpus poorly: AP 0.379,
ROC AUC 0.860, and zero malicious groups recovered at approximately 1% FPR.
Its synthetic-training confidence is therefore not a useful low-FPR residual
ranking on this development distribution.

A from-scratch residual experiment keeps the current 567,746-parameter
architecture but uses positive class weighting. Positive Jaccard >= 0.5 clusters
remain intact; for each outer fold a different fold is reserved for early
stopping/calibration, so outer labels never select epoch or temperature.

This nested cluster-disjoint run obtains AP **0.512**, ROC AUC **0.905**, and
Brier score 0.094. Approximate operating points recover 3/17 at 1% FPR, 4/17 at
2%, 9/17 at 5%, and 11/17 at 10%. Best epochs vary from 4 to 34 across folds.

Thus real residual training improves µMal over the frozen r3 checkpoint but the
full Transformer still underperforms the sparse cluster-disjoint baseline. The
large variation in selected epoch is additional evidence of model instability
under the current positive support.
### Small-Transformer ablation

A smaller hashed Transformer keeps vocab size 4,096 but uses max length 128,
width 32, four heads, one layer, and FFN width 64. It has 143,842 parameters
(about one quarter of full µMal) and a roughly 0.58 MB checkpoint.

On the same nested Jaccard-0.5 cluster-disjoint protocol it performs worse than
both the full residual Transformer and sparse baseline: AP 0.260, ROC AUC 0.783,
with 1/17 recovered near 1% FPR and 3/17 near 2% FPR. Best epochs range from 1
to 25 across folds.

The small model still spends 135,168 parameters, about 94% of its total, on
token and positional embeddings. Merely reducing Transformer depth/width does
not solve the representation inefficiency. Explicit/factorized embeddings and a
sparse residual model remain higher-priority experiments than further scaling or
shrinking the current hashed architecture.

No residual checkpoint from these experiments is promoted. Production µMal
remains the 2026-08-15-r3 seed-13 checkpoint with support profile v1.
