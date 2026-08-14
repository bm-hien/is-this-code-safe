# Browser analyzer architecture

The GitHub Pages analyzer is deliberately static. It has no API, server-side
runtime, telemetry, or package installation step. Opening the page loads the
interface, the locally bundled Monaco editor, the lexical analyzer, and an empty
model runtime. It does not load a model checkpoint automatically.

The user must select **Download full model** before analysis is enabled. That
action dynamically imports the small model manifest, downloads `model.bin`
from the same GitHub Pages origin, verifies its SHA-256 digest with Web Crypto,
and installs float32 tensor views in memory.

## Security boundary

- User source is handled as text and is never passed to `eval`, `Function`,
  an import mechanism, a subprocess, or a remote service. Monaco may mirror the
  editor model into its same-origin worker for editor services only.
- A 1 MB input bound limits browser memory and CPU use.
- Dynamic result elements are created with DOM APIs and `textContent`; source
  text is never inserted as HTML.
- Content Security Policy limits scripts, connections, and workers to the same
  origin. Monaco requires inline theme styles, so `style-src` allows inline CSS;
  inline and remote scripts remain blocked.
- The model manifest contains a SHA-256 digest checked before weights install.
- Monaco is a pinned build dependency and is committed as static ESM, CSS, and
  worker assets. There is no CDN or runtime package fetch.

This boundary does not control browser extensions, a modified browser, copied
results, or a compromised GitHub account. Review the deployed commit before
using the analyzer for sensitive proprietary source.

## Source editor

Desktop browsers use Monaco 0.56.0 with Python tokenization, line numbers,
folding, find, bracket matching, indentation guides, multi-cursor editing, and
common code-editing commands. The build imports only the selected feature
registrations and runs the generic editor worker from the same origin. A plain
textarea stays available when Monaco or workers cannot initialize; coarse
pointer screens below 700 px use that fallback because Monaco does not support
mobile browsers.

The editor is independent from model loading. Controls become interactive
against the textarea fallback immediately; Monaco upgrades that editor
asynchronously instead of blocking the model button. `model.bin` is fetched
only after the user selects **Download full model**. The build replaces
Monaco's vendored sanitizer with the explicitly pinned DOMPurify 3.4.13
dependency; both the build and UI test reject a regression to the vendored
3.4.8 marker.

Rebuild and test the pinned browser assets with:

```bash
npm ci
npm run check:web
```

## MalIR-Lite frontend

GitHub Pages cannot execute the Python AST extractor. The browser therefore
uses a bounded lexical frontend that:

1. masks comments and string contents before identifying calls;
2. extracts string values separately for sensitive and persistence paths;
3. resolves common `import`, `from ... import`, and assignment aliases;
4. emits the same operation names used by MalIR;
5. distinguishes compilation from execution, constant imports from truly
   dynamic imports, and typed file APIs from unknown object methods;
6. builds conservative, same-function proximity motifs labeled
   `proximity:low` and gives them only weak rule weight;
7. summarizes entrypoints, origins, destinations, transforms, flows, and
   conservative purpose candidates; and
8. preserves line locations for every weighted signal.

MalIR-Lite intentionally does not claim full Python parsing. In particular,
multi-line calls, unusual aliasing, generated code, advanced f-strings, and
dynamic dispatch can evade or confuse it. It never labels a browser path as
proved data flow. The installed CLI remains the reference frontend because it
uses Python's bounded `ast` parser plus candidate-gated local value provenance.
Its `dataflow:high` and the browser's `proximity:low` labels are qualitative
evidence tiers, not calibrated probabilities.

## Semantic saturation

Rule scoring groups equivalent event operations and equivalent
motif/evidence-kind pairs before selecting the strongest eight distinct
signals. Repeating the same outbound call therefore increases an
`occurrences` counter but does not add the operation or motif weight again.
The full event and motif arrays remain in JSON for audit.

The model input applies a separate compaction key using phase, category,
operation, and a coarse target class. Network destinations share a network
class, so changing or repeating URL text cannot crowd other behaviors out of
the model sequence. The representative MalIR token remains inspectable; this
is input canonicalization, not a claim that frequency never matters.

The committed adversarial regression repeats the screenshot's outbound call
while varying later URLs:

| Outbound calls | Unique weighted signals | Capability score | Model tokens | Risk score |
|---:|---:|---:|---:|---:|
| 1 | 4 | 28 | 12 | 52.00 |
| 4 | 4 | 28 | 12 | 52.00 |
| 20 | 4 | 28 | 12 | 52.00 |

This establishes repeat invariance for that transformation only; it is not an
accuracy or false-positive-rate result.

## Effect and purpose profile

The result card separately shows deterministic capability and a conservative
whole-file purpose candidate. A local input-to-generated-artifact pipeline with
AST/compiler structure can be labeled `local-code-transformer`; network,
process, persistence, or sensitive-data flows block that benign-role shortcut.
The label explains observed effects and never proves author intent or safety.
The detailed `ff.py` hard-negative analysis and limitations are recorded in
[effect and purpose context v1](EFFECT_PURPOSE_V1_2026-08-14.md).

## Full µMal model

The browser runs the same full µMal architecture and checkpoint exported for
the Python CLI. It is a local Transformer encoder, not a remote LLM call:

| Property | Value |
|---|---:|
| Layers | 2 |
| Attention heads | 4 |
| Hidden width | 96 |
| Feed-forward width | 192 |
| Model context | 256 hashed tokens per window; up to 16 overlapping windows |
| Hashed vocabulary | 4,096 |
| Trainable parameters | 567,746 |
| On-demand float32 binary | 2,270,984 bytes |
| Training split | 72 rows / 24 synthetic behavior groups |
| Validation split | 36 rows / 12 disjoint synthetic behavior groups |

The binary omits only the duplicate serialized language-model head because it
is tied to the token embedding and is not used by browser classification.
Inference tensors, classifier output, and token hashing otherwise match the
checkpoint. Generated smoke vectors verify browser probabilities against
PyTorch during JavaScript tests.

The input is a sequence of normalized MalIR phase, category, operation,
target-class, effect, purpose, and motif tokens, not raw source. A constant
`FILE` boundary prevents filenames from becoming learned identifiers. A
32-token overlap carries local context between windows, and the maximum bounded
window probability is reported rather than adding probabilities as source size
grows.

After the checkpoint has been downloaded, every analysis consults µMal and
shows its probability. Inside the 20–80 gate, fusion is 65% capability and 35%
model probability, followed by `risk = max(capability, fused)`. The model may
raise an ambiguous decision but cannot lower concrete capability. Outside the
gate its probability is advisory.

V3 also checks every compacted sequence against a checkpoint-bound support
profile: exact train-token coverage plus nearest train-group Jaccard similarity.
Unknown MalIR tokens or a similarity below 0.20 produce `gate = abstained`.
The probability remains in JSON for audit, while fusion is disabled and the
deterministic capability score is unchanged. This is a conservative support
boundary, not a claim that distance detects all out-of-distribution programs.
JSON reports support, coverage, nearest similarity, unknown tokens, gate state,
window count, evaluated-token count, and whether input hit the window bound.

The V3 corpus is designed only to test group-disjoint training mechanics,
paired effect roles, semantic-context consistency, support abstention, and
browser/PyTorch parity. The manifest declares
`calibration = temperature-scaled-validation` and
`validation_kind = synthetic-group-disjoint-paired-effects`. The validation
set was used for epoch/seed selection and is not a test set. These results,
semantic saturation, support checks, and windowing are not detection-accuracy
claims. See [MICRO_TRAINING_V3_2026-08-14.md](MICRO_TRAINING_V3_2026-08-14.md).
Real claims require project/family-disjoint, time-aware evaluation under
[EVALUATION_PROTOCOL.md](EVALUATION_PROTOCOL.md).

Export the existing full checkpoint for the browser:

```bash
npm ci
make web-model
make test-web
```

To retrain the checkpoint first and then export it:

```bash
make web-model-train
make test-web
```

## Deployment

`.github/workflows/pages.yml` installs the locked build dependencies,
rebuilds Monaco, rejects stale committed assets, runs the JavaScript tests,
uploads only `web/`, and deploys it through the protected `github-pages`
environment. Every push to `main` that changes the analyzer or its editor
build inputs triggers a new deployment.
