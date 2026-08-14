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
5. builds conservative, same-function proximity motifs labeled
   `proximity:low` and gives them only weak rule weight; and
6. preserves line locations for every weighted signal.

MalIR-Lite intentionally does not claim full Python parsing. In particular,
multi-line calls, unusual aliasing, generated code, advanced f-strings, and
dynamic dispatch can evade or confuse it. It never labels a browser path as
proved data flow. The installed CLI remains the reference frontend because it
uses Python's bounded `ast` parser plus candidate-gated local value provenance.
Its `dataflow:high` and the browser's `proximity:low` labels are qualitative
evidence tiers, not calibrated probabilities.

## Full µMal model

The browser runs the same full µMal architecture and checkpoint exported for
the Python CLI. It is a local Transformer encoder, not a remote LLM call:

| Property | Value |
|---|---:|
| Layers | 2 |
| Attention heads | 4 |
| Hidden width | 96 |
| Feed-forward width | 192 |
| Maximum sequence | 256 hashed behavior tokens |
| Hashed vocabulary | 4,096 |
| Trainable parameters | 567,746 |
| On-demand float32 binary | 2,270,984 bytes |
| Training rows | 32 synthetic smoke examples |

The binary omits only the duplicate serialized language-model head because it
is tied to the token embedding and is not used by browser classification.
Inference tensors, classifier output, and token hashing otherwise match the
checkpoint. Generated smoke vectors verify browser probabilities against
PyTorch during JavaScript tests.

The input is a sequence of full MalIR-style phase, category, operation, target,
file, and motif tokens, not raw source. Rule scores outside 20–80 bypass model
inference; inside that uncertainty gate, the final score is 65% evidence score
and 35% model probability.

The bundled corpus is designed only to test plumbing. Its output must not be
used as a real-world efficacy claim. Real claims require project/family-
disjoint, time-aware evaluation under `docs/EVALUATION_PROTOCOL.md`.

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
