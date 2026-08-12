# Browser demo architecture

The GitHub Pages demo is deliberately static. It has no API, server-side
runtime, telemetry, or package installation step. The page loads four
first-party assets: HTML, CSS, the analyzer, and the embedded model weights.

## Security boundary

- User source is handled as text and is never passed to `eval`, `Function`,
  an import mechanism, a worker, or a subprocess.
- A 1 MB input bound limits browser memory and CPU use.
- Dynamic result elements are created with DOM APIs and `textContent`; source
  text is never inserted as HTML.
- The page Content Security Policy sets `connect-src 'none'`, so application
  scripts cannot send HTTP, WebSocket, or event-stream requests.
- The repository has no third-party JavaScript runtime dependency.

This boundary does not control browser extensions, a modified browser, copied
results, or a compromised GitHub account. Review the deployed commit before
using the demo for sensitive proprietary source.

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

## µMal Nano

The browser model is a real Transformer encoder, not a remote LLM call:

| Property | Value |
|---|---:|
| Layers | 1 |
| Attention heads | 2 |
| Hidden width | 16 |
| Feed-forward width | 32 |
| Maximum sequence | 48 behavior tokens |
| Vocabulary | MalIR operations, motifs, and install phase |
| Trainable parameters | 3,538 |
| Embedded ES module | 72,620 bytes |
| Training rows | 32 synthetic smoke examples |

Training combines binary classification with masked behavior-token prediction.
The input is a sequence of operation and motif tokens, not raw source. Rule
scores outside 20–80 bypass the model; inside that uncertainty gate, the final
score is 65% evidence score and 35% model probability.

The bundled corpus is designed only to test plumbing. Its 100% training
accuracy is expected overfitting and must not be used as an efficacy result.
Real claims require project/family-disjoint, time-aware evaluation under
`docs/EVALUATION_PROTOCOL.md`.

Reproduce the generated module on CPU:

```bash
.venv/bin/python scripts/train_web_model.py --epochs 500 --threads 2
node --test web/tests/*.test.mjs
```

## Deployment

`.github/workflows/pages.yml` tests the JavaScript engine, uploads only
`web/`, and deploys it through the protected `github-pages` environment.
Every push to `main` that changes the demo triggers a new deployment.
