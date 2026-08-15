# MalIR v1 specification

MalIR is a deterministic, evidence-carrying intermediate representation for
security-relevant source behavior. Version 1 currently has a Python frontend,
but event names are intentionally language-neutral.

## File record

Each analyzed file emits:

| Field | Meaning |
|---|---|
| path | Display path relative to the scan root where possible |
| sha256 | Hash of the bytes actually parsed |
| bytes_read | Parsed byte count |
| truncated | Whether the extractor byte limit was reached |
| event_limit_reached | Whether additional behavior events were suppressed |
| parse_error | Sanitized syntax/recursion error or null |
| events | Ordered evidence-bearing behavior events |
| behavior_paths | Bounded data-flow, direct-call summary, proximity, and structural motifs |
| effect_summary | Conservative entrypoint, origin, destination, transform, flow, and purpose context |
| tokens | Deterministic model sequence |

Oversized files are skipped by the scanner rather than partially parsed under
normal defaults. The truncated field remains in the schema for direct extractor
use and future streaming frontends.

## Event schema

| Field | Meaning |
|---|---|
| op | Language-neutral behavior operation |
| category | context, source, transform, or sink |
| target | Syntax-derived API, path, URL, or identifier |
| path | Source file |
| line, column | Zero/one-based AST location: line is one-based |
| function | Innermost function or <module> |
| phase | import, install, or runtime |
| detail | Short human-readable rule explanation |

The initial vocabulary includes IMPORT, ENV_READ, FILE_READ,
SENSITIVE_FILE_READ, FILE_WRITE, FILE_DELETE, PERSISTENCE_WRITE,
SYSTEM_DISCOVERY, ENCODE, DECODE, CODE_COMPILE, DYNAMIC_IMPORT,
UNSAFE_DESERIALIZE, NETWORK_RECEIVE, NETWORK_SEND, PROCESS_EXEC, and
DYNAMIC_EXEC. `CODE_COMPILE` represents compilation as a transformation;
compilation alone is not dynamic execution.

## Token form

Each event becomes one token:

~~~text
P:<phase>|C:<category>|O:<operation>|T:<normalized-target>
~~~

Behavior paths append `PATH:<motif>|K:<evidence-kind>|Q:<confidence>` so
causal evidence and weak proximity cannot collapse to the same model token.
Effect summaries append `EFFECT:<dimension>:<value>` for `ENTRY`, `ORIGIN`,
`DESTINATION`, `FLOW`, and `TRANSFORM`, plus
`PURPOSE:<candidate>|Q:<confidence>` tokens. Proximity paths remain reviewable
but do not create causal `EFFECT:FLOW` values. The serialized file record
retains the complete deterministic token list. Model input uses a constant
`FILE` boundary and compacts events by phase, category, operation, and a coarse
target class. Concrete filenames and URLs are not model vocabulary; repeated
syntax cannot crowd later semantic behavior out of a bounded context.
Sparse features use signed BLAKE2b hashing over one-to-three-token n-grams.
µMal uses a separately personalized BLAKE2b hash into a fixed 4,096-token
default vocabulary.

Hashing makes the representation compact and streaming-friendly. Collisions are
possible and must be measured as an ablation against learned or explicit
vocabularies.

## Ordering rule

The extractor visits arguments of a call before emitting the outer call. Thus
nested source or transform operations precede their sink:

~~~python
exec(base64.b64decode(blob))
~~~

emits DECODE followed by DYNAMIC_EXEC. Imports retain source order. Files are
walked in stable lexical order.

## Phase semantics

- import: module-level behavior in an ordinary Python file.
- install: module-level behavior in setup.py or behavior inside common
  setup/install hook names.
- runtime: behavior inside other functions.

This is a conservative heuristic, not a complete model of Python packaging.
Future frontends should map equivalent lifecycle concepts to the same phases.

## Behavior paths

Each path carries `motif`, `score`, `reason`, `event_indexes`, `evidence_kind`,
and `confidence`. Event indexes refer to the ordered file event list.

| Evidence kind | Meaning | Default tier |
|---|---|---|
| dataflow | Bounded value provenance reaches a supported sink inside one callable | high |
| summary | Bounded provenance reaches a supported sink across a statically resolved direct call | medium |
| proximity | Source/transform and sink occur in a 12-event same-function window, but value flow is unproven | low |
| structural | The event itself establishes the motif; no value flow is required | high |

`confidence` is a qualitative analysis tier, not a probability, calibration
result, or malware likelihood. Proximity paths deliberately receive much lower
policy scores than data-flow paths.

The data-flow pass is flow-sensitive for local names and handles assignments,
container expressions, common transforms, comprehensions, loops, and
conservative branch joins. Unknown local calls conservatively propagate their
input provenance. A summary requires a bare call to one unique, unrebound
top-level definition in the same module with no lexical shadow in the caller.
It binds explicit or default arguments to a fresh local frame and merges return
provenance. Async callees require an immediate `await`; generator creation is
not treated as executing the generator body. Eligible crossings are reported
as `summary:medium`, while paths that remain inside one callable stay
`dataflow:high`.

The pass is bounded to 16 traces per value, 16 real events per trace, 256
emitted paths, a direct-call depth of 3, and 64 direct-call expansions per file.
Recursion and exhausted limits conservatively preserve input provenance. A
cheap event gate skips this second AST pass unless a supported source/sink pair
can exist; the broader file-level gate is considered only when a statically
resolved local call is present.

Supported motifs include:

| Motif | Data-flow or structural condition |
|---|---|
| credential_or_file_exfil | Environment/sensitive-file value reaches outbound payload |
| fingerprinting_transfer | Host-discovery value reaches outbound payload |
| file_to_network | Generic file-read value reaches outbound payload |
| download_execute | Network-received value reaches process or dynamic execution |
| encoded_execution | Decode/deserialization result reaches execution |
| install_time_execution | Execution occurs during an install phase |
| persistence_write | Write targets a common autostart location |
| destructive_file_action | Broad/user-data deletion or recursive deletion outside known temporary/build targets |

The analysis is not whole-program flow. Direct-call summaries cover only
unique, unrebound top-level functions reached through an unshadowed bare name in
the same module. Callable aliases, duplicate definitions, star imports, and
module rebinding are rejected rather than guessed. The pass does not model
imported or nested functions, methods, globals, closures, object attributes,
mutation, generator iteration, async scheduling beyond immediate `await`,
dynamic dispatch, decorators, exceptions, or other modules. Every path keeps
its supporting real event indexes for review; the internal call-boundary marker
is never serialized. Path tokens preserve motif, evidence kind, and confidence.
The selected µMal checkpoint still declares
`feature_schema = malir.effect-context.2026-08-15-r3`. MalIR 2026-08-15-r4
adds literal single-component `__import__` chains, assigned file-handle
provenance, legacy `urllib.urlopen`/`os.startfile` capabilities, and
sensitive-environment qualification. MalIR 2026-08-15-r5 additionally scopes
assignment aliases across functions/classes, preserves a verified raw-socket
type through SSL wrapping, models Python dotted-import binding correctly, and
permits host/file provenance in GET-like URL/`params` request arguments to form
causal transfer paths. Environment secrets, authentication headers, and cookies
are intentionally excluded from that GET rule. MalIR 2026-08-15-r6 additionally
resolves flat exact-arity tuple/list assignment aliases after evaluating all RHS
bindings; starred or dynamic unpacking remains conservative. The dated
representation also
distinguishes temporary/user-data/broad deletion targets and compiler/shell/
interpreter/build/package process targets. Historical V1/V2/V3 checkpoints
remain loadable, but they do not carry the dated representation guarantees. See
the [2026-08-15 checkpoint note](MALIR_MICRO_RESEARCH_2026-08-15.md), the
[r4 research note](MALIR_RESEARCH_2026-08-15-r4.md), the
[r5 research note](MALIR_RESEARCH_2026-08-15-r5.md), the
[r6 research note](MALIR_RESEARCH_2026-08-15-r6.md), and the historical
[V3 training note](MICRO_TRAINING_V3_2026-08-14.md).

See [the bounded-summary design note](BOUNDED_CALL_SUMMARIES.md) for its
research basis, conservative cases, and regression matrix.

## Effect and purpose context

`EffectSummary` separates whole-file context from isolated operations. It
records entrypoints, data origins and destinations, transformations, flows, a
primary purpose candidate, and ranked candidates with qualitative confidence,
reason, and supporting lines. Current candidates include local code transformer,
sensitive-data transfer, remote code executor, persistence modifier, and
destructive file operator.

Candidates require structural or motif support and are deliberately narrower
than human intent. The Python frontend derives them from AST structure; the
browser lexical frontend may emit the same candidate at lower confidence. A
local code transformer can still contain reviewable execution capability, and a
malicious program can disguise that role. See
[the effect/purpose decision record](EFFECT_PURPOSE_V1_2026-08-14.md).

## Risk and model separation

MalIR contains observations; detector weights and verdict thresholds are policy.
This separation allows the same IR to feed rules, sparse models, µMal, graph
models, or external review without changing extraction.

The default `semantic-top8-v1` policy groups equivalent event operations and
equivalent motif/evidence-kind pairs across the scan. Each group contributes
its maximum policy weight once, while report evidence retains an `occurrences`
count and the raw IR retains every event. The eight strongest distinct groups
are summed with a hard 100-point cap. This makes the rule score invariant to
copying the same URL, sink, or motif onto more source lines. Summary paths also
remove their covered source/sink event contributions. `legacy-top8` remains
available explicitly for reproducing earlier research baselines.

JSON exposes the deterministic score as both historical `rule_score` and the
clearer `capability_score`. A supplied model is consulted over the compacted
sequence even outside the 20–80 gate, so its probability remains observable for
audit. Inside the gate, fusion computes 65% capability plus 35% model
probability, then applies `risk = max(capability, fused)`. The model can raise an
ambiguous decision but cannot erase concrete capability evidence. `model_used`
means a supported sample entered this fusion gate; `model_consulted` also
includes advisory inference outside it. V3 additionally exposes
`model_supported`, `model_abstained`, token coverage, nearest train-group
similarity, and the unknown-token list. An abstained probability remains
auditable but cannot enter fusion. The current support profile remains v1; a
legal token absent from training can therefore still force abstention.

µMal evaluates at most 254 behavior tokens plus boundary tokens per window.
Longer compacted sequences use up to 16 overlapping windows and return the
maximum window probability rather than summing probabilities. These aggregation
and gate constants are bounded policy choices, not calibrated accuracy claims,
and require time-split validation.

## Versioning

JSON scan output uses malir.scan.v1, extraction output uses malir.ir.v1, sparse
models use malir.sparse-logistic.v1, and µMal checkpoints use
malir.micro-transformer.v1. Readers must reject unknown model schemas rather
than silently guessing compatibility.