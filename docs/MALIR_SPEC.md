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
| behavior_paths | Bounded data-flow, proximity, and structural motifs |
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
SYSTEM_DISCOVERY, ENCODE, DECODE, DYNAMIC_IMPORT, UNSAFE_DESERIALIZE,
NETWORK_RECEIVE, NETWORK_SEND, PROCESS_EXEC, and DYNAMIC_EXEC.

## Token form

Each event becomes one token:

~~~text
P:<phase>|C:<category>|O:<operation>|T:<normalized-target>
~~~

Behavior paths append a token of the form MOTIF:<name>. File boundaries are
added by the detector before model input. Sparse features use signed BLAKE2b
hashing over one-to-three-token n-grams. µMal uses a separately personalized
BLAKE2b hash into a fixed 4,096-token default vocabulary.

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
| dataflow | Bounded local value provenance reaches a supported sink | high |
| proximity | Source/transform and sink occur in a 12-event same-function window, but value flow is unproven | low |
| structural | The event itself establishes the motif; no value flow is required | high |

`confidence` is a qualitative analysis tier, not a probability, calibration
result, or malware likelihood. Proximity paths deliberately receive much lower
policy scores than data-flow paths.

The data-flow pass is flow-sensitive for local names and handles assignments,
container expressions, common transforms, comprehensions, loops, and
conservative branch joins. Unknown local calls conservatively propagate their
input provenance. It is bounded to 16 traces per value, 16 events per trace,
and 256 emitted paths. A cheap per-callable event gate skips this second AST
pass unless a supported source/sink pair can exist.

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
| destructive_file_action | File or directory deletion |

The analysis is intraprocedural: it does not prove flows through function
returns, globals, object attributes, mutation, dynamic dispatch, or other
modules. Every path keeps its supporting event indexes for review. Model tokens
remain `MOTIF:<name>` regardless of evidence kind, so this additive metadata
does not invalidate existing v1 sparse or µMal checkpoints.

## Risk and model separation

MalIR contains observations; detector weights and verdict thresholds are policy.
This separation allows the same IR to feed rules, sparse models, µMal, graph
models, or external review without changing extraction.

The default cascade calls a supplied model only when the rule score is from 20
through 80. Model probability is combined with the rule score at 35%/65%.
Those constants are initial policy values and require calibration on a
time-split validation set.

## Versioning

JSON scan output uses malir.scan.v1, extraction output uses malir.ir.v1, sparse
models use malir.sparse-logistic.v1, and µMal checkpoints use
malir.micro-transformer.v1. Readers must reject unknown model schemas rather
than silently guessing compatibility.