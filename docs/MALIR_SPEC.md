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
| behavior_paths | Bounded proximity motifs |
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

Version 1 paths are local proximity motifs within one file and one function,
using a maximum preceding window of 12 events. Supported motifs include:

| Motif | Static evidence |
|---|---|
| credential_or_file_exfil | Sensitive source near outbound transfer |
| fingerprinting_transfer | Host discovery near outbound transfer |
| file_to_network | Generic file read near outbound transfer |
| download_execute | Remote input near process or dynamic execution |
| encoded_execution | Decode/deserialization near execution |
| install_time_execution | Execution during an install phase |
| persistence_write | Write to a common autostart location |
| destructive_file_action | File or directory deletion |

These are not claims of exact data flow. Every motif stores event indexes so a
reviewer can inspect its supporting operations. A future SSA/data-flow layer
should use a distinct schema version or attach a confidence field.

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