# Threat model and safe handling

## Scope

ITCS accepts untrusted Python source as hostile text. Its job is to produce
review evidence without giving that source Python execution privileges. The
protected assets are the analyst workstation, Codespace credentials, network
identity, filesystem contents, and the integrity of scan results.

## Trust boundaries

The scanner may trust its own installed code and explicit configuration. It
must not trust:

- Python files being scanned;
- filenames, paths, encodings, comments, or type comments from a package;
- labels or paths in a contributed dataset;
- model checkpoints from unknown parties;
- archive metadata or symlinks.

## Safety invariants in version 0.5

- Source is opened as bytes, bounded, decoded with replacement, and passed to
  ast.parse.
- No inspected module is imported, compiled to bytecode, installed, or run.
- Local provenance is a second traversal of the already parsed AST; it performs
  no evaluation and is bounded by traces per value, trace length, and path count.
- A per-callable event gate skips provenance traversal when no supported
  source/sink combination exists.
- A provenance recursion/value error is reported and falls back to weak
  proximity evidence instead of aborting the whole scan.
- Files over the configured limit are skipped.
- Symlinked Python files are skipped and directory traversal does not follow
  symlinks.
- Common virtual environment, dependency, VCS, and build directories are
  excluded.
- Event targets contain syntax-derived identifiers or literals, never contents
  read from paths mentioned by the inspected program.
- Sparse checkpoints are data-only JSON with a schema check.
- µMal loading uses torch.load with weights_only=True, but checkpoints should
  still come from a trusted source.
- Research manifest audit reads bounded metadata JSONL only and rejects source,
  token, content, path, archive-path, and other payload-bearing fields.
- Prediction evaluation reads bounded numeric/metadata rows, rejects duplicate
  IDs and non-finite scores, and never loads a checkpoint or sample.
- Paired comparison requires aligned sample metadata and resamples only
  prediction rows; it does not resolve paths or inspect sample content.
- Tests never import suspicious or hard-negative files under tests/fixtures.

## Explicit non-goals

This prototype is not a containment sandbox, antivirus, EDR, package installer,
or proof that low-signal code is benign. It does not safely unpack adversarial
archives. It does not inspect binary wheels, native extensions, generated code,
or behavior fetched at runtime.

Do not point pip, npm, setup.py, or another package manager at an untrusted
sample. A Codespace or Docker container is not automatically a malware sandbox;
tokens and network access may still be reachable.

## Denial-of-service considerations

Python's parser still consumes CPU and memory on attacker-controlled syntax.
Current controls bound bytes per file, total bytes, file count, emitted
events, provenance traces per value, trace length, and behavior-path count.
Future archive support must additionally bound nesting depth,
compression ratio, extracted bytes, duplicate paths, and wall-clock time.

The current scanner is single-process. A production service should run parsing
in a short-lived worker with OS-level memory, CPU, syscall, filesystem, and
network limits.

## Expected evasions

Static syntax analysis can miss:

- reflective call construction and deep alias indirection;
- encrypted or remotely retrieved payloads;
- native code and unsafe build backends;
- runtime-generated import names, URLs, and paths;
- semantic flows split across functions, globals, object attributes, mutation,
  dynamic dispatch, or packages;
- environment-triggered branches and logic bombs;
- adversarial dead code designed to create false positives;
- equivalent APIs absent from the policy vocabulary.

It can also flag legitimate installers, deployment tools, debuggers, backup
clients, and security software. Evidence is shown so a reviewer can resolve
that ambiguity.

## Handling real malware research data

1. Work on a dedicated isolated worker with no reusable secrets.
2. Disable outbound network by default.
3. Keep samples encrypted at rest and record hashes/provenance.
4. Extract archives with path, size, ratio, and nesting controls.
5. Scan as text only for this project.
6. Never commit real samples to this repository.
7. Delete or quarantine workers according to the dataset license and policy.
8. Publish hashes and evaluation metadata, not redistributable malware.

## Reporting security problems

Open a private security report with a minimal non-malicious reproducer. Do not
attach live payloads, credentials, or samples that execute during reproduction.