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

## Safety invariants in version 0.6

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
- The research archive reader supports only wheel/ZIP/TAR.GZ, reads `.py` member
  bytes in memory, and never materializes an archive tree on disk.
- It rejects traversal/control-character paths, case-folded duplicate paths,
  symlinks, non-regular TAR members, encrypted ZIP entries, unsupported formats,
  excessive member/path/source/uncompressed byte counts, oversized members, and
  excessive compression ratios.
- Source-set and normalized-AST grouping consume member bytes only; they do not
  import modules, resolve runtime dependencies, or evaluate annotations.
- The OMCBench runner verifies the pinned commit and manifest hash, refuses a
  nonempty output directory, writes only metadata, and records output hashes.
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
or proof that low-signal code is benign. The normal CLI does not accept package
archives. The research reader does not recursively inspect nested archives,
binary wheels, native extensions, generated code, or behavior fetched at
runtime, and it is not a substitute for OS isolation.

Do not point pip, npm, setup.py, or another package manager at an untrusted
sample. A Codespace or Docker container is not automatically a malware sandbox;
tokens and network access may still be reachable.

## Denial-of-service considerations

Python's parser and archive decompression still consume CPU and memory on
attacker-controlled input. Current controls bound bytes per file, archive and
member bytes, total source/uncompressed bytes, file/member count, path length,
compression ratio, emitted events, provenance traces per value, trace length,
and behavior-path count. Nested archives are not followed. The reader itself
does not enforce a wall clock, so the OS worker must impose CPU, memory, PID,
filesystem, and lifecycle limits.

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

1. Keep the corpus in a quarantine path outside the repository and record its
   source, license constraints, commit, manifest hash, and archive hashes.
2. Use a short-lived child worker with no home directory, secrets, or credential
   mounts; a normal Codespace or container is not sufficient by itself.
3. Disable outbound network and mount the repository/corpus read-only.
4. Prefer bounded in-memory member reads; never install, import, compile, or run
   a sample. Do not recursively follow nested archives.
5. Apply archive checks plus OS CPU, memory, PID, filesystem, and lifetime limits.
6. Never commit real samples, source snippets, or payload-bearing tokens.
7. Publish hashes and evaluation metadata only, and validate output fields before
   moving them back into the repository.
8. Delete or retain the quarantine according to the dataset license and policy.

## Reporting security problems

Open a private security report with a minimal non-malicious reproducer. Do not
attach live payloads, credentials, or samples that execute during reproduction.