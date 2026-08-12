# Contributing to ITCS

Thank you for helping make source-code security analysis cheaper and more
auditable.

## Safety first

Do not submit live malware, credentials, private source, weaponized archives,
or a test that imports or executes an untrusted fixture. Suspicious-shaped
fixtures must be inert, use reserved domains such as example.invalid, and only
be parsed as text.

Read docs/THREAT_MODEL.md before working with real research data. Real samples
belong in an isolated worker with no reusable secrets or outbound network, not
in this repository or a normal Codespace.

## Development

~~~bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
make lint
make test
~~~

The core scanner must remain usable without PyTorch or NumPy. Optional µMal
work uses make bootstrap-micro. Avoid adding a heavyweight dependency to the
default installation.

## Changes we welcome

- conservative Python API mappings with benign counterexamples;
- bounded extraction or value-flow improvements;
- hard-negative tests for legitimate tools;
- reproducible CPU/memory benchmarks;
- dataset leakage audits and temporal evaluation;
- a JavaScript frontend that maps into the existing MalIR contract;
- explanation faithfulness measurements.

Every detector change should include both a positive fixture and a benign case
that must not be flagged. Do not broaden suffix heuristics without measuring
false positives.

## Pull requests

Keep changes focused. Explain the behavior being modeled, threat assumptions,
expected false positives, and validation performed. Run make lint and make test.
For model claims, include the locked split, seed, thresholds, confidence
intervals, checkpoint size, and target CPU measurements.

New operations or schema changes require an update to docs/MALIR_SPEC.md.
Breaking serialized formats require a new schema version.

## Research claims

Synthetic fixtures are acceptable for correctness and performance tests, but
not for efficacy claims. Accuracy, F1, or training-set results alone are not
enough. Follow docs/EVALUATION_PROTOCOL.md and report recall at fixed false
positive rates on package-, family-, and time-disjoint data.

By contributing, you agree that your contribution is licensed under MIT.