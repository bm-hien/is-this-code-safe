# MalIR 2026-08-15-r7 browser-session semantics

## Scope

This revision continues development-only hardening after `2026-08-15-r6`.
The sealed PyPI holdout and OMCBench test split remain unopened. Production
µMal remains the `2026-08-15-r3` seed-13 checkpoint; no residual model is
promoted.

r7 introduces a dedicated `BROWSER_COOKIE_READ` source and a distinct
`browser_session_transfer` behavior path. Browser cookies are not represented
as ordinary file reads, and session transfer is not conflated with generic
credential/environment transfer.

## API boundary

The exposed malicious corpus uses exact calls to
`browser_cookie3.chrome`, `chromium`, `edge`, `firefox`, and `opera`.
r7 recognizes only those qualified APIs. A custom object method such as
`custom.chrome()` does not match. Import aliases such as
`import browser_cookie3 as bc; bc.firefox()` are resolved normally.

A read-only prevalence scan covered 551 exposed benign artifacts (450 PyPI
development groups plus OMC validation benign artifacts). None contained
`browser_cookie3` source references. This does not prove population prevalence;
it only bounds the exposed development evidence used for this revision.

## Evidence contract

In the Python frontend, a proven cookie value reaching `NETWORK_SEND` produces
`browser_session_transfer|dataflow|high` with score 36. An isolated cookie read
has event weight 12. A cookie read near unrelated telemetry remains
`proximity|low`; it does not create a causal effect flow.

The browser MalIR-Lite frontend intentionally stays weaker. It emits the coarse
`BROWSER_COOKIE_READ` capability and may emit
`browser_session_transfer|proximity|low`, but it never upgrades this lexical
co-occurrence to `dataflow:high` or `EFFECT:FLOW:browser_session_to_network`.

Effect context records `browser-session` as a distinct origin. A causal Python
path maps to `browser-session-to-network` and a high-confidence
`sensitive-data-transfer` purpose candidate.

## Target and validation behavior

`xss-0.0.8` previously exposed only the outbound POST and scored 15. r7 proves
four independent browser-cookie-to-POST paths (Edge, Chrome, Firefox, Opera),
each `dataflow:high`, and raises the package to 36. The threshold remains
strictly above 36, so this moves the sample into the residual/model-consultable
region rather than forcing a deterministic alert.

Across all 53 malicious OMC validation groups, `xss` is the only group whose
`context-causal-v6` score changes:

- r6 buckets: `>36: 24`, `20-36: 21`, `<20: 8`;
- r7 buckets: `>36: 24`, `20-36: 22`, `<20: 7`.

No malicious group decreases. Paired against r6, zero PyPI development
artifacts and zero OMC validation benign groups change score. The residual gate
therefore contains 163 benign and 22 malicious groups.

## Strict development result

The strict run used the frozen Python 3.12.13 preparation image, two workers,
network disabled, bounded archive loading, and the frozen manifests. It scored
451 PyPI development artifacts / 450 groups and 200 OMC validation artifacts.
The runner refuses PyPI holdout and OMCBench test rows.

For `context-causal-v6`:

- maximum development benign score: **36**;
- threshold: `nextafter(36, +inf)`;
- malicious alerts: **24/53 (45.28%)**;
- wall time: **616.55 s**; child CPU: **1115.96 s**;
- Python regression suite: **218/218**;
- browser web regression suite after parity update: **31/31**;
- `ff.py` hard-negative probe remains rule 48 / REVIEW with raw µMal 2.13%
  and production support abstention.

Strict output directory:
`/workspaces/itcs-quarantine/context-causal-r7-browser-session-2026-08-15-strict`.
SHA-256 values:

- `report.json`: `e913cb69cbaa2f3dc1bbad0469821264b8dd0ddd0420db41ea3002247e84561b`;
- `pypi-development-predictions.jsonl`: `5191f364c38521354db0352835102563b72a9f262309d43b4464e1d10ab751db`;
- `omc-validation-predictions.jsonl`: `5b7d3ca0294b341541191933c603054cd8b4561f665b3b0c540b330448060735`.
