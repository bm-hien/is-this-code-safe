# MalIR 2026-08-15-r8 install-time network access

## Scope

This revision continues development-only hardening after `2026-08-15-r7`.
The sealed PyPI holdout and OMCBench test split remain unopened. Production
µMal remains the `2026-08-15-r3` seed-13 checkpoint; no residual model is
promoted.

r8 adds a neutral lifecycle capability:
`install_time_network_access|structural|high`. It applies when a network send
or receive occurs directly in install phase (`setup.py` module scope or an
install-named callable). The path does not assert exfiltration, malware intent,
or a causal data flow.

The structural score is 20: below the alert threshold, but high enough to make
an installation-time external communication side effect explicitly reviewable.
Normal runtime/import network activity keeps its existing event score and does
not receive this lifecycle path.

## Prevalence study

A read-only scan covered 551 exposed benign artifacts: 450 PyPI development
groups plus OMC validation benign artifacts. It found zero `setup.py`
install-phase network operations under the current exact API vocabulary.
The same scanner was positive-controlled on `byted_tbs`, where it found the
module-level GET in `setup.py`.

Across OMC malicious validation it found two artifacts with install-time
network access:

- `byted_tbs-0.1.0`: constant GET beacon during setup;
- `async-box-1.4.7`: downloads a ZIP during setup and subsequently executes
  extracted code. That sample already scores 30 from install-time execution.

The exposed zero-benign count is not a population prevalence guarantee. r8
therefore treats the pattern as a reviewable lifecycle side effect, not as a
malware purpose or alert-level condition.

## Validation behavior

`byted_tbs` moves from score 7 to 20. `async-box` remains 30 because its
existing install-time execution evidence is stronger. Across all 53 malicious
validation groups, `byted_tbs` is the only score change:

- r7 buckets: `>36: 24`, `20-36: 22`, `<20: 7`;
- r8 buckets: `>36: 24`, `20-36: 23`, `<20: 6`.

Paired against r7, zero PyPI development artifacts and zero OMC validation
benign groups change `context-causal-v6` score. The residual gate therefore
contains 163 benign and 23 malicious groups.

Browser MalIR-Lite mirrors the structural lifecycle path. Its scorer suppresses
the covered network event for this path only, so `setup.py` GET is 20 rather
than self-stacking 20 + 7. This scoped coverage rule avoids changing historical
browser scores for other structural motifs in the same revision.

## Strict development result

The strict run used the frozen Python 3.12.13 preparation image, two workers,
network disabled, bounded archive loading, and the frozen manifests. It scored
451 PyPI development artifacts / 450 groups and 200 OMC validation artifacts.
The runner refuses PyPI holdout and OMCBench test rows.

For `context-causal-v6`:

- maximum development benign score: **36**;
- threshold: `nextafter(36, +inf)`;
- malicious alerts: **24/53 (45.28%)**;
- wall time: **627.96 s**; child CPU: **1111.69 s**;
- Python regression suite: **219/219**; browser suite: **32/32**;
- `ff.py` remains rule 48 / REVIEW with raw µMal 2.13% and production
  support abstention.

Strict output directory:
`/workspaces/itcs-quarantine/context-causal-r8-install-network-2026-08-15-strict`.
SHA-256 values:

- `report.json`: `b26e5c03f6a110f7d24c62fb4754810f369c2de45c512a0353d257670031e5a2`;
- `pypi-development-predictions.jsonl`: `5191f364c38521354db0352835102563b72a9f262309d43b4464e1d10ab751db`;
- `omc-validation-predictions.jsonl`: `8cf28601cab4f4916ab9048220c9b92eebd54161a0c464f08365206b0bd7bd89`.

## Remaining blind spots

A separate sensitive-environment-to-GET scanner returned zero exposed benign
matches, but its positive control failed on `ctx-0.2.2`. Inspection explains
why: AWS credentials are first stored in `self.access` / `self.secret` inside
`__init__`, then a different method builds the GET URL from those attributes.
This is an object-attribute/direct-self-method provenance problem, not evidence
that broad ENV-to-GET classification is safe. r8 does not change that rule.

After r8, six malicious validation groups remain below score 20. The most
meaningful representation gaps are object-attribute flow (`ctx`), DNS/domain
shape (`tiktok_session_lite_sdk`), and user-data enumeration/path provenance
(`proxyfullscrapers`). `scrapeasy` and `exotel` contain legitimate-looking
scraper/SDK functionality, while `test_for_virus_spook` already has an exact
local-file-to-GET path whose score is a policy question rather than an extractor
blind spot.
