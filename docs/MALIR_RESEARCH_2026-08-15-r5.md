# MalIR 2026-08-15-r5 development study

## Scope

This note records development-only hardening after `2026-08-15-r4` (`cac4814`).
It does not score the sealed PyPI holdout or the OMCBench test split, and it does
not promote a new µMal checkpoint. Production µMal remains `2026-08-15-r3`.

The strict run used the frozen preparation runtime:
`python@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36`
(Python 3.12.13), two workers, no network, and the existing bounded archive
reader.

## Accepted deterministic changes

1. Alias state is scoped across functions and classes instead of leaking through
   a file-wide mutable map. Function parameters and ordinary assignments can
   shadow inherited aliases without contaminating another callable.
2. Verified SSL wrapping preserves socket receiver type only when the wrapped
   argument is already proven to be a `socket.socket`. Arbitrary `.wrap_socket`
   names remain untyped.
3. GET-like request calls may act as causal request sinks only for URL/`params`
   provenance from host discovery or local files. Environment/token data,
   headers, cookies, and authentication are intentionally excluded.
4. `import package.submodule` now models Python binding semantics correctly:
   without `as`, the top-level package name is bound; with `as`, the alias binds
   the full module.

## Strict development result

For `context-causal-v6`, r5 preserves the r4 frozen operating point:

- maximum development benign score: **36**;
- frozen threshold: `nextafter(36, +inf)`;
- OMC validation malicious alerts: **24/53 (45.28%)**;
- PyPI development groups: 450;
- OMC validation artifacts: 200.

Strict output directory:
`/workspaces/itcs-quarantine/context-causal-r5-abcd-opt2-2026-08-15-strict`.
Artifact SHA-256 values:

- `report.json`: `03191f99e530395874d4e16f1e13cdee0cb9343b7fb807553220f1c509651160`;
- `pypi-development-predictions.jsonl`: `5191f364c38521354db0352835102563b72a9f262309d43b4464e1d10ab751db`;
- `omc-validation-predictions.jsonl`: `b3288b9e0dd2e459b309d97f9d21160376308519deb84c768eff65148374aed2`.

The important change is below the alert threshold. OMC malicious group buckets
move from r4 `[>36: 24, 20-36: 17, <20: 12]` to
`[>36: 24, 20-36: 20, <20: 9]`.

The four changed malicious group maxima are:

- `security-util`: 5 -> 24, SSL socket host-state transfer;
- `kmvn_ekjvnbwkhjbewv`: 12 -> 24, host state in a GET query;
- `test_for_virus_spook`: 7 -> 14, local file content in a GET query;
- `solgpt`: 18 -> 22, correct `urllib.request.urlretrieve` visibility plus
  download/execute proximity.

Three groups therefore cross from `<20` into the model-consultable residual
region. No malicious group decreases.

## Benign precision and residual load

The combined benign residual region remains **163 groups**:
143 PyPI development groups plus 20 OMC validation benign groups. r5 therefore
adds three malicious residual groups without adding benign residual groups.

Only six PyPI development artifacts change `context-causal-v6` score: three up
and three down. No artifact crosses above the benign ceiling.

Precision fixes remove prior alias mistakes:

- `asgiref`: 7 -> 0;
- `wsproto`: 15 -> 7;
- `lupa`: 27 -> 18.

True capability recovery raises:

- `torchvision`: 10 -> 20 from correctly resolved `urllib.request.urlopen`;
- `stevedore`: 1 -> 7 from real cache-directory environment reads;
- `typer`: 30 -> 35 from a real shell-completion write to `.zshrc`.

The only changed OMC benign group is `stevedore 5.3.0`, 1 -> 7, for the same
real environment access. It remains below the residual gate.

## CPU and rejected experiments

The accepted r5 strict run takes 649.41 seconds wall time versus 661.24 seconds
for r4 on the same development protocol. Child CPU is 1157.10 versus 1104.23
seconds. Treat this as the same practical CPU budget, not as a speed claim.

A whole-function lexical binding pre-scan was rejected. A Python AST collector
added roughly 15-35% on representative large packages; a `symtable` second
parse was worse. The accepted implementation keeps scope frames, parameter
shadowing, and flow-sensitive rebinding without rescanning every function body.

A DNS experiment was also rejected. Treating `socket.gethostbyname` as outbound
transfer recovered a DNS side-channel sample but incorrectly promoted legitimate
`gethostname() -> gethostbyname(hostname)` local-address resolution in
`google-auth-oauthlib`, `testcontainers`, and `xgboost`. A future IR needs an
explicit DNS operation and static-domain-shape context before revisiting this.

Broad GET credential transfer remains rejected as well. r5 request provenance
intentionally excludes environment secrets and authentication material because
legitimate authentication is not equivalent to exfiltration.
