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

test("benign demo remains low signal", () => {
  const report = analyzeSource(DEMO_SOURCES.benign, "benign.py");
  assert.equal(report.assessment, "no-malware-evidence");
  assert.equal(report.verdict, "low-signal");
  assert.equal(report.model.loaded, true);
  assert.equal(report.model.used, false);
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
