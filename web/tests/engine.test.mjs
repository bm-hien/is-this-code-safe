import assert from "node:assert/strict";
import test from "node:test";

import {
  analyzeSource,
  DEMO_SOURCES,
  MAX_SOURCE_BYTES,
  predictMicro,
} from "../engine.mjs";

test("benign demo remains low signal", () => {
  const report = analyzeSource(DEMO_SOURCES.benign, "benign.py");
  assert.equal(report.assessment, "no-malware-evidence");
  assert.equal(report.verdict, "low-signal");
  assert.equal(report.model.used, false);
});

test("exfiltration demo produces line evidence and uses µMal Nano", () => {
  const report = analyzeSource(DEMO_SOURCES.suspicious, "exfil.py");
  assert.equal(report.assessment, "malware-like");
  assert.ok(report.riskScore >= 50);
  assert.equal(report.model.used, true);
  assert.ok(report.model.probability > 0.5);
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

test("the tiny Transformer is deterministic and sequence-sensitive", () => {
  const benign = predictMicro(["OP:FILE_READ", "OP:FILE_WRITE"]);
  const suspicious = predictMicro([
    "OP:ENV_READ",
    "OP:ENCODE",
    "OP:NETWORK_SEND",
    "MOTIF:credential_or_file_exfil",
  ]);
  assert.ok(benign < 0.5);
  assert.ok(suspicious > 0.5);
  assert.equal(
    suspicious,
    predictMicro([
      "OP:ENV_READ",
      "OP:ENCODE",
      "OP:NETWORK_SEND",
      "MOTIF:credential_or_file_exfil",
    ]),
  );
});

test("browser input is bounded", () => {
  assert.throws(
    () => analyzeSource("x".repeat(MAX_SOURCE_BYTES + 1), "large.py"),
    /1 MB/,
  );
});
