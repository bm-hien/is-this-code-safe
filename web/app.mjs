import { analyzeSource, DEMO_SOURCES, MAX_SOURCE_BYTES } from "./engine.mjs";

const elements = {
  editor: document.querySelector("#editor-panel"),
  source: document.querySelector("#source-code"),
  fileInput: document.querySelector("#file-input"),
  fileName: document.querySelector("#file-name"),
  fileSize: document.querySelector("#file-size"),
  analyze: document.querySelector("#analyze-button"),
  clear: document.querySelector("#clear-code"),
  result: document.querySelector("#result-panel"),
  assessmentTitle: document.querySelector("#assessment-title"),
  assessmentCopy: document.querySelector("#assessment-copy"),
  riskGauge: document.querySelector("#risk-gauge"),
  riskScore: document.querySelector("#risk-score"),
  verdictBadge: document.querySelector("#verdict-badge"),
  ruleScore: document.querySelector("#rule-score"),
  modelScore: document.querySelector("#model-score"),
  latency: document.querySelector("#latency"),
  modelTitle: document.querySelector("#model-title"),
  modelCopy: document.querySelector("#model-copy"),
  evidenceList: document.querySelector("#evidence-list"),
  evidenceCount: document.querySelector("#evidence-count"),
  behaviorTokens: document.querySelector("#behavior-tokens"),
  eventCount: document.querySelector("#event-count"),
  warnings: document.querySelector("#warnings"),
  copyJson: document.querySelector("#copy-json"),
  copyCommand: document.querySelector("#copy-command"),
};

const assessmentText = Object.freeze({
  "no-malware-evidence": {
    title: "No malware evidence found",
    copy: "The analyzer found little weighted behavior evidence. This does not prove the file is safe.",
  },
  "needs-review": {
    title: "Human review recommended",
    copy: "The source contains ambiguous behavior that deserves inspection before you trust or run it.",
  },
  "malware-like": {
    title: "Malware-like behavior found",
    copy: "Multiple risky operations or a behavior path were found. Review the cited lines before taking action.",
  },
});

let currentFileName = "sample.py";
let currentReport = null;

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  return `${(bytes / 1024).toFixed(1)} KB`;
}

function sourceBytes() {
  return new TextEncoder().encode(elements.source.value).length;
}

function updateFileMetadata() {
  elements.fileName.textContent = currentFileName;
  elements.fileSize.textContent = formatBytes(sourceBytes());
}

function setButtonFeedback(button, value, fallback) {
  button.textContent = value;
  globalThis.setTimeout(() => {
    button.textContent = fallback;
  }, 1300);
}

async function copyText(value, button, success, fallback) {
  try {
    await navigator.clipboard.writeText(value);
    setButtonFeedback(button, success, fallback);
  } catch {
    setButtonFeedback(button, "Copy failed", fallback);
  }
}

function clearChildren(element) {
  element.replaceChildren();
}

function makeEvidenceItem(item) {
  const row = document.createElement("li");
  row.className = "evidence-item";

  const line = document.createElement("span");
  line.className = "evidence-line";
  line.textContent = `L${item.line || "?"}`;

  const body = document.createElement("div");
  body.className = "evidence-body";
  const operation = document.createElement("strong");
  const provenance = item.evidenceKind
    ? ` · ${item.evidenceKind}:${item.confidence}`
    : "";
  operation.textContent = item.motif
    ? `${item.op} · ${item.motif}${provenance}`
    : item.op;
  const reason = document.createElement("p");
  reason.textContent = item.reason;
  body.append(operation, reason);

  const score = document.createElement("span");
  score.className = "evidence-score";
  score.textContent = `+${item.score}`;

  row.append(line, body, score);
  return row;
}

function renderEvidence(report) {
  clearChildren(elements.evidenceList);
  elements.evidenceCount.textContent = `${report.evidence.length} ${report.evidence.length === 1 ? "signal" : "signals"}`;
  if (!report.evidence.length) {
    const item = document.createElement("li");
    item.className = "empty-state";
    item.textContent = "No weighted behavior evidence in the browser frontend.";
    elements.evidenceList.append(item);
    return;
  }
  elements.evidenceList.append(...report.evidence.map(makeEvidenceItem));
}

function renderTokens(report) {
  clearChildren(elements.behaviorTokens);
  elements.eventCount.textContent = `${report.events.length} ${report.events.length === 1 ? "event" : "events"}`;
  if (!report.modelTokens.length) {
    const token = document.createElement("span");
    token.className = "empty-token";
    token.textContent = "No MalIR operations";
    elements.behaviorTokens.append(token);
    return;
  }
  for (const value of report.modelTokens.slice(0, 48)) {
    const token = document.createElement("span");
    if (value.startsWith("MOTIF:")) token.className = "motif-token";
    token.textContent = value;
    elements.behaviorTokens.append(token);
  }
}

function renderWarnings(report) {
  clearChildren(elements.warnings);
  for (const warning of report.warnings) {
    const item = document.createElement("li");
    item.textContent = warning;
    elements.warnings.append(item);
  }
}

function setGauge(score) {
  const band = Math.max(0, Math.min(10, Math.ceil(score / 10)));
  elements.riskGauge.className = "risk-gauge";
  if (band) elements.riskGauge.classList.add(`score-band-${band}`);
  elements.riskGauge.setAttribute("aria-valuenow", String(Math.round(score)));
}

function renderReport(report) {
  currentReport = report;
  const content = assessmentText[report.assessment];
  const roundedRisk = Math.round(report.riskScore);
  const model = report.model;

  elements.result.dataset.verdict = report.verdict;
  elements.assessmentTitle.textContent = content.title;
  elements.assessmentCopy.textContent = content.copy;
  elements.riskScore.textContent = String(roundedRisk);
  setGauge(report.riskScore);

  elements.verdictBadge.className = `verdict-badge ${report.verdict}`;
  elements.verdictBadge.textContent = report.verdict;
  elements.ruleScore.textContent = `${report.ruleScore.toFixed(0)} / 100`;
  elements.modelScore.textContent = model.used
    ? `${(model.probability * 100).toFixed(1)}%`
    : "gated off";
  elements.latency.textContent = `${report.elapsedMs.toFixed(1)} ms`;

  elements.modelTitle.textContent = model.used
    ? "µMal Nano consulted"
    : "µMal Nano skipped";
  elements.modelCopy.textContent = model.used
    ? `${model.metadata.parameters.toLocaleString()} parameters · probability contributes 35% inside the uncertainty gate`
    : `${model.metadata.parameters.toLocaleString()} parameters · rule score outside the 20–80 uncertainty gate`;

  renderEvidence(report);
  renderTokens(report);
  renderWarnings(report);
  elements.copyJson.disabled = false;
}

function renderError(error) {
  currentReport = null;
  elements.result.removeAttribute("data-verdict");
  elements.assessmentTitle.textContent = "Analysis stopped";
  elements.assessmentCopy.textContent =
    error instanceof Error ? error.message : String(error);
  elements.riskScore.textContent = "—";
  elements.ruleScore.textContent = "—";
  elements.modelScore.textContent = "—";
  elements.latency.textContent = "—";
  elements.verdictBadge.className = "verdict-badge neutral";
  elements.verdictBadge.textContent = "input error";
  setGauge(0);
  elements.copyJson.disabled = true;
}

function analyze() {
  const source = elements.source.value;
  if (!source.trim()) {
    renderError(new Error("Paste Python source or choose a .py file first."));
    return;
  }
  elements.analyze.disabled = true;
  elements.analyze.firstElementChild.textContent = "Analyzing…";
  try {
    const report = analyzeSource(source, currentFileName);
    renderReport(report);
  } catch (error) {
    renderError(error);
  } finally {
    elements.analyze.disabled = false;
    elements.analyze.firstElementChild.textContent = "Analyze locally";
  }
}

async function loadFile(file) {
  if (!file) return;
  if (file.size > MAX_SOURCE_BYTES) {
    renderError(new Error("File exceeds the 1 MB browser analysis limit."));
    return;
  }
  try {
    const source = await file.text();
    currentFileName = file.name || "sample.py";
    elements.source.value = source;
    updateFileMetadata();
    analyze();
  } catch {
    renderError(new Error("The selected file could not be read as text."));
  }
}

function loadSample(name) {
  if (!(name in DEMO_SOURCES)) return;
  currentFileName = `${name}.py`;
  elements.source.value = DEMO_SOURCES[name];
  updateFileMetadata();
  analyze();
}

elements.source.addEventListener("input", updateFileMetadata);
elements.analyze.addEventListener("click", analyze);
elements.clear.addEventListener("click", () => {
  currentFileName = "sample.py";
  elements.source.value = "";
  updateFileMetadata();
  elements.source.focus();
});

elements.fileInput.addEventListener("change", () => {
  loadFile(elements.fileInput.files?.[0]);
  elements.fileInput.value = "";
});

for (const button of document.querySelectorAll("[data-sample]")) {
  button.addEventListener("click", () => loadSample(button.dataset.sample));
}

for (const eventName of ["dragenter", "dragover"]) {
  elements.editor.addEventListener(eventName, (event) => {
    event.preventDefault();
    elements.editor.classList.add("drag-active");
  });
}
for (const eventName of ["dragleave", "drop"]) {
  elements.editor.addEventListener(eventName, (event) => {
    event.preventDefault();
    elements.editor.classList.remove("drag-active");
  });
}
elements.editor.addEventListener("drop", (event) => {
  loadFile(event.dataTransfer?.files?.[0]);
});

elements.copyJson.addEventListener("click", () => {
  if (!currentReport) return;
  copyText(
    JSON.stringify(currentReport, null, 2),
    elements.copyJson,
    "Copied",
    "Copy JSON",
  );
});

elements.copyCommand.addEventListener("click", () => {
  copyText("itcs file.py", elements.copyCommand, "Copied", "Copy");
});

loadSample("suspicious");
