import {
  analyzeSource,
  DEMO_SOURCES,
  getFullModelStatus,
  loadFullModel,
  MAX_SOURCE_BYTES,
} from "./engine.mjs";
import { createSourceEditor } from "./source-editor.mjs";

const elements = Object.freeze({
  editor: document.querySelector("#editor-panel"),
  source: document.querySelector("#source-code"),
  sourceMount: document.querySelector("#source-editor"),
  editorKind: document.querySelector("#editor-kind"),
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
  purposeTitle: document.querySelector("#purpose-title"),
  purposeCopy: document.querySelector("#purpose-copy"),
  evidenceList: document.querySelector("#evidence-list"),
  evidenceCount: document.querySelector("#evidence-count"),
  behaviorTokens: document.querySelector("#behavior-tokens"),
  eventCount: document.querySelector("#event-count"),
  warnings: document.querySelector("#warnings"),
  copyJson: document.querySelector("#copy-json"),
  loadModel: document.querySelector("#load-model"),
  modelStatus: document.querySelector("#model-status"),
  modelProgress: document.querySelector("#model-progress"),
});

const assessmentText = Object.freeze({
  "no-malware-evidence": {
    title: "No malware evidence found",
    copy: "Little weighted behavior evidence was found. This does not prove the file is safe.",
  },
  "needs-review": {
    title: "Human review recommended",
    copy: "The source contains ambiguous behavior that deserves inspection before it is trusted or run.",
  },
  "malware-like": {
    title: "Malware-like behavior found",
    copy: "Risky operations or behavior paths were found. Review the cited lines before taking action.",
  },
});

let currentFileName = "sample.py";
let currentReport = null;
let modelLoading = false;
let sourceEditor = {
  focus: () => elements.source.focus(),
  getValue: () => elements.source.value,
  setValue: (value) => {
    elements.source.value = value;
  },
};
function formatBytes(bytes) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(2) + " MB";
}

function sourceBytes() {
  return new TextEncoder().encode(sourceEditor.getValue()).length;
}

function updateFileMetadata() {
  elements.fileName.textContent = currentFileName;
  elements.fileSize.textContent = formatBytes(sourceBytes());
}

function updateAnalyzeState() {
  const ready = getFullModelStatus().loaded;
  elements.analyze.disabled =
    modelLoading || !ready || !sourceEditor.getValue().trim();
  if (!ready) {
    elements.analyze.title = "Download the full model first";
  } else if (!sourceEditor.getValue().trim()) {
    elements.analyze.title = "Add Python source first";
  } else {
    elements.analyze.removeAttribute("title");
  }
}

function setModelState(state) {
  document.documentElement.dataset.modelState = state;
}
function setTemporaryLabel(button, label, fallback) {
  button.textContent = label;
  globalThis.setTimeout(() => {
    button.textContent = fallback;
  }, 1300);
}

async function copyText(value, button) {
  try {
    await navigator.clipboard.writeText(value);
    setTemporaryLabel(button, "Copied", "Copy JSON");
  } catch {
    setTemporaryLabel(button, "Copy failed", "Copy JSON");
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
  line.textContent = "L" + (item.line || "?");

  const body = document.createElement("div");
  body.className = "evidence-body";
  const operation = document.createElement("strong");
  const provenance = item.evidenceKind
    ? " · " + item.evidenceKind + ":" + item.confidence
    : "";
  const occurrences =
    item.occurrences > 1 ? " ×" + item.occurrences : "";
  operation.textContent = item.motif
    ? item.op + occurrences + " · " + item.motif + provenance
    : item.op + occurrences;

  const reason = document.createElement("p");
  reason.textContent = item.reason;
  body.append(operation, reason);

  const score = document.createElement("span");
  score.className = "evidence-score";
  score.textContent = "+" + item.score;
  row.append(line, body, score);
  return row;
}

function renderEvidence(report) {
  clearChildren(elements.evidenceList);
  const count = report.evidence.length;
  const collapsed = report.suppressedEvidenceCount || 0;
  elements.evidenceCount.textContent =
    count +
    (count === 1 ? " unique signal" : " unique signals") +
    (collapsed ? " · " + collapsed + " repeats collapsed" : "");
  if (!count) {
    const item = document.createElement("li");
    item.className = "empty-state";
    item.textContent = "No weighted behavior evidence.";
    elements.evidenceList.append(item);
    return;
  }
  elements.evidenceList.append(...report.evidence.map(makeEvidenceItem));
}

function renderTokens(report) {
  clearChildren(elements.behaviorTokens);
  const count = report.events.length;
  elements.eventCount.textContent =
    count + (count === 1 ? " event" : " events");
  if (!report.modelTokens.length) {
    const token = document.createElement("span");
    token.className = "empty-token";
    token.textContent = "No behavior tokens";
    elements.behaviorTokens.append(token);
    return;
  }
  for (const value of report.modelTokens.slice(0, 64)) {
    const token = document.createElement("span");
    token.className = value.startsWith("MOTIF:")
      ? "behavior-token motif-token"
      : "behavior-token";
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
  const normalized = Math.max(0, Math.min(100, score));
  elements.riskGauge.style.setProperty("--risk", normalized + "%");
  elements.riskGauge.setAttribute("aria-valuenow", String(Math.round(normalized)));
}

function renderPurpose(effectSummary) {
  const purpose = effectSummary.purposeCandidates[0];
  if (!purpose) {
    elements.purposeTitle.textContent = "Purpose not resolved";
    elements.purposeCopy.textContent =
      "Capabilities remain visible, but this frontend did not establish a program role.";
    return;
  }
  const label = purpose.label.replaceAll("-", " ");
  elements.purposeTitle.textContent =
    label.charAt(0).toUpperCase() +
    label.slice(1) +
    " · " +
    purpose.confidence +
    " confidence";
  const dualUse = purpose.label === "local-code-transformer"
    ? " This is a dual-use role: execution capabilities still require review."
    : " This is an effect-backed candidate, not a claim about author intent.";
  elements.purposeCopy.textContent = purpose.reason + "." + dualUse;
}

function renderReport(report) {
  currentReport = report;
  const content = assessmentText[report.assessment];
  const model = report.model;
  const metadata = model.metadata;

  elements.result.dataset.verdict = report.verdict;
  elements.assessmentTitle.textContent = content.title;
  elements.assessmentCopy.textContent = content.copy;
  elements.riskScore.textContent = String(Math.round(report.riskScore));
  elements.verdictBadge.className = "verdict-badge " + report.verdict;
  elements.verdictBadge.textContent = report.verdict;
  elements.ruleScore.textContent = report.ruleScore.toFixed(0) + " / 100";
  elements.modelScore.textContent = model.consulted
    ? (model.probability * 100).toFixed(1) +
      "%" +
      (model.abstained ? " audit" : "")
    : "not loaded";
  elements.latency.textContent = report.elapsedMs.toFixed(1) + " ms";
  setGauge(report.riskScore);

  if (model.consulted) {
    const windows = model.windows === 1 ? "1 window" : model.windows + " windows";
    const coverage =
      model.tokensEvaluated + " semantic tokens · " + windows;
    const calibration =
      metadata.calibration === "temperature-scaled-validation"
        ? "temperature-scaled on group-disjoint synthetic validation"
        : "uncalibrated";
    elements.modelTitle.textContent = metadata.name + " consulted";
    if (model.abstained) {
      const coveragePercent = (model.tokenCoverage * 100).toFixed(0) + "%";
      const nearestPercent = (model.nearestSimilarity * 100).toFixed(0) + "%";
      elements.modelTitle.textContent = metadata.name + " abstained";
      elements.modelCopy.textContent =
        metadata.parameters.toLocaleString() +
        " parameters · probability shown only for audit · token coverage " +
        coveragePercent +
        " · nearest trained behavior " +
        nearestPercent +
        "; unsupported semantic context cannot raise the capability score";
    } else if (model.used) {
      elements.modelCopy.textContent =
        metadata.parameters.toLocaleString() +
        " parameters · " +
        coverage +
        " · " +
        calibration +
        "; advisory probability can raise risk inside the uncertainty gate; the capability floor is never reduced";
    } else {
      const boundary = model.gate === "below" ? "below 20" : "above 80";
      elements.modelCopy.textContent =
        metadata.parameters.toLocaleString() +
        " parameters · " +
        coverage +
        " · " +
        calibration +
        "; score shown for audit while capability score " +
        boundary +
        " keeps the deterministic score unchanged";
    }
  } else {
    elements.modelTitle.textContent = "µMal Full not loaded";
    elements.modelCopy.textContent =
      "Download the model to include an advisory model score.";
  }

  renderPurpose(report.effectSummary);
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
  elements.purposeTitle.textContent = "Effect profile unavailable";
  elements.purposeCopy.textContent = "Fix the input error and analyze again.";
  elements.verdictBadge.className = "verdict-badge neutral";
  elements.verdictBadge.textContent = "input error";
  setGauge(0);
  elements.copyJson.disabled = true;
}

async function analyze() {
  if (!getFullModelStatus().loaded) {
    renderError(new Error("Download the full model before analyzing."));
    return;
  }
  const source = sourceEditor.getValue();
  if (!source.trim()) {
    renderError(new Error("Paste Python source or choose a .py file first."));
    return;
  }

  elements.analyze.disabled = true;
  elements.analyze.firstElementChild.textContent = "Analyzing…";
  await new Promise((resolve) => requestAnimationFrame(resolve));
  try {
    renderReport(analyzeSource(source, currentFileName));
  } catch (error) {
    renderError(error);
  } finally {
    elements.analyze.firstElementChild.textContent = "Analyze locally";
    updateAnalyzeState();
  }
}
async function downloadModel() {
  if (modelLoading || getFullModelStatus().loaded) return;
  modelLoading = true;
  setModelState("loading");
  elements.loadModel.disabled = true;
  elements.loadModel.textContent = "Downloading…";
  elements.modelStatus.textContent = "Preparing full model";
  elements.modelProgress.hidden = false;
  elements.modelProgress.value = 0;
  updateAnalyzeState();

  try {
    const module = await import("./model.mjs");
    const manifest = module.FULL_MODEL_MANIFEST;
    elements.modelProgress.max = manifest.binary.bytes;
    await loadFullModel(manifest, {
      onProgress(loaded, total) {
        elements.modelProgress.max = total || manifest.binary.bytes;
        elements.modelProgress.value = loaded;
        elements.modelStatus.textContent =
          "Downloading " + formatBytes(loaded) + " / " +
          formatBytes(manifest.binary.bytes);
      },
    });
    const status = getFullModelStatus();
    setModelState("ready");
    elements.modelStatus.textContent =
      status.metadata.name + " ready · " + formatBytes(status.binaryBytes);
    elements.modelTitle.textContent = status.metadata.name + " ready";
    elements.modelCopy.textContent =
      status.metadata.parameters.toLocaleString() +
      " parameters · waiting for a test input";
    elements.assessmentTitle.textContent = sourceEditor.getValue().trim()
      ? "Ready to analyze"
      : "Waiting for input";
    elements.assessmentCopy.textContent =
      "The full model is loaded. Add source and select Analyze locally.";
    elements.loadModel.textContent = "Model ready";
    elements.modelProgress.hidden = true;
  } catch (error) {
    setModelState("error");
    elements.modelStatus.textContent =
      error instanceof Error ? error.message : String(error);
    elements.loadModel.disabled = false;
    elements.loadModel.textContent = "Retry download";
    elements.modelProgress.hidden = true;
  } finally {
    modelLoading = false;
    updateAnalyzeState();
  }
}

async function loadFile(file) {
  if (!file) return;
  if (file.size > MAX_SOURCE_BYTES) {
    renderError(new Error("File exceeds the 1 MB browser analysis limit."));
    return;
  }
  try {
    sourceEditor.setValue(await file.text());
    currentFileName = file.name || "sample.py";
    updateFileMetadata();
    updateAnalyzeState();
  } catch {
    renderError(new Error("The selected file could not be read as text."));
  }
}

function loadSample(name) {
  if (!(name in DEMO_SOURCES)) return;
  currentFileName = name + ".py";
  sourceEditor.setValue(DEMO_SOURCES[name]);
  updateFileMetadata();
  updateAnalyzeState();
  sourceEditor.focus();
}

void createSourceEditor({
  mount: elements.sourceMount,
  textarea: elements.source,
  onChange() {
    updateFileMetadata();
    updateAnalyzeState();
  },
}).then((editor) => {
  sourceEditor = editor;
  elements.editorKind.textContent =
    editor.kind === "monaco" ? "PYTHON · MONACO" : "PYTHON · BASIC EDITOR";
  updateFileMetadata();
  updateAnalyzeState();
});

elements.loadModel.addEventListener("click", downloadModel);
elements.analyze.addEventListener("click", analyze);
elements.clear.addEventListener("click", () => {
  currentFileName = "sample.py";
  sourceEditor.setValue("");
  updateFileMetadata();
  updateAnalyzeState();
  sourceEditor.focus();
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
  copyText(JSON.stringify(currentReport, null, 2), elements.copyJson);
});

setModelState("idle");
updateFileMetadata();
updateAnalyzeState();
